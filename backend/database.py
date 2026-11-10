"""
数据库连接、异步会话管理与核心 ORM 模型定义 (database.py)
已针对 PyInstaller 免安装 .exe 打包进行适配：
- 默认使用本地 SQLite 数据库 (data/windfir.db)，无需外部安装 MySQL 服务即可开箱即用
- 通过 utils.path_helper 确保 windfir.db 始终创建在 .exe 同级外部 data/ 目录下（可读可写）
- 对 5 张核心表 (cases, case_hosts, host_artifacts, ioc_intelligence, llm_configs) 的 JSON 与 DateTime 字段做 SQLite 完整兼容
"""

import os
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Optional

from dotenv import load_dotenv
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    event,
    func,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from utils.path_helper import get_env_file_path, get_sqlite_db_path, get_sqlite_url

# 加载外部可读写目录下的 .env 配置文件（若存在）
load_dotenv(dotenv_path=get_env_file_path(), override=True)


def _resolve_async_database_url() -> str:
    """
    解析数据库连接串：
    - 默认使用 path_helper 生成的外部可读写 SQLite 路径 (sqlite+aiosqlite:///.../data/windfir.db)
    - 若环境变量配置了 sqlite:///./data/windfir.db，自动转换为异步驱动 sqlite+aiosqlite:///
    """
    raw_url = os.getenv("DATABASE_URL", "").strip()
    if not raw_url:
        return get_sqlite_url(async_driver=True)
    if raw_url.startswith("sqlite:///"):
        return raw_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    return raw_url


DATABASE_URL = _resolve_async_database_url()
IS_SQLITE = DATABASE_URL.startswith("sqlite")

# 构建异步引擎参数（区分 SQLite 与外部数据库）
_engine_kwargs: dict[str, Any] = {
    "echo": os.getenv("SQL_ECHO", "false").lower() == "true",
}
if IS_SQLITE:
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    _engine_kwargs.update({
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
        "pool_recycle": 3600,
    })

engine = create_async_engine(DATABASE_URL, **_engine_kwargs)

# 针对 SQLite 开启外键级联约束 (PRAGMA foreign_keys=ON) 与 WAL 并发日志模式
if IS_SQLITE:
    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.close()


# 创建异步会话工厂
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


def utc_now() -> datetime:
    """获取当前 UTC 时间（不带时区信息，完全兼容 SQLite DATETIME 存储与比较）"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    """SQLAlchemy 声明式基类"""
    pass


# ==============================================================================
# 1. cases: 应急响应案件表
# ==============================================================================
class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, comment="案件主键ID")
    case_code: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False, comment="案件唯一编号（如 IR-20261020-001）"
    )
    case_name: Mapped[str] = mapped_column(String(255), nullable=False, comment="案件名称")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True, comment="案件背景与现象描述")
    status: Mapped[str] = mapped_column(
        String(32), default="open", index=True, nullable=False,
        comment="案件状态: open(待调查) / analyzing(分析中) / completed(已结案) / archived(已归档)"
    )
    severity: Mapped[str] = mapped_column(
        String(32), default="medium", nullable=False,
        comment="案件严重程度: low / medium / high / critical"
    )
    industry_type: Mapped[str] = mapped_column(
        String(64), default="enterprise", nullable=False,
        comment="客户行业场景: hospital(医疗卫健) / enterprise(政企集团) / university(高校科研)"
    )
    analyst: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, comment="负责应急分析人员")
    ai_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True, comment="AI 全案攻击链综述与研判报告")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, server_default=func.current_timestamp(), nullable=False, comment="创建时间"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, onupdate=utc_now, server_default=func.current_timestamp(), nullable=False, comment="更新时间"
    )

    # 关联关系
    hosts: Mapped[list["CaseHost"]] = relationship(
        "CaseHost", back_populates="case", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list["HostArtifact"]] = relationship(
        "HostArtifact", back_populates="case", cascade="all, delete-orphan"
    )
    iocs: Mapped[list["IOCIntelligence"]] = relationship(
        "IOCIntelligence", back_populates="case"
    )


# ==============================================================================
# 2. case_hosts: 涉案主机表
# ==============================================================================
class CaseHost(Base):
    __tablename__ = "case_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, comment="主机主键ID")
    case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False, comment="所属案件ID"
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True, comment="主机名")
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True, comment="主机IP地址")
    os_version: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, comment="操作系统版本（如 Windows Server 2019）"
    )
    archive_path: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True, comment="上传或关联的采集压缩包（.zip）本地存储路径"
    )
    parse_status: Mapped[str] = mapped_column(
        String(32), default="pending", index=True, nullable=False,
        comment="日志解析状态: pending(待解析) / parsing(解析中) / completed(解析完成) / failed(解析失败)"
    )
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False, comment="主机综合风险评分(0-100)")
    risk_level: Mapped[str] = mapped_column(
        String(32), default="low", index=True, nullable=False,
        comment="主机风险等级: low / medium / high / critical"
    )
    compromise_summary: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="主机失陷摘要与解析状态说明"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, server_default=func.current_timestamp(), nullable=False, comment="接入时间"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, onupdate=utc_now, server_default=func.current_timestamp(), nullable=False, comment="更新时间"
    )

    # 关联关系
    case: Mapped["Case"] = relationship("Case", back_populates="hosts")
    artifacts: Mapped[list["HostArtifact"]] = relationship(
        "HostArtifact", back_populates="host", cascade="all, delete-orphan"
    )
    iocs: Mapped[list["IOCIntelligence"]] = relationship(
        "IOCIntelligence", back_populates="host"
    )


# ==============================================================================
# 3. host_artifacts: 主机取证伪影与高危事件表
# ==============================================================================
class HostArtifact(Base):
    __tablename__ = "host_artifacts"
    __table_args__ = (
        Index("idx_host_event_risk", "host_id", "event_id", "risk_level"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, comment="伪影事件主键ID")
    case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=True, comment="关联案件ID"
    )
    host_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("case_hosts.id", ondelete="CASCADE"), index=True, nullable=False, comment="所属涉案主机ID"
    )
    artifact_type: Mapped[str] = mapped_column(
        String(64), default="evtx", index=True, nullable=False,
        comment="取证伪影类型: evtx_logon / evtx_process / evtx_service / evtx_account / registry / file 等"
    )
    source_file: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, comment="来源日志文件名（如 Security.evtx / System.evtx）"
    )
    event_id: Mapped[Optional[int]] = mapped_column(
        Integer, index=True, nullable=True, comment="Windows 事件 ID（如 4624/4625/4688/7045/4720）"
    )
    event_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime, index=True, nullable=True, comment="事件原始发生时间(UTC)"
    )
    summary: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True, comment="事件可读性摘要描述"
    )
    parsed_data: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON, default=dict, nullable=True,
        comment="结构化提取的核心字段(JSON): 如 LogonType, IpAddress, TargetUserName, CommandLine, PPID, ServiceName 等"
    )
    raw_data: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="原始事件 XML/JSON 载荷"
    )
    risk_level: Mapped[str] = mapped_column(
        String(32), default="low", index=True, nullable=False,
        comment="事件风险等级: info / low / medium / high / critical"
    )
    risk_tags: Mapped[Optional[list[str]]] = mapped_column(
        JSON, default=list, nullable=True,
        comment="风险标签与 ATT&CK 战术技术列表（如 ['T1059.001', 'PowerShell编码执行']）"
    )
    ai_analysis: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="AI 对该高危事件的深度研判结论"
    )
    is_malicious: Mapped[bool] = mapped_column(
        Boolean, default=False, index=True, nullable=False, comment="是否标记为确认恶意行为"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, server_default=func.current_timestamp(), nullable=False, comment="入库时间"
    )

    # 关联关系
    case: Mapped[Optional["Case"]] = relationship("Case", back_populates="artifacts")
    host: Mapped["CaseHost"] = relationship("CaseHost", back_populates="artifacts")


# ==============================================================================
# 4. ioc_intelligence: IOC 威胁情报表
# ==============================================================================
class IOCIntelligence(Base):
    __tablename__ = "ioc_intelligence"
    __table_args__ = (
        Index("idx_ioc_type_value", "ioc_type", "ioc_value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, comment="IOC 主键ID")
    case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("cases.id", ondelete="SET NULL"), index=True, nullable=True, comment="关联案件ID"
    )
    host_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("case_hosts.id", ondelete="SET NULL"), index=True, nullable=True, comment="关联主机ID"
    )
    ioc_type: Mapped[str] = mapped_column(
        String(32), index=True, nullable=False,
        comment="IOC 类型: ip / domain / hash_md5 / hash_sha256 / url / user_account / service_name"
    )
    ioc_value: Mapped[str] = mapped_column(
        String(512), index=True, nullable=False, comment="IOC 具体指标值"
    )
    threat_level: Mapped[str] = mapped_column(
        String(32), default="suspicious", index=True, nullable=False,
        comment="威胁等级: clean / suspicious / malicious / critical"
    )
    confidence: Mapped[int] = mapped_column(
        Integer, default=50, nullable=False, comment="情报置信度(0-100)"
    )
    source: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, comment="情报来源（如 EVTX_Rule / ThreatBook / VirusTotal / AI_Agent）"
    )
    tags: Mapped[Optional[list[str]]] = mapped_column(
        JSON, default=list, nullable=True,
        comment="情报标签 JSON 数组（如 ['BruteForce', 'C2', 'CobaltStrike']）"
    )
    intel_detail: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON, default=dict, nullable=True, comment="威胁情报上下文详情(JSON)"
    )
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, comment="首次出现时间")
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, comment="最近出现时间")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, server_default=func.current_timestamp(), nullable=False, comment="创建时间"
    )

    # 关联关系
    case: Mapped[Optional["Case"]] = relationship("Case", back_populates="iocs")
    host: Mapped[Optional["CaseHost"]] = relationship("CaseHost", back_populates="iocs")


# ==============================================================================
# 5. llm_configs: 大语言模型配置表
# ==============================================================================
class LLMConfig(Base):
    __tablename__ = "llm_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, comment="配置主键ID")
    config_name: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, comment="配置展示名称（如 DeepSeek-R1-安全研判）"
    )
    provider: Mapped[str] = mapped_column(
        String(64), default="openai", nullable=False,
        comment="模型服务商: openai / deepseek / ollama / qwen / custom"
    )
    base_url: Mapped[str] = mapped_column(
        String(512), nullable=False, comment="API Base URL（如 https://api.deepseek.com/v1）"
    )
    api_key: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True, comment="API 密钥（本地模型可为空）"
    )
    model_name: Mapped[str] = mapped_column(
        String(128), nullable=False, comment="调用的模型名称（如 deepseek-chat / gpt-4o）"
    )
    temperature: Mapped[float] = mapped_column(
        Float, default=0.2, nullable=False, comment="模型推理采样温度(0.0-2.0)"
    )
    max_tokens: Mapped[int] = mapped_column(
        Integer, default=4096, nullable=False, comment="单次响应最大 Token 数量"
    )
    system_prompt: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="默认 DFIR 安全专家系统提示词模板"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, index=True, nullable=False, comment="是否为当前激活使用的模型配置"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, server_default=func.current_timestamp(), nullable=False, comment="创建时间"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, onupdate=utc_now, server_default=func.current_timestamp(), nullable=False, comment="更新时间"
    )


# ==============================================================================
# 数据库初始化与依赖注入函数
# ==============================================================================
async def init_db() -> None:
    """应用启动时自动检查并创建本地 SQLite 数据库文件及 5 张核心表，并执行轻量级字段升级"""
    if IS_SQLITE:
        get_sqlite_db_path().parent.mkdir(parents=True, exist_ok=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if IS_SQLITE:
            # 兼容已有数据库平滑新增 cases.industry_type 字段
            res = await conn.exec_driver_sql("PRAGMA table_info(cases);")
            cols = [row[1] for row in res.fetchall()]
            if "industry_type" not in cols:
                await conn.exec_driver_sql(
                    "ALTER TABLE cases ADD COLUMN industry_type VARCHAR(64) NOT NULL DEFAULT 'enterprise';"
                )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI 依赖注入：提供异步数据库会话并在请求结束后自动关闭"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
