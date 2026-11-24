"""
案件与涉案主机管理路由模块 (routers/cases.py)
提供以下核心接口：
- POST /api/cases : 创建应急响应案件
- POST /api/cases/{case_id}/hosts : 向指定案件添加涉案主机（支持上传 .zip 采集包或关联本地采集包路径，并触发 EVTX 日志解析）
- GET  /api/cases : 获取案件列表
- GET  /api/cases/{case_id}/hosts/{host_id}/artifacts : 查询主机解析出的高危事件伪影
"""

import logging
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import aiofiles
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import Case, CaseHost, HostArtifact, IOCIntelligence, get_db
from services.evtx_parser import EvtxParseError, _decode_ps_base64, parse_host_evtx_archive
from utils.path_helper import get_storage_dir

logger = logging.getLogger("windfir.routers.cases")

router = APIRouter(prefix="/api/cases", tags=["Cases & Hosts (案件与主机管理)"])

# 证据采集包统一持久化存储目录 (storage/)，始终位于 .exe 同级外部可读写目录下
STORAGE_ROOT = get_storage_dir()


async def resolve_case_by_identifier(case_identifier: str, db: AsyncSession) -> Case:
    """
    根据传入的案件标识符查找案件记录，同时兼容以下 3 种格式：
    1. 整数主键 Case.id（如 "1", "2"）
    2. 完整案件编号 Case.case_code（如 "IR-20261021-21CEDA"，大小写不敏感）
    3. 不带 "IR-" 前缀的案件编号后缀（如 "20261021-21CEDA"）
    """
    raw = (case_identifier or "").strip()
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="案件标识 (case_id) 不能为空。",
        )

    # 1. 若为纯数字，优先按主键 Case.id 精确查询
    if raw.isdigit():
        case_obj = await db.get(Case, int(raw))
        if case_obj:
            return case_obj

    # 2. 按完整 case_code 或自动补齐 "IR-" 前缀查询（忽略大小写）
    upper_raw = raw.upper()
    prefixed_code = upper_raw if upper_raw.startswith("IR-") else f"IR-{upper_raw}"

    stmt = select(Case).where(
        or_(
            func.upper(Case.case_code) == upper_raw,
            func.upper(Case.case_code) == prefixed_code,
        )
    )
    case_obj = (await db.execute(stmt)).scalar_one_or_none()
    if case_obj:
        return case_obj

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=(
            f"未找到标识为 '{raw}' 的应急案件（支持传入数字 ID、完整编号如 '{prefixed_code}' 或后缀 '{raw}'），"
            "请确认案件已在作战台中创建。"
        ),
    )


# ==============================================================================
# Pydantic 请求与响应数据模型 (Schemas)
# ==============================================================================
class CaseCreateRequest(BaseModel):
    case_name: str = Field(..., min_length=1, max_length=255, description="案件名称", examples=["某集团内网域控失陷应急响应"])
    case_code: Optional[str] = Field(
        default=None, max_length=64, description="案件唯一编号（为空则系统自动生成）", examples=["IR-20261020-001"]
    )
    description: Optional[str] = Field(default=None, description="案件背景描述")
    severity: str = Field(default="high", pattern="^(low|medium|high|critical)$", description="严重程度: low/medium/high/critical")
    industry_type: str = Field(
        default="enterprise",
        pattern="^(hospital|enterprise|university)$",
        description="客户行业场景: hospital(医院/医疗卫健) / enterprise(政企/集团内网) / university(高校/科研机构)",
    )
    analyst: Optional[str] = Field(default="SecOps-Analyst", max_length=100, description="负责分析员姓名")


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_code: str
    case_name: str
    description: Optional[str] = None
    status: str
    severity: str
    industry_type: str = "enterprise"
    analyst: Optional[str] = None
    ai_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class HostResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    hostname: str
    ip_address: Optional[str] = None
    os_version: Optional[str] = None
    archive_path: Optional[str] = None
    parse_status: str
    risk_score: int
    risk_level: str
    compromise_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class HostCreateResultResponse(BaseModel):
    message: str
    host: HostResponse
    parse_result: Optional[dict[str, Any]] = None


# ==============================================================================
# 1. POST /api/cases : 创建应急响应案件
# ==============================================================================
@router.post(
    "",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="创建应急响应案件",
)
async def create_case(
    payload: CaseCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> Case:
    """
    创建新的 Windows 应急响应案件记录。
    若未指定 `case_code`，系统将自动按日期生成唯一案件编号。
    """
    case_code = payload.case_code or f"IR-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    # 检查案件编号是否重复
    stmt = select(Case).where(Case.case_code == case_code)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"案件编号 '{case_code}' 已存在，请更换编号。",
        )

    new_case = Case(
        case_code=case_code,
        case_name=payload.case_name,
        description=payload.description,
        severity=payload.severity,
        industry_type=payload.industry_type or "enterprise",
        status="open",
        analyst=payload.analyst,
    )
    db.add(new_case)
    await db.commit()
    await db.refresh(new_case)
    logger.info(f"成功创建应急案件: id={new_case.id}, code={new_case.case_code}")
    return new_case


# ==============================================================================
# 2. POST /api/cases/{case_id}/hosts : 向指定案件中添加涉案主机
# ==============================================================================
@router.post(
    "/{case_id}/hosts",
    response_model=HostCreateResultResponse,
    status_code=status.HTTP_201_CREATED,
    summary="向指定案件中添加涉案主机（支持数字 ID、完整案件编号或无前缀编号，支持上传 .zip/.evtx）",
)
@router.post(
    "/{case_id}/upload-evidence",
    response_model=HostCreateResultResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def add_host_to_case(
    case_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    hostname: Optional[str] = Form(default="", description="涉案主机名（选填，留空则从 .evtx <Computer> 自动提取）"),
    ip_address: Optional[str] = Form(default="", description="涉案主机内网 IP 地址（选填，留空自动识别）"),
    os_version: Optional[str] = Form(default="Windows Server 2019", description="操作系统版本（如 Windows Server 2019）"),
    archive_path: Optional[str] = Form(default="", description="服务器本地采集包路径（当不直接上传文件时使用）"),
    sync_parse: bool = Form(default=True, description="是否同步等待 EVTX 解析完成并返回结果（False 则后台异步解析）"),
    file: Optional[UploadFile] = File(default=None, description="上传的主机日志采集包 (.zip 或 .evtx)"),
    db: AsyncSession = Depends(get_db),
) -> HostCreateResultResponse:
    """
    向指定案件 (`case_id`，支持整数 ID、完整案件编号如 `IR-20261021-21CEDA` 或后缀 `20261021-21CEDA`) 添加一台涉案主机：
    - **方式一 (Multipart 文件上传)**：通过表单上传 `file` (`.zip` 压缩包或 `.evtx` 日志) 及 `hostname`、`ip_address` 等字段。
    - **方式二 (JSON 或表单关联路径)**：传入 `archive_path` 指向服务器上已存在的 `.zip` 采集包路径。
    - 添加成功后自动触发 `evtx_parser` 服务提取关键安全事件 (4624/4625/4688/7045/4720) 存入 `host_artifacts`。
    """
    # 兼容客户端使用 application/json 请求体传参的场景
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body_json = await request.json()
            hostname = body_json.get("hostname", hostname)
            ip_address = body_json.get("ip_address", ip_address)
            os_version = body_json.get("os_version", os_version)
            archive_path = body_json.get("archive_path", archive_path)
            if "sync_parse" in body_json:
                sync_parse = bool(body_json["sync_parse"])
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"JSON 请求体格式非法: {exc}",
            ) from exc

    # 允许主机名留空，解析器会自动从 EVTX <Computer> 节点或快照 JSON 中提取
    clean_hostname = (hostname or "").strip() or "自动识别中..."
    clean_ip = (ip_address or "").strip() or None

    # 清理 Swagger UI 默认可能填充的 "string" 占位符
    if archive_path and archive_path.strip() == "string":
        archive_path = ""

    # 校验案件是否存在（兼容数字主键 ID、完整 case_code 或无 IR- 前缀编号）
    case_obj = await resolve_case_by_identifier(case_id, db)
    real_case_id = case_obj.id

    saved_archive_path: Optional[str] = None

    # 处理上传的采集包文件
    if file and file.filename:
        ext = Path(file.filename).suffix.lower()
        if ext not in (".zip", ".evtx"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"不支持的采集包格式 '{ext}'，仅支持上传 .zip 压缩包或 .evtx 日志文件。",
            )
        case_storage_dir = STORAGE_ROOT / f"case_{real_case_id}"
        case_storage_dir.mkdir(parents=True, exist_ok=True)
        safe_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}_{Path(file.filename).name}"
        dest_path = case_storage_dir / safe_filename

        try:
            async with aiofiles.open(dest_path, "wb") as out_file:
                while chunk := await file.read(1024 * 1024):  # 每次异步读取 1MB
                    await out_file.write(chunk)
            saved_archive_path = str(dest_path)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"保存上传的采集包文件失败: {exc}",
            ) from exc
        finally:
            await file.close()

    elif archive_path:
        target_local = Path(archive_path)
        if not target_local.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"关联的本地采集包路径不存在: {archive_path}",
            )
        saved_archive_path = str(target_local.resolve())

    # 创建涉案主机记录
    new_host = CaseHost(
        case_id=real_case_id,
        hostname=clean_hostname,
        ip_address=clean_ip,
        os_version=os_version.strip() if os_version else None,
        archive_path=saved_archive_path,
        parse_status="pending",
        risk_score=0,
        risk_level="low",
    )
    db.add(new_host)
    if case_obj.status == "open":
        case_obj.status = "analyzing"
    await db.commit()
    await db.refresh(new_host)

    parse_summary: Optional[dict[str, Any]] = None

    # 若提供了采集包，执行或调度 EVTX 日志解析
    if saved_archive_path:
        if sync_parse:
            try:
                parse_summary = await parse_host_evtx_archive(
                    case_id=real_case_id,
                    host_id=new_host.id,
                    archive_path=saved_archive_path,
                    db=db,
                )
                await db.refresh(new_host)
            except EvtxParseError as exc:
                await db.refresh(new_host)
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"主机已创建(host_id={new_host.id})，但采集包解析失败: {exc}",
                ) from exc
        else:
            background_tasks.add_task(
                parse_host_evtx_archive,
                case_id=real_case_id,
                host_id=new_host.id,
                archive_path=saved_archive_path,
                db=None,
            )
            return HostCreateResultResponse(
                message="涉案主机添加成功，采集包已转入后台异步解析队列。",
                host=HostResponse.model_validate(new_host),
                parse_result={"status": "scheduled_in_background"},
            )

    return HostCreateResultResponse(
        message="涉案主机添加成功" + ("并完成 EVTX 日志解析。" if parse_summary else "（未提供采集包，待后续上传解析）。"),
        host=HostResponse.model_validate(new_host),
        parse_result=parse_summary,
    )


# ==============================================================================
# 辅助查询接口：查询案件列表与主机解析出的高危事件伪影
# ==============================================================================
@router.get("", response_model=list[CaseResponse], summary="获取应急案件列表")
async def list_cases(db: AsyncSession = Depends(get_db)) -> list[Case]:
    stmt = select(Case).order_by(Case.created_at.desc())
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/{case_id}/hosts", response_model=list[HostResponse], summary="获取指定案件下的所有涉案主机")
async def list_case_hosts(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[CaseHost]:
    case_obj = await resolve_case_by_identifier(case_id, db)
    stmt = (
        select(CaseHost)
        .where(CaseHost.case_id == case_obj.id)
        .order_by(CaseHost.risk_score.desc(), CaseHost.id.asc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/{case_id}/artifacts", summary="查询指定案件（或指定主机）解析出的高危 EVTX 事件时间轴")
async def list_case_artifacts(
    case_id: str,
    host_id: Optional[int] = Query(default=None, description="可选：按涉案主机 ID 过滤"),
    event_id: Optional[int] = Query(default=None, description="可选：按 EventID 过滤 (4624/4625/4688/7045/4720)"),
    risk_level: Optional[str] = Query(default=None, description="可选：按风险等级过滤 (low/medium/high/critical)"),
    limit: int = Query(default=200, ge=1, le=1000, description="返回最大条数"),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    case_obj = await resolve_case_by_identifier(case_id, db)
    real_case_id = case_obj.id
    stmt = select(HostArtifact).where(HostArtifact.case_id == real_case_id)
    if host_id is not None:
        stmt = stmt.where(HostArtifact.host_id == host_id)
    if event_id is not None:
        stmt = stmt.where(HostArtifact.event_id == event_id)
    if risk_level:
        stmt = stmt.where(HostArtifact.risk_level == risk_level)

    stmt = stmt.order_by(HostArtifact.event_time.asc(), HostArtifact.id.asc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()

    # 获取主机名映射方便前端时间轴展示
    host_stmt = select(CaseHost).where(CaseHost.case_id == real_case_id)
    hosts_map = {h.id: h.hostname for h in (await db.execute(host_stmt)).scalars().all()}

    return {
        "case_id": real_case_id,
        "case_code": case_obj.case_code,
        "host_id": host_id,
        "count": len(rows),
        "artifacts": [
            {
                "id": item.id,
                "host_id": item.host_id,
                "hostname": hosts_map.get(item.host_id, f"Host-{item.host_id}"),
                "artifact_type": item.artifact_type,
                "source_file": item.source_file,
                "event_id": item.event_id,
                "event_time": item.event_time,
                "summary": item.summary,
                "risk_level": item.risk_level,
                "risk_tags": item.risk_tags,
                "is_malicious": item.is_malicious,
                "parsed_data": item.parsed_data,
                "decoded_payload": (
                    (item.parsed_data or {}).get("DecodedPayload")
                    or _decode_ps_base64(
                        (item.parsed_data or {}).get("CommandLine")
                        or (item.parsed_data or {}).get("ImagePath")
                        or item.summary
                        or ""
                    )
                ),
                "ai_analysis": item.ai_analysis,
            }
            for item in rows
        ],
    }


@router.get("/{case_id}/hosts/{host_id}/artifacts", summary="查询指定主机解析出的高危 EVTX 事件")
async def list_host_artifacts(
    case_id: str,
    host_id: int,
    event_id: Optional[int] = Query(default=None, description="按 EventID 过滤 (4624/4625/4688/7045/4720)"),
    risk_level: Optional[str] = Query(default=None, description="按风险等级过滤 (low/medium/high/critical)"),
    limit: int = Query(default=100, ge=1, le=1000, description="返回最大条数"),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    return await list_case_artifacts(
        case_id=case_id,
        host_id=host_id,
        event_id=event_id,
        risk_level=risk_level,
        limit=limit,
        db=db,
    )


# ==============================================================================
# 3. DELETE /api/cases/{case_id} & DELETE /api/cases/{case_id}/hosts/{host_id}
# ==============================================================================
@router.delete("/{case_id}", summary="删除指定案件及其关联的所有主机、事件伪影与本地取证包文件")
async def delete_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    case_obj = await resolve_case_by_identifier(case_id, db)
    real_case_id = case_obj.id
    case_code = case_obj.case_code
    case_name = case_obj.case_name

    # 查询关联主机，清理可能存在的本地取证包文件
    hosts_stmt = select(CaseHost).where(CaseHost.case_id == real_case_id)
    hosts_list = (await db.execute(hosts_stmt)).scalars().all()
    for h in hosts_list:
        if h.archive_path:
            try:
                p = Path(h.archive_path)
                if p.is_file() and STORAGE_ROOT in p.resolve().parents:
                    p.unlink(missing_ok=True)
            except Exception as exc:
                logger.warning(f"清理主机取证包文件失败 ({h.archive_path}): {exc}")

    # 删除 storage/case_{id} 目录
    case_storage_dir = STORAGE_ROOT / f"case_{real_case_id}"
    if case_storage_dir.exists() and case_storage_dir.is_dir():
        shutil.rmtree(case_storage_dir, ignore_errors=True)

    # 显式清理关联的 IOC、事件伪影、主机与案件记录
    await db.execute(delete(IOCIntelligence).where(IOCIntelligence.case_id == real_case_id))
    await db.execute(delete(HostArtifact).where(HostArtifact.case_id == real_case_id))
    await db.execute(delete(CaseHost).where(CaseHost.case_id == real_case_id))
    await db.delete(case_obj)
    await db.commit()

    logger.info(f"已删除应急案件: id={real_case_id}, code={case_code}")
    return {
        "message": f"案件 [{case_code}] {case_name} 及其关联的主机、日志伪影和本地取证包已彻底删除。",
        "deleted_case_id": real_case_id,
        "deleted_case_code": case_code,
    }


@router.delete("/{case_id}/hosts/{host_id}", summary="删除指定案件下的单台涉案主机及其日志伪影")
async def delete_case_host(
    case_id: str,
    host_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    case_obj = await resolve_case_by_identifier(case_id, db)
    real_case_id = case_obj.id

    stmt = select(CaseHost).where(CaseHost.id == host_id, CaseHost.case_id == real_case_id)
    host_obj = (await db.execute(stmt)).scalar_one_or_none()
    if not host_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未在案件 {case_obj.case_code} 下找到 ID={host_id} 的涉案主机。",
        )

    hostname = host_obj.hostname
    if host_obj.archive_path:
        try:
            p = Path(host_obj.archive_path)
            if p.is_file() and STORAGE_ROOT in p.resolve().parents:
                p.unlink(missing_ok=True)
        except Exception as exc:
            logger.warning(f"删除单台主机取证包文件失败 ({host_obj.archive_path}): {exc}")

    await db.execute(delete(IOCIntelligence).where(IOCIntelligence.host_id == host_id))
    await db.execute(delete(HostArtifact).where(HostArtifact.host_id == host_id))
    await db.delete(host_obj)
    await db.commit()

    logger.info(f"已删除涉案主机: case_id={real_case_id}, host_id={host_id}, hostname={hostname}")
    return {
        "message": f"涉案主机 [{hostname}] 及其关联日志记录已删除。",
        "deleted_host_id": host_id,
        "hostname": hostname,
    }


# ==============================================================================
# 4. POST /api/cases/simulate/{scenario_key} : 一键载入三大行业实战仿真案件
# ==============================================================================
@router.post("/simulate/{scenario_key}", summary="一键生成三大行业实战应急仿真案件 (hospital / university / enterprise)")
async def simulate_industry_case(
    scenario_key: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    from services.simulation_cases import create_simulation_case

    if scenario_key not in ("hospital", "university", "enterprise"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不支持的仿真场景类型，可选值为: hospital (医院勒索) / university (高校挖矿) / enterprise (政企域控)",
        )
    return await create_simulation_case(scenario_key=scenario_key, db=db)


# ==============================================================================
# 5. GET /api/cases/collector-download/{platform} : 一键下载 Windows / Linux 采集脚本
# ==============================================================================
@router.get("/collector-download/{platform}", summary="一键下载 Windows (.ps1) 或 Linux 抗篡改 (.sh) 应急采集脚本")
async def download_collector_script(platform: str):
    from fastapi.responses import FileResponse

    collector_dir = get_app_root().parent / "collector"
    if platform.lower() == "linux":
        fpath = collector_dir / "linux_collector.sh"
        fname = "linux_collector.sh"
    else:
        fpath = collector_dir / "win_collector.ps1"
        fname = "win_collector.ps1"

    if not fpath.exists():
        raise HTTPException(status_code=404, detail=f"未找到采集脚本: {fname}")

    return FileResponse(
        path=str(fpath),
        filename=fname,
        media_type="application/octet-stream",
    )




