"""
统一可执行程序路径管理模块 (utils/path_helper.py)
区分“源码开发环境”与“PyInstaller 冻结打包环境 (getattr(sys, 'frozen', False))”：
- 确保 SQLite 数据库文件 (data/windfir.db) 与上传证据包存储目录 (storage/)
  始终生成在 .exe 所在同级外部目录下（可读可写），避免写入临时只读目录 _MEIPASS。
"""

import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    """判断当前是否运行在 PyInstaller 冻结打包后的 .exe 环境中"""
    return bool(getattr(sys, "frozen", False))


def get_app_root() -> Path:
    """
    获取应用外部可读写根目录：
    - 若为 PyInstaller 打包后的 .exe 环境，返回 .exe 可执行文件所在的同级目录
    - 若为源码开发环境，返回 backend/ 根目录
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def get_bundle_dir() -> Path:
    """
    获取应用内部静态资源目录（只读）：
    - 若为 PyInstaller 单文件打包模式，返回 sys._MEIPASS 临时解压目录
    - 若为源码开发环境，返回 backend/ 根目录
    """
    if is_frozen() and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")).resolve()
    return get_app_root()


def get_data_dir() -> Path:
    """
    获取外部可读写的数据目录 (data/)，若不存在则自动创建
    """
    data_dir = get_app_root() / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_sqlite_db_path() -> Path:
    """
    获取 SQLite 数据库文件完整路径 (data/windfir.db)
    """
    return get_data_dir() / "windfir.db"


def get_sqlite_url(async_driver: bool = True) -> str:
    """
    构造 SQLAlchemy SQLite 连接 URL：
    - 异步模式 (默认): sqlite+aiosqlite:///<绝对路径>/data/windfir.db
    - 同步模式: sqlite:///<绝对路径>/data/windfir.db
    """
    db_file = get_sqlite_db_path().as_posix()
    scheme = "sqlite+aiosqlite" if async_driver else "sqlite"
    return f"{scheme}:///{db_file}"


def get_storage_dir() -> Path:
    """
    获取上传证据采集包的持久化存储目录 (storage/)，若不存在则自动创建
    始终位于 .exe 同级外部目录（或开发环境 backend/storage/）下
    """
    custom_dir = os.getenv("STORAGE_DIR", "").strip()
    if custom_dir:
        storage_path = Path(custom_dir).resolve()
    else:
        storage_path = get_app_root() / "storage"
    storage_path.mkdir(parents=True, exist_ok=True)
    return storage_path


def get_env_file_path() -> Path:
    """
    获取外部可配置的 .env 文件路径（优先读取 .exe 同级目录下的 .env）
    """
    return get_app_root() / ".env"


def get_static_dir() -> Path:
    """
    获取前端静态资源目录 (static/)：
    - 若在 PyInstaller _MEIPASS 单文件打包模式下且内部打包了 static/，优先返回内部路径
    - 否则返回外部根目录下的 static/ 目录（并确保目录存在）
    """
    bundle_static = get_bundle_dir() / "static"
    if bundle_static.exists():
        return bundle_static
    app_static = get_app_root() / "static"
    app_static.mkdir(parents=True, exist_ok=True)
    return app_static

