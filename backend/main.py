"""
WinDFIR-AI 后端主应用入口 (main.py)
负责初始化 FastAPI 实例、配置跨域中间件 (CORS)、管理生命周期自动建表并挂载核心业务路由。
"""

import logging
import os
import threading
import time
import webbrowser
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from database import engine, init_db
from routers.analysis import router as analysis_router
from routers.cases import router as cases_router
from utils.path_helper import get_sqlite_db_path, get_static_dir, get_storage_dir, is_frozen

# 配置全局日志格式
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("windfir.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI 应用生命周期管理器：
    启动时自动创建本地 SQLite 数据库 (data/windfir.db) 及 5 张核心表，并初始化外部 storage/ 目录
    关闭时优雅释放数据库连接池
    """
    db_path = get_sqlite_db_path()
    storage_dir = get_storage_dir()
    logger.info(f"正在初始化本地 SQLite 数据库: {db_path}")
    logger.info(f"证据采集包存储目录: {storage_dir}")
    try:
        await init_db()
        logger.info("SQLite 数据库 5 张核心表结构校验与自动创建完成。")
    except Exception as exc:
        logger.error(f"SQLite 数据库初始化失败: {exc}")
        if os.getenv("STRICT_DB_INIT", "false").lower() == "true":
            raise
    yield
    logger.info("正在关闭数据库连接...")
    await engine.dispose()


# 初始化 FastAPI 应用
app = FastAPI(
    title="WinDFIR-AI Backend API",
    description="智能 Windows 应急响应与取证研判系统 - 后端核心、EVTX 解析、威胁情报与 AI 研判服务",
    version="2.0.0",
    lifespan=lifespan,
)

# 配置 CORS 跨域中间件
cors_origins_env = os.getenv("CORS_ORIGINS", "*")
allow_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册核心业务路由
app.include_router(cases_router)
app.include_router(analysis_router)

# 挂载前端静态资源目录 (兼容源码运行与 PyInstaller _MEIPASS 冻结环境)
static_dir = get_static_dir()
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", include_in_schema=False, summary="WinDFIR-AI 可视化应急响应作战台首页")
async def serve_console_index():
    """访问根路径直接返回内嵌的深色安全作战大屏前端单页应用"""
    index_file = static_dir / "index.html"
    return FileResponse(str(index_file))


@app.get("/health", tags=["System (系统状态)"], summary="服务健康检查")
async def health_check() -> dict[str, str]:
    """返回服务运行状态"""
    return {
        "status": "ok",
        "service": "WinDFIR-AI Backend",
        "stage": "Stage 4 - Complete DFIR Platform + Collector + PyInstaller EXE Ready",
    }


def _open_browser_delayed(url: str, delay: float = 1.5) -> None:
    """服务启动后延迟自动打开系统默认浏览器进入应急响应作战台"""
    time.sleep(delay)
    try:
        logger.info(f"正在自动打开浏览器进入 WinDFIR-AI 作战台: {url}")
        webbrowser.open(url)
    except Exception as exc:
        logger.warning(f"自动打开浏览器失败，请手动访问 {url}: {exc}")


if __name__ == "__main__":
    host = os.getenv("APP_HOST", "127.0.0.1" if is_frozen() else "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8000"))
    browser_url = f"http://127.0.0.1:{port}"

    if is_frozen() or os.getenv("AUTO_OPEN_BROWSER", "true").lower() == "true":
        threading.Thread(
            target=_open_browser_delayed,
            args=(browser_url, 1.5),
            daemon=True,
        ).start()

    if is_frozen():
        # PyInstaller 冻结环境下直接传入 app 实例并关闭 reload
        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=False,
            log_level="info",
        )
    else:
        uvicorn.run(
            "main:app",
            host=host,
            port=port,
            reload=True,
        )
