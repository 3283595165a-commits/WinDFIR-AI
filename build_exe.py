"""
WinDFIR-AI 平台一键打包 EXE 自动化构建脚本 (build_exe.py)
=============================================================================
功能说明：
1. 自动检查并校验前端离线静态资源 (`backend/static/vendor/` 是否齐全，缺失则自动调用下载)
2. 自动检查 PyInstaller 是否安装（未安装时支持自动 pip install pyinstaller）
3. 使用 PyInstaller 将 FastAPI + SQLite (aiosqlite) + EVTX 解析引擎 + python-docx + 静态作战大屏
   一键打包成免安装的 Windows 可执行程序 `dist/WinDFIR-AI.exe`
4. 启动 `WinDFIR-AI.exe` 时，会自动在同级目录创建 `data/windfir.db` 和 `storage/`，
   在后台启动本地服务并自动打开系统默认浏览器进入应急响应作战台 (`http://127.0.0.1:8000`)
5. 同时自动将终端采集器 (`collector/win_collector.ps1` 及可选编译 `WinDFIR-Collector.exe`)
   一并归档到 `dist/` 发布目录，开箱即用。

使用方法：
    python build_exe.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
STATIC_DIR = BACKEND_DIR / "static"
COLLECTOR_DIR = ROOT_DIR / "collector"
DIST_DIR = ROOT_DIR / "dist"
BUILD_DIR = ROOT_DIR / "build"


def ensure_static_vendor_assets() -> None:
    """检查前端 vendor 离线资源是否已就绪，若缺失则执行 download_assets.py"""
    vendor_dir = STATIC_DIR / "vendor"
    required_files = ["tailwind.js", "vue.global.prod.js", "g6.min.js", "marked.min.js"]
    missing = [f for f in required_files if not (vendor_dir / f).exists()]
    if missing:
        print(f"[*] 检测到离线前端依赖缺失 {missing}，正在运行 download_assets.py 下载...")
        download_script = BACKEND_DIR / "download_assets.py"
        subprocess.run([sys.executable, str(download_script)], check=True)
    else:
        print("[+] 前端离线静态资源 (Vue3 / Tailwind / AntV G6 / Marked) 校验通过。")


def ensure_pyinstaller() -> None:
    """确保当前 Python 环境已安装 PyInstaller"""
    try:
        import PyInstaller  # noqa: F401
        print("[+] PyInstaller 环境校验通过。")
    except ImportError:
        print("[*] 未检测到 PyInstaller，正在自动安装 pyinstaller...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)


def build_platform_exe() -> Path:
    """调用 PyInstaller 将后端与前端资源打包为单文件 WinDFIR-AI.exe"""
    print("\n================================================================")
    print("  正在构建 WinDFIR-AI 主战平台可执行文件 (WinDFIR-AI.exe) ...")
    print("================================================================")

    entry_script = BACKEND_DIR / "main.py"
    # Windows 下 PyInstaller --add-data 使用分号 ';' 分隔源路径与目标相对路径
    sep = ";" if os.name == "nt" else ":"
    add_data_arg = f"{STATIC_DIR}{sep}static"

    # FastAPI / Uvicorn / SQLAlchemy / aiosqlite / python-docx 常见需要显式声明的隐藏导入
    hidden_imports = [
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "sqlalchemy.dialects.sqlite",
        "sqlalchemy.dialects.sqlite.aiosqlite",
        "aiosqlite",
        "Greenlet",
        "greenlet",
        "multipart",
        "python_multipart",
        "docx",
        "Evtx",
        "Evtx.Evtx",
        "Evtx.Views",
        "httpx",
        "routers",
        "routers.cases",
        "routers.analysis",
        "services",
        "services.evtx_parser",
        "services.threat_intel",
        "services.ai_analyzer",
        "utils",
        "utils.path_helper",
        "database",
        "config",
    ]

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "WinDFIR-AI",
        "--paths",
        str(BACKEND_DIR),
        "--add-data",
        add_data_arg,
        "--collect-data",
        "docx",
        "--distpath",
        str(DIST_DIR),
        "--workpath",
        str(BUILD_DIR),
        "--specpath",
        str(ROOT_DIR),
    ]

    for mod in hidden_imports:
        cmd.extend(["--hidden-import", mod])

    cmd.append(str(entry_script))

    print(f"[*] 执行打包命令:\n    {' '.join(cmd)}\n")
    subprocess.run(cmd, check=True)

    exe_path = DIST_DIR / ("WinDFIR-AI.exe" if os.name == "nt" else "WinDFIR-AI")
    return exe_path


def bundle_collector_tools() -> None:
    """将终端应急采集器脚本及可选编译的 Go 采集器一并复制到 dist/collector 目录"""
    dist_collector_dir = DIST_DIR / "collector"
    dist_collector_dir.mkdir(parents=True, exist_ok=True)

    ps_script = COLLECTOR_DIR / "win_collector.ps1"
    if ps_script.exists():
        shutil.copy2(ps_script, dist_collector_dir / "win_collector.ps1")
        print(f"[+] 已将免编译 PowerShell 采集器复制至: {dist_collector_dir / 'win_collector.ps1'}")

    go_src = COLLECTOR_DIR / "main.go"
    if go_src.exists():
        shutil.copy2(go_src, dist_collector_dir / "main.go")
        go_bin = shutil.which("go")
        if go_bin:
            print("[*] 检测到本地安装有 Golang 编译器，正在同步编译单文件采集器 WinDFIR-Collector.exe ...")
            out_collector_exe = dist_collector_dir / "WinDFIR-Collector.exe"
            env = os.environ.copy()
            env["GOOS"] = "windows"
            env["GOARCH"] = "amd64"
            res = subprocess.run(
                [go_bin, "build", "-ldflags=-s -w", "-o", str(out_collector_exe), "main.go"],
                cwd=str(COLLECTOR_DIR),
                env=env,
                capture_output=True,
                text=True,
            )
            if res.returncode == 0 and out_collector_exe.exists():
                print(f"[+] Go 单文件采集器编译完成: {out_collector_exe}")
            else:
                print(f"[!] Go 采集器编译跳过 (可稍后手动执行 go build): {res.stderr.strip()}")
        else:
            print("[*] 当前机器未安装 Go 编译器，已保留 collector/main.go 源码与免编译 win_collector.ps1。")


def main() -> None:
    print("================================================================")
    print("         WinDFIR-AI 应急响应平台一键 EXE 打包工具 v1.0          ")
    print("================================================================")
    ensure_static_vendor_assets()
    ensure_pyinstaller()
    exe_path = build_platform_exe()
    bundle_collector_tools()

    # 预先在 dist 目录下创建好外部可写目录结构示意
    (DIST_DIR / "data").mkdir(parents=True, exist_ok=True)
    (DIST_DIR / "storage").mkdir(parents=True, exist_ok=True)

    print("\n================================================================")
    print("[SUCCESS] 打包全部完成！")
    print(f"  -> 平台可执行程序: {exe_path}")
    print(f"  -> 数据库存储目录: {DIST_DIR / 'data'}")
    print(f"  -> 证据包存储目录: {DIST_DIR / 'storage'}")
    print(f"  -> 终端取证采集器: {DIST_DIR / 'collector'}")
    print("  双击运行 WinDFIR-AI.exe 即可在本地启动后端服务并自动打开浏览器作战台！")
    print("================================================================")


if __name__ == "__main__":
    main()
