"""
前端核心静态依赖本地化下载脚本 (download_assets.py)
用途：
将 Vue 3、Tailwind CSS、AntV G6、Marked.js 下载保存到 backend/static/vendor/ 目录下，
确保系统在应急响应纯内网/断网环境或 PyInstaller 打包成 .exe 后无需联网即可正常加载作战大屏，杜绝断网白屏。
"""

import logging
import urllib.request
from pathlib import Path

from utils.path_helper import get_static_dir

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("windfir.assets")

# 定义需要本地化的前端核心依赖清单（含主备双镜像源，确保国内网络稳定下载）
VENDOR_ASSETS: dict[str, list[str]] = {
    "vue.global.prod.js": [
        "https://unpkg.com/vue@3.4.38/dist/vue.global.prod.js",
        "https://cdn.jsdelivr.net/npm/vue@3.4.38/dist/vue.global.prod.js",
        "https://cdnjs.cloudflare.com/ajax/libs/vue/3.4.38/vue.global.prod.min.js",
    ],
    "tailwindcss.js": [
        "https://cdn.tailwindcss.com/3.4.13",
        "https://unpkg.com/tailwindcss-cdn@3.4.10/tailwindcss.js",
    ],
    "g6.min.js": [
        "https://gw.alipayobjects.com/os/lib/antv/g6/4.8.24/dist/g6.min.js",
        "https://unpkg.com/@antv/g6@4.8.24/dist/g6.min.js",
        "https://cdn.jsdelivr.net/npm/@antv/g6@4.8.24/dist/g6.min.js",
    ],
    "marked.min.js": [
        "https://unpkg.com/marked@12.0.2/marked.min.js",
        "https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/marked/12.0.2/marked.min.js",
    ],
}


def ensure_vendor_assets(force: bool = False) -> dict[str, str]:
    """
    检查并下载所有前端静态资源到 static/vendor/ 目录
    返回各文件的状态字典
    """
    vendor_dir: Path = get_static_dir() / "vendor"
    vendor_dir.mkdir(parents=True, exist_ok=True)
    status_report: dict[str, str] = {}

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        )
    }

    for filename, urls in VENDOR_ASSETS.items():
        target_path = vendor_dir / filename
        if target_path.exists() and target_path.stat().st_size > 1024 and not force:
            logger.info(f"[已就绪] {filename} ({target_path.stat().st_size // 1024} KB)")
            status_report[filename] = "cached"
            continue

        downloaded = False
        for url in urls:
            try:
                logger.info(f"正在下载 {filename} <- {url} ...")
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=25) as resp:
                    content = resp.read()
                    if len(content) > 1024:
                        target_path.write_bytes(content)
                        logger.info(f"[下载成功] {filename} ({len(content) // 1024} KB)")
                        status_report[filename] = "downloaded"
                        downloaded = True
                        break
            except Exception as exc:
                logger.warning(f"从镜像 {url} 下载 {filename} 失败: {exc}")

        if not downloaded:
            logger.error(f"[下载失败] {filename} 所有镜像均不可达，前端将回退至在线 CDN 或本地轻量兜底脚本。")
            status_report[filename] = "failed"

    return status_report


if __name__ == "__main__":
    result = ensure_vendor_assets()
    print("静态资源本地化结果:", result)
