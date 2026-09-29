# -*- coding: utf-8 -*-
"""E2E 冒烟测试：真实启动 web_apps Flask 应用并验证核心端点。

按需执行（On Demand）——tdd-guardian 的 e2e lane 在 push 前触发，
不在每次 taskCompleted 时自动跑（自动跑 E2E 浪费时间）。

用法：
    uv run python suricata_tools/web_apps/e2e_smoke.py
退出码 0 = 通过，1 = 失败（含环境启动失败）。
"""

import logging
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
# 待验证端点：首页（模板渲染）+ /health（健康检查）
CHECK_PATHS = ("/", "/health")
START_TIMEOUT_S = 15.0
REQUEST_TIMEOUT_S = 5.0
KILL_TIMEOUT_S = 5.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("e2e_smoke")


def _free_port() -> int:
    """随机分配一个空闲端口，避免与正在运行的开发实例冲突。"""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(port: int) -> bool:
    """轮询 /health 直到就绪或超时。"""
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.monotonic() + START_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT_S) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    return False


def main() -> int:
    port = _free_port()
    env = {
        **os.environ,
        "FLASK_PORT": str(port),
        "FLASK_HOST": "127.0.0.1",
        "FLASK_DEBUG": "false",
    }
    logger.info("启动 web_apps 于 127.0.0.1:%s", port)
    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=APP_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not _wait_for_health(port):
            # 启动失败属环境问题，不是测试失败——但 e2e 门同样不能放行
            logger.error(
                "/health 在 %.0fs 内未就绪，进程退出码：%s",
                START_TIMEOUT_S,
                proc.poll(),
            )
            return 1
        logger.info("/health 就绪")

        for path in CHECK_PATHS:
            url = f"http://127.0.0.1:{port}{path}"
            try:
                with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT_S) as resp:
                    body = resp.read(64 * 1024)  # 页面模板很小，限量读
                    logger.info("GET %s -> %s (%d bytes)", path, resp.status, len(body))
                    if resp.status != 200:
                        return 1
            except urllib.error.HTTPError as exc:
                logger.error("GET %s -> HTTP %s", path, exc.code)
                return 1
        logger.info("冒烟测试通过：%s", ", ".join(CHECK_PATHS))
        return 0
    except Exception:
        logger.exception("冒烟测试执行失败")
        return 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=KILL_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=KILL_TIMEOUT_S)
            logger.warning("应用进程未响应 terminate，已强杀")


if __name__ == "__main__":
    sys.exit(main())
