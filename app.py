# -*- coding: utf-8 -*-
"""
主应用程序入口
- 集成多个 Flask 蓝图
- 设置定时任务定期清理生成的文件
- 所有配置通过环境变量控制
"""

import logging
import os
import shutil
import time
import fcntl

from flask import Flask, render_template, request

# 蓝图导入
from generate_pcap import generate_pcap as generate_pcap_blueprint
from generate_udp import generate_udp as generate_udp_blueprint
from generate_icmp import generate_icmp as generate_icmp_blueprint
from generate_tcp import generate_tcp as generate_tcp_blueprint
from generate_smtp import generate_smtp as generate_smtp_blueprint
from suricata_check import suricata_check as suricata_check_blueprint
from detect_check import detect_check as detect_check_blueprint
from download import download_bp
from utils import get_gen_count

# APScheduler 导入（带兼容性处理）
try:
    from apscheduler.schedulers.background import BackgroundScheduler
except ImportError:
    try:
        from apscheduler import BackgroundScheduler
    except ImportError:
        # 旧版本兼容性
        from apscheduler.schedulers.background import Scheduler as BackgroundScheduler

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 创建 Flask 应用
app = Flask(__name__)

# Flask 配置（从环境变量读取）
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
FLASK_PORT = int(os.getenv("FLASK_PORT", "9900"))
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")

# M-2 修复：限制单个请求体大小，防止超大 payload 占内存。
# - 上传（.pcap / .pcapng / .rules）通常 < 100MB；
# - 生成接口的 request_body / response_body 几乎从不超过几 MB；
# 设为 128MB 给合法大 pcap 留足空间，远低于默认无限制的 OOM 风险。
# 超限请求 Flask 会自动返回 413 Payload Too Large。
_MAX_REQUEST_BYTES = int(os.getenv("WEB_APPS_MAX_REQUEST_BYTES", str(128 * 1024 * 1024)))
app.config['MAX_CONTENT_LENGTH'] = _MAX_REQUEST_BYTES

# 蓝图注册（按功能分组）
# PCAP 生成相关
app.register_blueprint(generate_pcap_blueprint)
app.register_blueprint(generate_udp_blueprint)
app.register_blueprint(generate_icmp_blueprint)
app.register_blueprint(generate_tcp_blueprint)
app.register_blueprint(generate_smtp_blueprint)

# 检测相关
app.register_blueprint(suricata_check_blueprint)
app.register_blueprint(detect_check_blueprint)

# 其他（可选模块）
try:
    from finance import finance_bp as finance_blueprint
    app.register_blueprint(finance_blueprint)
    _finance_available = True
except ImportError:
    _finance_available = False
app.register_blueprint(download_bp)


# 多 worker 进程间互斥：拿不到锁的 worker 本轮直接跳过清理。
# 锁文件放 BASE_DIR 下，避开被清理的 PCAP_DIR/RULES_DIR，防止锁被自己删。
_BASE_DIR_FOR_CLEANUP = os.getenv("WEB_APPS_BASE_DIR", os.getcwd())
_CLEANUP_LOCK_PATH = os.path.join(_BASE_DIR_FOR_CLEANUP, ".web_apps_cleanup.lock")


def clear_directories():
    """
    定时任务：清理 PCAP_DIR/RULES_DIR 下 mtime 超过阈值的文件。

    设计要点：
    1. 阈值由环境变量 WEB_APPS_CLEANUP_HOURS 控制（默认 16h）。
    2. 多 worker 场景用 fcntl.flock 非阻塞锁去重——只一个 worker 真清。
    3. 读 utils.PCAP_DIR/RULES_DIR 而非硬编码，与 operator 配置保持一致。
    4. 只清 mtime 在阈值前的文件，刚生成的不动。
    """
    # 多 worker 去重：拿不到锁说明别的 worker 正在清理，本轮跳过
    lock_fd = None
    try:
        lock_fd = open(_CLEANUP_LOCK_PATH, "w")
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        if lock_fd is not None:
            lock_fd.close()
        logger.debug("cleanup 锁被其他 worker 持有，本轮跳过")
        return

    try:
        # 函数内 import：utils 在 app 启动时已固化目录，模块级引用稳定
        from utils import PCAP_DIR, RULES_DIR

        threshold_hours = float(os.getenv("WEB_APPS_CLEANUP_HOURS", "16"))
        cutoff = time.time() - threshold_hours * 3600

        for directory in (PCAP_DIR, RULES_DIR):
            if not os.path.isdir(directory):
                continue

            for item in os.listdir(directory):
                file_path = os.path.join(directory, item)
                try:
                    if os.path.isfile(file_path):
                        if os.path.getmtime(file_path) < cutoff:
                            os.remove(file_path)
                    elif os.path.isdir(file_path):
                        # 子目录：仅当 mtime 满足条件才清
                        if os.path.getmtime(file_path) < cutoff:
                            shutil.rmtree(file_path)
                except OSError as e:
                    logger.warning("清理文件失败 %s: %s", file_path, e)
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            lock_fd.close()


@app.after_request
def add_cache_control(response):
    """禁用 HTML 响应的浏览器缓存，防止模板更新后仍显示旧内容。"""
    if response.content_type and 'text/html' in response.content_type:
        if 'Cache-Control' not in response.headers:
            response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/')
def home():
    """
    主页：展示所有功能模块的导航链接。
    """
    title = "首页"
    # 功能列表（与 url_prefix 对应，现在都是根路径）
    items = [
        ('生成PCAP', '/generate_pcap'),
        ('UDP生成', '/generate_udp'),
        ('ICMP生成', '/generate_icmp'),
        ('TCP生成', '/generate_tcp'),
        ('SMTP生成', '/generate_smtp'),
        ('Suricata校验', '/suricata_check'),
        ('Detect校验', '/detect_check'),
    ]
    if _finance_available:
        items.append(('金融监控', '/finance'))
    return render_template('home.html', title=title, items=items, next_page='pcap.generate_pcap.generate')


@app.route('/health')
def health():
    """健康检查端点。"""
    return {'status': 'ok'}, 200


@app.route('/count')
def count():
    """使用统计：浏览器访问返回美化页面，API 请求返回 JSON。"""
    counts = get_gen_count()
    last_updated = counts.pop('last_updated', None)
    if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
        return counts, 200
    return render_template('count.html', counts=counts, last_updated=last_updated)


if __name__ == '__main__':
    """
    应用入口：
    1. 启动定时清理任务
    2. 运行 Flask 应用
    """
    logger.info("启动 Web Apps 服务，监听 %s:%s", FLASK_HOST, FLASK_PORT)

    # 注意：scheduler 已在模块顶层根据 WEB_APPS_CLEANUP_ENABLED 启动。
    # __main__ 块不再重复 start；gunicorn 模式下不走此分支。
    app.run(debug=FLASK_DEBUG, port=FLASK_PORT, host=FLASK_HOST)


# 模块顶层：gunicorn 通过 `from app import app` 也会执行此处，
# 因此 cleanup scheduler 必须放在 __main__ 块外，由环境变量显式开启，
# 默认关闭以避免与 e2e_smoke 冲突。
if os.getenv("WEB_APPS_CLEANUP_ENABLED", "false").lower() in ("true", "1", "yes"):
    try:
        _cleanup_scheduler = BackgroundScheduler()
        _cleanup_scheduler.add_job(func=clear_directories, trigger="interval", hours=16)
        _cleanup_scheduler.start()
        logger.info("web_apps 清理任务已启动（每 16h，多 worker 通过 fcntl 去重）")
    except Exception as e:
        logger.exception("web_apps 清理任务启动失败: %s", e)
