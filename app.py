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

from flask import Flask, render_template

# 蓝图导入
from generate_pcap import generate_pcap as generate_pcap_blueprint
from generate_udp import generate_udp as generate_udp_blueprint
from generate_icmp import generate_icmp as generate_icmp_blueprint
from generate_tcp import generate_tcp as generate_tcp_blueprint
from generate_smtp import generate_smtp as generate_smtp_blueprint
from suricata_check import suricata_check as suricata_check_blueprint
from detect_check import detect_check as detect_check_blueprint
from finance import finance_bp as finance_blueprint
from download import download_bp

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

# 其他
app.register_blueprint(finance_blueprint)
app.register_blueprint(download_bp)


def clear_directories():
    """
    定时任务：清空 ruless 和 pcapss 目录下的文件。

    原因：每天创建 PCAP 太多，文件只保留 16 小时。
    """
    base_dir = os.getenv("WEB_APPS_BASE_DIR", os.getcwd())
    directories = [
        os.path.join(base_dir, 'ruless'),
        os.path.join(base_dir, 'pcapss')
    ]

    for directory in directories:
        if not os.path.isdir(directory):
            continue

        for item in os.listdir(directory):
            file_path = os.path.join(directory, item)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except OSError as e:
                logger.warning("清理文件失败 %s: %s", file_path, e)


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
        ('金融监控', '/finance'),
    ]
    return render_template('home.html', title=title, items=items, next_page='pcap.generate_pcap.generate')


@app.route('/health')
def health():
    """健康检查端点。"""
    return {'status': 'ok'}, 200


if __name__ == '__main__':
    """
    应用入口：
    1. 启动定时清理任务
    2. 运行 Flask 应用
    """
    logger.info("启动 Web Apps 服务，监听 %s:%s", FLASK_HOST, FLASK_PORT)

    scheduler = BackgroundScheduler()
    scheduler.add_job(func=clear_directories, trigger="interval", hours=16)
    scheduler.start()

    try:
        app.run(debug=FLASK_DEBUG, port=FLASK_PORT, host=FLASK_HOST)
    finally:
        scheduler.shutdown()
        logger.info("Web Apps 服务已关闭")
