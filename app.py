# -*- coding: utf-8 -*-
# app.py
# 作用：主应用程序入口，集成多个Flask蓝图，并设置定时任务定期清理生成的文件

import os
import shutil

from flask import Flask, render_template
# 假设generate_pcap.py与app.py位于同一目录下
from generate_pcap import generate_pcap as generate_pcap_blueprint
from suricata_check import suricata_check as suricata_check_blueprint
from detect_check import detect_check as detect_check_blueprint

from apscheduler.schedulers.background import BackgroundScheduler

# 创建 Flask 应用实例
app = Flask(__name__)


def clear_directories():
    """
    定时任务：清空固定目录下的文件。

    :return: None
    """
    # BASE_DIR = os.getcwd()
    # 设置基础目录路径，可以根据需要进行调整
    BASE_DIR = '/var/www/web_apps/'
    # 定义需要清理的目录列表
    directories = [os.path.join(BASE_DIR, 'ruless'), os.path.join(BASE_DIR, 'pcapss')]
    for directory in directories:
        # 遍历目录中的所有文件和子目录，逐一删除
        for item in os.listdir(directory):
            file_path = os.path.join(directory, item)
            # 如果是文件则删除，如果是子目录则递归删除
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)


@app.after_request
def add_cache_control(response):
    # Check if the response content type is HTML
    if response.content_type and 'text/html' in response.content_type:
        # Only set Cache-Control if not already set to avoid conflicts
        if 'Cache-Control' not in response.headers:
            response.headers['Cache-Control'] = 'public, max-age=3600, must-revalidate'
    return response

@app.route('/')
def home():
    """
    展示功能列表的主页视图。

    :return: 渲染后的HTML页面，包含功能链接。
    """
    title = "首页"
    # 修改items为包含项目名称和链接地址的元组列表
    items = [
        ('生成PCAP', '/generate_pcap'),
        ('suricata校验', '/suricata_check'),
        ('Detect校验', '/detect_check'),
        ('其他', '/other')
    ]
    # 使用render_template渲染home.html模板文件
    return render_template('home.html', title=title, items=items, next_page='generate_pcap.generate')


if __name__ == '__main__':
    """
    应用程序的入口。

    1. 配置并启动定时任务，定期清理指定目录下的文件。
    2. 注册各个功能模块的蓝图。
    3. 启动 Flask 应用，监听 0.0.0.0:9900 端口。
    """
    # 创建后台调度器实例
    scheduler = BackgroundScheduler()
    # 2024-7-12 考虑，由于每天创建 PCAP 太多，文件只保留 16 小时
    scheduler.add_job(func=clear_directories, trigger="interval", hours=16)
    scheduler.start()

    # 注册生成PCAP、suricata校验和Detect校验的蓝图，绑定到根路径下
    app.register_blueprint(generate_pcap_blueprint, url_prefix='/')
    app.register_blueprint(suricata_check_blueprint, url_prefix='/')
    app.register_blueprint(detect_check_blueprint, url_prefix='/')
    # app.run(debug=True, port=9900, host='0.0.0.0')

    # 启动 Flask 应用，启用调试模式，监听指定端口和IP地址
    try:
        app.run(debug=True, port=9900, host='0.0.0.0')
    finally:
        # 确保在应用关闭时，正确关闭调度器
        scheduler.shutdown()  # Properly shutdown the scheduler when closing the app
