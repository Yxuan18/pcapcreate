# -- coding: utf-8 --
"""
Suricata 检测模块
提供 PCAP 和规则文件的上传、Suricata 检测、以及规则文件内容加载功能。
"""

import logging
import os
import random
import re
import shutil
import string
from datetime import datetime
from typing import Optional

import pytz
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

import surui_de
from utils import PCAP_DIR as pcap_files_dir, RULES_DIR as rule_files_dir, get_detect_status

logger = logging.getLogger(__name__)

# 魔法字符串常量化
SURICATA_ALERT_PATTERNS = (
    'Info: counters: Alerts: 1',
    '<Info> - Alerts: 1',
)
LOG_FILES = ('suricata.log', 'eve.json', 'fast.log', 'stats.log')
ALLOWED_EXTENSIONS = ('.pcap', '.pcapng', '.rules')

# 蓝图定义
suricata_check = Blueprint('suricata_check', __name__, template_folder='./')


def clear_logs() -> None:
    """
    删除当前目录下的 Suricata 日志文件。

    原因：确保每次检测前环境干净，避免旧日志干扰分析。
    """
    for file_name in LOG_FILES:
        try:
            os.remove(file_name)
        except FileNotFoundError:
            pass  # 文件不存在，忽略
        except OSError as e:
            logger.exception("删除日志文件 %s 失败", file_name)


def get_suricata_status() -> dict:
    """
    探测本地 Suricata 可用性：配置路径（surui_de.suri_path）优先，PATH 兜底。

    Returns:
        {'available': bool, 'bin': str, 'version': str}
        bin 为实际可执行的路径；不可用时为配置路径，供页面提示定位。
    """
    configured = surui_de.suri_path.get('bin_', '')
    candidates = [configured, shutil.which('suricata')]
    bin_path = next(
        (c for c in candidates if c and os.path.isfile(c) and os.access(c, os.X_OK)),
        ''
    )
    if not bin_path:
        return {'available': False, 'bin': configured, 'version': ''}

    version = ''
    try:
        result = subprocess.run(
            [bin_path, '-V'], capture_output=True, timeout=10
        )
        version = (result.stdout + result.stderr).decode('utf-8', errors='ignore').strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        # 版本探测失败不等于不可用，只降级为无版本信息
        logger.warning("获取 Suricata 版本失败: %s", e)
    return {'available': True, 'bin': bin_path, 'version': version}


def get_sorted_files(directory: str, suffixes: str | list[str], display_count: Optional[int] = None) -> list[str]:
    """
    获取指定目录下按创建时间倒序排列的文件列表。

    Args:
        directory: 目录路径
        suffixes: 文件后缀（单个或列表）
        display_count: 显示数量上限，None 表示不限制

    Returns:
        按创建时间倒序排列的文件名列表
    """
    if isinstance(suffixes, str):
        suffixes = [suffixes]

    # 确保目录存在
    os.makedirs(directory, exist_ok=True)

    # 过滤符合后缀的文件
    files = [
        f for f in os.listdir(directory)
        if any(f.endswith(suffix) for suffix in suffixes)
    ]

    # 按创建时间倒序
    files.sort(key=lambda x: os.path.getctime(os.path.join(directory, x)), reverse=True)

    if display_count is not None and len(files) > display_count:
        return files[:display_count]
    return files


@suricata_check.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    """
    处理 PCAP 或 RULES 文件上传，保存到预定义目录。

    Returns:
        成功消息或错误信息和 HTTP 状态码
    """
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    if not file.filename:
        return "No selected file", 400

    filename = secure_filename(file.filename)
    if not filename:
        return "Invalid file name", 400

    if filename.endswith('.pcap') or filename.endswith('.pcapng'):
        file.save(os.path.join(pcap_files_dir, filename))
        return "PCAP File uploaded successfully", 200
    elif filename.endswith('.rules'):
        file.save(os.path.join(rule_files_dir, filename))
        return "RULES File uploaded successfully", 200
    else:
        return "Invalid file type", 400


@suricata_check.route('/suricata_check', methods=['GET', 'POST'])
def check():
    """
    显示可用的 PCAP 和 RULES 文件，POST 时执行 Suricata 检测。

    流程：
    1. 获取所有 pcap 和 rules 文件
    2. 若提交规则内容，创建以时间戳命名的新规则文件
    3. 若执行检测，调用 Suricata，成功后跳转到 Detect 检查流程
    """
    rule_files = get_sorted_files(rule_files_dir, '.rules')
    pcap_files = get_sorted_files(pcap_files_dir, ['.pcap', '.pcapng'])
    suricata_status = get_suricata_status()
    detect_status = get_detect_status()

    output = ""

    if request.method == 'POST':
        selected_rule = request.form.get('file_select')
        selected_pcap = request.form.get('pcap_select')

        # 路径安全校验
        safe_rule_path = None
        safe_pcap_path = None

        if selected_rule:
            safe_rule_path = os.path.realpath(os.path.join(rule_files_dir, selected_rule))
            if not safe_rule_path.startswith(os.path.realpath(rule_files_dir) + os.sep):
                return "非法规则文件路径", 400

        if selected_pcap:
            safe_pcap_path = os.path.realpath(os.path.join(pcap_files_dir, selected_pcap))
            if not safe_pcap_path.startswith(os.path.realpath(pcap_files_dir) + os.sep):
                return "非法 PCAP 文件路径", 400

        suri_bin = suricata_status['bin']
        suri_yaml = surui_de.suri_path['yaml']
        selected_rule_path = safe_rule_path or rule_files_dir
        selected_pcap_path = safe_pcap_path or pcap_files_dir

        # 构建命令（避免 shell 注入）
        command = [
            suri_bin,
            '-c', suri_yaml,
            '-s', selected_rule_path,
            '-r', selected_pcap_path,
            '-k', 'none',
            '-v'
        ]

        # 保存新的规则内容
        if 'file_content_edit' in request.form and 'load_rules' in request.form:
            file_content = request.form.get('file_content_edit', '').strip()
            if file_content:
                # 生成带时间戳的规则文件名
                times = datetime.now(pytz.timezone('Asia/Shanghai')).strftime("%m%d-%H%M%S-")
                rand_num = ''.join(random.choices(string.digits, k=2))
                new_rule_path = os.path.join(rule_files_dir, f'{times}{rand_num}.rules')

                # 提取协议类型
                match = re.search(r'metadata:service\s+(\w+);', file_content)
                if match:
                    protocol = match.group(1)
                elif '; http.' in file_content:
                    protocol = 'http'
                else:
                    protocol = 'udp'

                rule_content = f'alert {protocol} any any -> any any (msg:"{rand_num}"; {file_content} sid:{rand_num};)'
                with open(new_rule_path, 'w', encoding='utf-8') as f:
                    f.write(rule_content)

                logger.info("创建新规则文件: %s", new_rule_path)

            return redirect(url_for('suricata_check.check'))

        # 执行 Suricata 检测
        if 'execute' in request.form:
            # Suricata 不可用时服务端再挡一道（前端 disabled 可被直接 POST 绕过）
            if not suricata_status['available']:
                logger.warning("Suricata 不可用，拒绝执行检查: %s", suricata_status['bin'])
                return render_template(
                    'suricata_check.html',
                    rule_files=rule_files,
                    pcap_files=pcap_files,
                    suricata_status=suricata_status,
                    detect_status=detect_status,
                    error='未检测到本地 Suricata，无法执行检查',
                    previous_page='home',
                    next_page='detect_check.check'
                )
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            output = stdout.decode() + stderr.decode()

            # 检测到告警时跳转到 Detect 检查
            if any(pattern in output for pattern in SURICATA_ALERT_PATTERNS):
                clear_logs()
                message = "即将运行 Detect 检查，请稍后"
                redirect_url = url_for('detect_check.run_detect', rule_path=selected_rule_path, pcap_path=selected_pcap_path)
                script = f'setTimeout(function() {{ window.location.href = "{redirect_url}"; }}, 2000);'
                return render_template(
                    'intermediate.html',
                    message=message,
                    script=script,
                    rule_path=selected_rule_path,
                    pcap_path=selected_pcap_path,
                    previous_page='suricata_check.check',
                    next_page='detect_check.check'
                )
            else:
                return render_template(
                    'suricata_check_result.html',
                    output=output,
                    previous_page='suricata_check.check',
                    next_page='detect_check.check'
                )

        if 'detect' in request.form:
            # Detect 未配置时拦截（前端按钮已隐藏，这里防直接 POST 绕过）
            if not detect_status['available']:
                logger.warning("Detect 未配置，拒绝执行: %r", detect_status['bin'])
                return render_template(
                    'suricata_check.html',
                    rule_files=rule_files,
                    pcap_files=pcap_files,
                    suricata_status=suricata_status,
                    detect_status=detect_status,
                    error='本机未配置 Detect（安装目录不存在或 bin_ 为空），无法执行检测',
                    previous_page='home',
                    next_page='detect_check.check'
                )
            message = "即将运行 Detect 检查，请稍后"
            redirect_url = url_for('detect_check.run_detect', rule_path=selected_rule_path, pcap_path=selected_pcap_path)
            script = f'setTimeout(function() {{ window.location.href = "{redirect_url}"; }}, 2000);'
            return render_template(
                'intermediate.html',
                message=message,
                script=script,
                rule_path=selected_rule_path,
                pcap_path=selected_pcap_path,
                previous_page='suricata_check.check',
                next_page='detect_check.check'
            )

    return render_template(
        'suricata_check.html',
        rule_files=rule_files,
        pcap_files=pcap_files,
        suricata_status=suricata_status,
        detect_status=detect_status,
        previous_page='home',
        next_page='detect_check.check'
    )


@suricata_check.route('/load_rules_content')
def load_rules_content():
    """
    加载指定规则文件内容。

    路径遍历防护：仅允许读取 rules 目录下的文件。
    """
    file_name = request.args.get('file')
    if not file_name:
        return "No file specified", 400

    safe_dir = os.path.realpath(rule_files_dir)
    file_path = os.path.realpath(os.path.join(rule_files_dir, file_name))

    if not file_path.startswith(safe_dir + os.sep) and file_path != safe_dir:
        logger.warning("路径遍历尝试: %s", file_name)
        return "非法路径", 400

    if not os.path.exists(file_path):
        return "文件不存在", 404

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except OSError as e:
        logger.exception("读取规则文件失败: %s", file_name)
        return "文件读取失败", 500
