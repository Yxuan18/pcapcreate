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
from utils import PCAP_DIR as pcap_files_dir, RULES_DIR as rule_files_dir, get_detect_status, inc_gen_count

logger = logging.getLogger(__name__)

# 魔法字符串常量化
SURICATA_ALERT_PATTERNS = (
    'Info: counters: Alerts: 1',
    '<Info> - Alerts: 1',
)
LOG_FILES = ('suricata.log', 'eve.json', 'fast.log', 'stats.log')
ALLOWED_EXTENSIONS = ('.pcap', '.pcapng', '.rules')


# PCAP 文件魔数
PCAP_MAGIC_BIG_ENDIAN = b'\xa1\xb2\xc3\xd4'   # 大端序
PCAP_MAGIC_LITTLE_ENDIAN = b'\xd4\xc3\xb2\xa1'  # 小端序
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'             # PCAPNG

# 敏感路径正则：匹配常见的绝对路径模式（可能泄漏部署信息）
_SENSITIVE_PATH_PATTERN = re.compile(
    r'(^|/)(usr|opt|etc|var|home|Users|Applications|Clash|Meta|'
    r'\.config|'
    r'/[a-zA-Z0-9_.-]+){1,3}/[^/\s]+'  # 路径段
)


def _sanitize_output(output: str) -> str:
    """
    过滤 Suricata 输出中的敏感路径信息，防止路径泄漏攻击。

    替换规则：
    - 绝对路径 → [路径已隐藏]
    - 配置文件路径中的实际路径 → [配置已隐藏]
    - socket 路径 → [socket 已隐藏]

    Args:
        output: 原始 stdout/stderr 输出

    Returns:
        过滤后的安全输出
    """
    lines = output.splitlines()
    safe_lines = []
    for line in lines:
        # 跳过包含完整绝对路径的调试信息行
        stripped = line.strip()
        if (
            # Suricata 版本/构建信息
            'This is' in line and ('Suricata' in line or 'Open Source' in line) or
            # 配置加载详情（包含配置文件路径）
            stripped.startswith('Loading configuration') or
            'config' in line.lower() and '.yaml' in line.lower() or
            # Socket 相关（包含 socket 路径）
            'socket' in line.lower() or
            # 规则加载详情
            'Loading rules' in line or
            'Loading ' in line and 'rules' in line or
            # 统计信息中的路径
            '.yaml' in line or '.conf' in line or
            # 完整的命令行参数展示
            ('-' in line and '.yaml' in line and '/') or
            # 包含多个路径段的复杂行（很可能是路径泄漏）
            len([p for p in _SENSITIVE_PATH_PATTERN.findall(line)]) > 1
        ):
            # 替换路径部分
            cleaned = _SENSITIVE_PATH_PATTERN.sub('[路径已隐藏]', line)
            safe_lines.append(cleaned)
        elif (
            # 告警相关行保留（包含检测结果信息）
            'alert' in line.lower() or
            'Info' in line or
            'Warning' in line or
            'Error' in line or
            'statistics' in line.lower() or
            'packets' in line.lower() or
            # 简单的状态信息
            len(stripped) < 100 and not '/' in stripped
        ):
            safe_lines.append(line)
        else:
            # 其他行也隐藏路径
            cleaned = _SENSITIVE_PATH_PATTERN.sub('[路径已隐藏]', line)
            if cleaned.strip():
                safe_lines.append(cleaned)

    return '\n'.join(safe_lines)


def verify_pcap_file(file_stream, filename: str) -> bool:
    """
    校验文件内容是否为合法的 PCAP 或 PCAPNG 文件。

    通过读取文件头魔数来判断，而非依赖后缀。
    保存后返回前会恢复文件指针。

    Args:
        file_stream: 已打开的文件流（必须可读）
        filename: 文件名（用于日志）

    Returns:
        True 是合法 PCAP/PCAPNG 文件，False 不是
    """
    try:
        header = file_stream.read(4)
        if not header or len(header) < 4:
            logger.warning("文件 %s 太短，无法读取魔数", filename)
            return False

        # 恢复文件指针（供后续 save() 使用）
        file_stream.seek(0)

        if header == PCAP_MAGIC_BIG_ENDIAN or header == PCAP_MAGIC_LITTLE_ENDIAN:
            return True
        if header == PCAPNG_MAGIC:
            return True

        logger.warning("文件 %s 不是有效的 PCAP/PCAPNG 文件，魔数: %s",
                       filename, header.hex())
        return False

    except OSError:
        logger.exception("读取文件 %s 头失败", filename)
        return False


def verify_rules_file(file_stream, filename: str) -> tuple[bool, str]:
    """
    校验文件内容是否符合 Suricata 规则语法。

    Suricata 规则格式：action protocol src dst direction (options) sid:xxx;
    每行可以是：
    - 空行（跳过）
    - 注释行（# 开头，跳过）
    - 有效规则（必须包含 action、protocol、方向和括号内选项）

    Args:
        file_stream: 已打开的文件流
        filename: 文件名（用于日志）

    Returns:
        (True, '') 校验通过
        (False, '错误信息') 校验失败，包含失败原因
    """
    try:
        content = file_stream.read().decode('utf-8', errors='replace')
    except OSError:
        logger.exception("读取文件 %s 失败", filename)
        return False, "文件读取失败"

    # 常见 action 和 protocol
    ACTIONS = {'alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'sdrop', 'log'}
    PROTOCOLS = {
        'tcp', 'udp', 'icmp', 'http', 'http2', 'ftp', 'smtp', 'ssh', 'dns',
        'tls', 'ssl', 'ssh', 'dcerpc', 'nfs', 'smb', 'imap', 'pop', 'sip',
        'modbus', 'enip', 'dnp3', 'ftp-data', 'rdp', 'snmp', 'ip', 'vlan',
    }
    DIRECTIONS = {'->', '<>', '<-'}

    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        # 跳过空行和注释行
        if not stripped or stripped.startswith('#'):
            continue

        # 检查括号配对（规则主体在括号内）
        if stripped.count('(') != stripped.count(')'):
            logger.warning("文件 %s 第 %d 行：括号不配对", filename, lineno)
            return False, f"第 {lineno} 行：括号不配对"

        # 最小结构：必须包含方向符号和括号
        has_direction = any(d in stripped for d in DIRECTIONS)
        has_paren = '(' in stripped and ')' in stripped
        if not (has_direction and has_paren):
            logger.warning("文件 %s 第 %d 行：缺少方向符号或括号", filename, lineno)
            return False, f"第 {lineno} 行：缺少方向符号或括号"

        # 提取 action（第一个词）
        parts = stripped.split()
        if not parts:
            continue
        action = parts[0]
        if action not in ACTIONS:
            logger.warning("文件 %s 第 %d 行：未知 action '%s'，期望 %s",
                          filename, lineno, action, ACTIONS)
            return False, f"第 {lineno} 行：未知 action '{action}'"

        # 提取 protocol（第二个词，必须是已知协议）
        if len(parts) < 2:
            logger.warning("文件 %s 第 %d 行：缺少 protocol", filename, lineno)
            return False, f"第 {lineno} 行：缺少 protocol"

        protocol = parts[1]
        if protocol not in PROTOCOLS:
            logger.warning("文件 %s 第 %d 行：未知 protocol '%s'",
                          filename, lineno, protocol)
            return False, f"第 {lineno} 行：未知 protocol '{protocol}'"

        # 检查括号内是否有 sid
        paren_start = stripped.index('(')
        paren_end = stripped.rindex(')')
        options_block = stripped[paren_start + 1:paren_end]

        # sid 格式：sid:数字;（sid 前后可能有空格）
        if not re.search(r'\bsid\s*:\s*\d+\s*;', options_block):
            logger.warning("文件 %s 第 %d 行：缺少 sid（格式应为 sid:数字;）", filename, lineno)
            return False, f"第 {lineno} 行：缺少 sid（格式应为 sid:数字;）"

    # 全部通过或仅空文件
    return True, ""


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
        except OSError:
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
        # 先校验文件内容是否为合法的 PCAP/PCAPNG
        if not verify_pcap_file(file, filename):
            return "Invalid PCAP file content", 400
        file.seek(0)  # 重置指针后再保存
        file.save(os.path.join(pcap_files_dir, filename))
        return "PCAP File uploaded successfully", 200
    elif filename.endswith('.rules'):
        # 校验规则文件语法
        ok, err = verify_rules_file(file, filename)
        if not ok:
            return err, 400
        file.seek(0)  # 重置指针后再保存
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
        # 注意：移除 -v 参数避免泄漏应用路径、配置路径、socket 路径等敏感信息
        command = [
            suri_bin,
            '-c', suri_yaml,
            '-s', selected_rule_path,
            '-r', selected_pcap_path,
            '-k', 'none',
            '-l', 'notice'  # 只输出 notice 及以上级别，不泄漏调试信息
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
            raw_output = stdout.decode() + stderr.decode()
            # 过滤敏感路径信息，防止路径泄漏
            output = _sanitize_output(raw_output)
            inc_gen_count("suricata_check")

            # 检测到告警时跳转到 Detect 检查（使用原始输出检测，过滤后的输出可能丢失特征）
            if any(pattern in raw_output for pattern in SURICATA_ALERT_PATTERNS):
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
    except OSError:
        logger.exception("读取规则文件失败: %s", file_name)
        return "文件读取失败", 500
