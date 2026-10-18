# -- coding: utf-8 --
"""
Detect 检测模块
提供 Detect 程序执行和检测结果查看功能。
"""

import logging
import os
from typing import Optional

from flask import Blueprint, render_template, request, jsonify

import surui_de
import run2
from suricata_check import get_sorted_files
from utils import PCAP_DIR as pcap_files_dir, RULES_DIR as rule_files_dir, get_detect_status, rate_limit

logger = logging.getLogger(__name__)

detect_check = Blueprint('detect_check', __name__, template_folder='./')


def _safe_join_under(base_dir: str, candidate: str) -> Optional[str]:
    """
    把客户端传入的 candidate 路径归一化并校验其必须位于 base_dir 之下。

    用途：防止 /run_detect 等接口被传入 ``/etc/passwd`` 或
    ``../../etc/shadow`` 之类任意路径，导致下游 subprocess / 文件读取
    越权访问。规则：
      1) 不接受空字符串；
      2) realpath 归一化符号链接与 ``../``；
      3) 结果路径必须以 ``realpath(base_dir) + os.sep`` 开头（防止
         ``/data/rules_evil`` 通过 ``/data/rules`` 前缀绕过）。

    Args:
        base_dir: 白名单目录绝对路径（RULES_DIR / PCAP_DIR）。
        candidate: 客户端传入的路径（绝对或相对均可）。

    Returns:
        校验通过则返回归一化后的绝对路径；否则 None。
    """
    if not candidate:
        return None
    safe_base = os.path.realpath(base_dir)
    safe_candidate = os.path.realpath(os.path.join(safe_base, candidate))
    if not (safe_candidate == safe_base
            or safe_candidate.startswith(safe_base + os.sep)):
        return None
    return safe_candidate


@detect_check.route('/detect_check', methods=['GET', 'POST'])
def check():
    """
    显示可用的规则和 PCAP 文件列表，POST 时跳转到检测流程。
    """
    rule_files = get_sorted_files(rule_files_dir, '.rules')
    pcap_files = get_sorted_files(pcap_files_dir, ['.pcap', '.pcapng'])
    detect_status = get_detect_status()

    if request.method == 'POST':
        selected_rule = request.form.get('file_select')
        selected_pcap = request.form.get('pcap_select')

        if not selected_rule or not selected_pcap:
            return render_template(
                'detect_check.html',
                rule_files=rule_files,
                pcap_files=pcap_files,
                error='请选择规则文件和 PCAP 文件',
                detect_status=detect_status,
                previous_page='suricata_check.check',
                next_page='generate_pcap.generate'
            )

        # 使用 os.path.join 确保跨平台安全
        rule_path = os.path.join(rule_files_dir, selected_rule)
        pcap_path = os.path.join(pcap_files_dir, selected_pcap)

        # Detect 未配置时拦截（前端按钮已隐藏，这里防直接 POST 绕过）
        if not detect_status['available']:
            logger.warning("Detect 未配置，拒绝执行: %r", detect_status['bin'])
            return render_template(
                'detect_check.html',
                rule_files=rule_files,
                pcap_files=pcap_files,
                error='本机未配置 Detect（安装目录不存在或 bin_ 为空），无法执行检测',
                detect_status=detect_status,
                previous_page='suricata_check.check',
                next_page='generate_pcap.generate'
            )

        return render_template(
            'intermediate.html',
            message='即将运行 Detect 检查，请稍后',
            script='',
            rule_path=rule_path,
            pcap_path=pcap_path,
            previous_page='detect_check.check',
            next_page='home'
        )

    return render_template(
        'detect_check.html',
        rule_files=rule_files,
        pcap_files=pcap_files,
        detect_status=get_detect_status(),
        previous_page='suricata_check.check',
        next_page='generate_pcap.generate'
    )


@detect_check.route('/run_detect', methods=['GET', 'POST'])
@rate_limit(max_calls=3, window_seconds=60)
def run_detect():
    """
    执行 Detect 检测，返回结果。

    接收 GET 或 POST 请求中的 rule_path 和 pcap_path 参数。
    """
    rule_path = request.form.get('rule_path') or request.args.get('rule_path')
    pcap_path = request.form.get('pcap_path') or request.args.get('pcap_path')

    if not rule_path or not pcap_path:
        return "缺少必要参数: rule_path 或 pcap_path", 400

    # 路径遍历防护：客户端传来的 rule_path / pcap_path 只允许落在
    # 白名单目录（utils.RULES_DIR / utils.PCAP_DIR）下。realpath 归一化
    # 符号链接与 ../，再比对目录前缀——与 suricata_check.load_rules_content
    # 校验方式一致。失败直接 400，不进 run2（任意文件读取 sink 入口）。
    safe_rule_path = _safe_join_under(rule_files_dir, rule_path)
    safe_pcap_path = _safe_join_under(pcap_files_dir, pcap_path)
    if safe_rule_path is None or safe_pcap_path is None:
        logger.warning(
            "run_detect 拒绝越权路径: rule_path=%r pcap_path=%r",
            rule_path, pcap_path,
        )
        return "非法路径", 400

    # Detect 未配置时直接拦下——否则 run2 会因 bin_ 为空产生 500
    detect_status = get_detect_status()
    if not detect_status['available']:
        logger.warning("Detect 未配置，拒绝执行: %r", detect_status['bin'])
        rule_files = get_sorted_files(rule_files_dir, '.rules')
        pcap_files = get_sorted_files(pcap_files_dir, ['.pcap', '.pcapng'])
        return render_template(
            'detect_check.html',
            rule_files=rule_files,
            pcap_files=pcap_files,
            error='本机未配置 Detect（安装目录不存在或 bin_ 为空），无法执行检测',
            detect_status=detect_status,
            previous_page='suricata_check.check',
            next_page='generate_pcap.generate'
        )

    pcap_filename = os.path.basename(safe_pcap_path).split(".")[0]

    try:
        success, result = run2.main(rules_file=safe_rule_path, pcaps_file=safe_pcap_path)
    except Exception as e:
        logger.exception("Detect 执行失败")
        return f"检测执行失败: {e}", 500

    # 失败时不再回显 rules 文件内容——任意文件读取 sink（参见 H-1）。
    # run2.main 失败分支仍会尝试 open(rules_file) 并返回内容，这里覆盖掉。
    if not success:
        result = "未检测到告警，请检查 PCAP 文件或规则文件"

    return render_template(
        'detect_check_result.html',
        output=result,
        pcap_name=pcap_filename,
        previous_page='detect_check.check',
        next_page='generate_pcap.generate'
    )


@detect_check.route('/check_files')
def check_files():
    """
    检查指定目录下的文件状态。

    Returns:
        JSON: {count: int, eve_exists: bool}
    """
    directory = surui_de.detect_path.get('bin_', '') + '/log/'

    try:
        if not os.path.isdir(directory):
            return jsonify({'error': '目录不存在'}), 500

        files = os.listdir(directory)
        eve_exists = 'eve.json' in files

        return jsonify({'count': len(files), 'eve_exists': eve_exists})
    except OSError as e:
        logger.exception("检查目录失败: %s", directory)
        return jsonify({'error': f'目录读取失败: {e}'}), 500
