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
from utils import PCAP_DIR as pcap_files_dir, RULES_DIR as rule_files_dir

logger = logging.getLogger(__name__)

detect_check = Blueprint('detect_check', __name__, template_folder='./')


@detect_check.route('/detect_check', methods=['GET', 'POST'])
def check():
    """
    显示可用的规则和 PCAP 文件列表，POST 时跳转到检测流程。
    """
    rule_files = get_sorted_files(rule_files_dir, '.rules')
    pcap_files = get_sorted_files(pcap_files_dir, ['.pcap', '.pcapng'])

    if request.method == 'POST':
        selected_rule = request.form.get('file_select')
        selected_pcap = request.form.get('pcap_select')

        if not selected_rule or not selected_pcap:
            return render_template(
                'detect_check.html',
                rule_files=rule_files,
                pcap_files=pcap_files,
                error='请选择规则文件和 PCAP 文件',
                previous_page='suricata_check.check',
                next_page='generate_pcap.generate'
            )

        # 使用 os.path.join 确保跨平台安全
        rule_path = os.path.join(rule_files_dir, selected_rule)
        pcap_path = os.path.join(pcap_files_dir, selected_pcap)

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
        previous_page='suricata_check.check',
        next_page='generate_pcap.generate'
    )


@detect_check.route('/run_detect', methods=['GET', 'POST'])
def run_detect():
    """
    执行 Detect 检测，返回结果。

    接收 GET 或 POST 请求中的 rule_path 和 pcap_path 参数。
    """
    rule_path = request.form.get('rule_path') or request.args.get('rule_path')
    pcap_path = request.form.get('pcap_path') or request.args.get('pcap_path')

    if not rule_path or not pcap_path:
        return "缺少必要参数: rule_path 或 pcap_path", 400

    pcap_filename = os.path.basename(pcap_path).split(".")[0]

    try:
        success, result = run2.main(rules_file=rule_path, pcaps_file=pcap_path)
    except Exception as e:
        logger.exception("Detect 执行失败")
        return f"检测执行失败: {e}", 500

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
