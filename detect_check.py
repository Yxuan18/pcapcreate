# -- coding: utf-8 -- 
# Name: detect_check.py
# Where:
# 作用：提供Flask蓝图，用于运行检测和检查文件状态的API
from flask import Blueprint, render_template, request, redirect, url_for, jsonify
import run2
import os
import surui_de

# 定义名为 detect_check 的蓝图，用于注册与检测相关的路由
detect_check = Blueprint('detect_check', __name__, template_folder='./')


@detect_check.route('/run_detect', methods=['POST'])
def run_detect():
    """
    接收 POST 请求，根据提供的规则文件路径和 PCAP 文件路径执行检测。

    :return: 渲染后的HTML页面，显示检测结果或错误信息。
    :raises KeyError: 如果请求中缺少 'rule_path' 或 'pcap_path' 参数。
    """
    # 获取POST请求中规则文件和PCAP文件的路径
    rule_path = request.form.get('rule_path')
    pcap_path = request.form.get('pcap_path')
    pcap_filename = os.path.basename(pcap_path).split(".")[0]  # 获取PCAP文件的基础文件名（不含扩展名）

    # 调用 run2.main 方法执行检测，并返回结果
    aa, returns_text = run2.main(rules_file=rule_path, pcaps_file=pcap_path)
    # 根据检测结果，渲染模板并返回内容
    # 在 aa 为 True 的时候，返回 eve.json 的内容
    if aa is True:
        return render_template('detect_check_result.html', output=returns_text, pcap_name=pcap_filename)
    else:
        return render_template('detect_check_result.html', output=returns_text, pcap_name=pcap_filename)


@detect_check.route('/check_files')
def check_files():
    """
    检查指定目录下的文件数量，并判断是否存在 eve.json 文件。

    :return: JSON 格式的数据，包括文件数量和是否存在 eve.json 文件。
    :raises Exception: 如果无法读取目录内容，返回包含错误信息的JSON响应。
    """
    # 指定要检查的目录，从 surui_de 配置中获取
    directory = surui_de.detect_path.get('bin_') + '/log/'  # 指定目录
    try:
        # 列出目录中的所有文件
        files = os.listdir(directory)
        eve_exists = 'eve.json' in files    # 判断 eve.json 文件是否存在
        return jsonify({'count': len(files), 'eve_exists': eve_exists})
    except Exception as e:
        # 如果读取目录时出现错误，返回错误信息
        return jsonify({'error': str(e)}), 500