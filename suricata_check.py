# -- coding: utf-8 -- 
# Name: suricata_check.py
# Where:
# 作用：提供Flask蓝图，用于管理PCAP和规则文件的上传、Suricata检测、以及规则文件内容加载的API

import re
from datetime import datetime
import pytz
from flask import Blueprint, render_template, request, redirect, url_for, flash
import subprocess
import os
import random
import string
import surui_de

# 定义名为 suricata_check 的蓝图，用于注册与 Suricata 检测相关的路由
suricata_check = Blueprint('suricata_check', __name__, template_folder='./')

# 假定.pcacp文件存储在以下目录
rule_files_dir = os.path.join(os.path.dirname(__file__), 'ruless/')
pcap_files_dir = os.path.join(os.path.dirname(__file__), 'pcapss/')


def clear_logs():
    """
    删除当前目录下的 suricata.log 和 eve.json 文件。
    确保路径下是干净的 Python  文件，而不是乱七八糟的

    :return: None
    """
    log_files = ['suricata.log', 'eve.json', 'fast.log', 'stats.log']
    for file_name in log_files:
        try:
            os.remove(file_name)
            # print(f"{file_name} 已被删除。")
        except FileNotFoundError:
            # 如果文件不存在，则忽略该错误
            pass
        except Exception as e:
            print(f"删除 {file_name} 时发生错误: {e}")

@suricata_check.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    """
    处理上传的PCAP或RULES文件，将其保存到预定义的目录中。

    :return: 成功时返回"PCAP File uploaded successfully" 或 "RULES File uploaded successfully"，
             否则返回错误信息和HTTP状态码400。
    :raises KeyError: 如果请求中缺少文件。
    """
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    # 根据文件类型保存到相应的目录
    if file and (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
        filename = file.filename
        file.save(os.path.join(pcap_files_dir, filename))
        return "PCAP File uploaded successfully", 200
    if file and file.filename.endswith('.rules'):
        filename = file.filename
        file.save(os.path.join(rule_files_dir, filename))
        return "RULES File uploaded successfully", 200
    else:
        return "Invalid file type", 400


def get_sorted_files(directory: str, suffixes, display_count=None) -> list:
    """
    获取指定目录下按创建时间倒序排列的文件列表。

    :param directory: 目录路径，类型为 str。
    :param suffixes: 文件后缀，可以是单个后缀字符串或后缀列表，类型为 str 或 list。
    :param display_count: 要显示的文件数量，类型为 int。
    :return: 按创建时间倒序排列的文件列表，如果数量超过指定值，仅返回显示数量的文件。
    """
    # 确保 suffixes 是列表
    if isinstance(suffixes, str):
        suffixes = [suffixes]

    # 如果路径不存在，则创建目录
    if not os.path.exists(directory):
        os.makedirs(directory)
    # 获取所有符合条件的文件
    files = [f for f in os.listdir(directory) if any(f.endswith(suffix) for suffix in suffixes)]
    # 根据创建时间倒序排列
    files.sort(key=lambda x: os.path.getctime(os.path.join(directory, x)), reverse=True)
    if display_count is None:
        return files
    else:
        return files[:display_count] if len(files) > display_count else files
    # 返回文件列表，限制显示数量
    # return files[:display_count] if len(files) > display_count else files


@suricata_check.route('/suricata_check', methods=['GET', 'POST'])
def check():
    """
    显示所有可用的PCAP文件和RULES文件，并在POST请求时执行Suricata检测。

    1、获取所有的 pcap 文件与 rules 文件
    2、确定唯一的请求方式是 POST
    3、若为 加载.rules文件内容，则以  日期时间-随机数.rules 命名规则
    4、若点击了 执行Suricata检查 ，则：
        - 调用 SURICATA 进行检查
        - 检查成功后，调用 火焰
        - 火焰检查后生成 eve.json
        - 将 JSON 内容返回到到页面中

    :return: 渲染后的HTML页面，显示文件列表或检测结果。
    """
    # 获取所有的 .rules 文件，按照创建时间倒序排列
    # rule_files = [f for f in os.listdir(rule_files_dir) if f.endswith('.rules')]
    # rule_files.sort(key=lambda x: os.path.getctime(os.path.join(rule_files_dir, x)), reverse=True)
    rule_files = get_sorted_files(directory=rule_files_dir, suffixes='.rules', display_count=None)
    # 获取所有的 .pcap 文件，按照创建时间倒序排列
    # pcap_files = [f for f in os.listdir(pcap_files_dir) if f.endswith('.pcap') or f.endswith('.pcapng')]
    # pcap_files.sort(key=lambda x: os.path.getctime(os.path.join(pcap_files_dir, x)), reverse=True)
    pcap_files = get_sorted_files(directory=pcap_files_dir, suffixes=['.pcap', '.pcapng'], display_count=None)
    output = ""  # 初始化输出变量
    if request.method == 'POST':
        selected_rule = request.form.get('file_select')
        selected_pcap = request.form.get('pcap_select')

        # suricata 可执行文件路径
        suri_bin_ = surui_de.suri_path['bin_']
        # suricata yaml 文件路径
        suri_yaml = surui_de.suri_path['yaml']
        # 规则文件的绝对路径
        selected_rule_path = rule_files_dir + selected_rule
        # PCAP 文件的绝对路径
        selected_pcap_path = pcap_files_dir + selected_pcap

        # 构建 suricata 执行命令
        command = f'{suri_bin_} -c {suri_yaml} -s {selected_rule_path} -r \"{selected_pcap_path}\" -k none -v'
        if 'file_content_edit' in request.form and 'load_rules' in request.form:
            # 注意修改为 file_content_edit
            # 去掉两边多余的空格
            # 如果表单中包含 file_content_edit 和 load_rules，则保存新的规则内容
            file_content = request.form.get('file_content_edit').strip()
            # 获取当前时间（东八区）和随机数，生成新的规则文件名
            times = datetime.now(pytz.timezone('Asia/Shanghai')).strftime("%m%d-%H%M%S-")
            random_number = ''.join([random.choice(string.digits) for i in range(2)])
            selected_rule = os.path.join(rule_files_dir, f'{times}{random_number}.rules')

            # 将规则内容写入新文件
            with open(selected_rule, 'w', encoding='utf-8') as f:
                if '; http.' in file_content:
                    ffs = f'alert http any any -> any any (msg:"{random_number}"; {file_content} sid:{random_number};)'
                elif 'metadata:service tcp;' in file_content:
                    ffs = f'alert tcp any any -> any any (msg:"{random_number}"; {file_content} sid:{random_number};)'
                else:
                    ffs = f'alert udp any any -> any any (msg:"{random_number}"; {file_content} sid:{random_number};)'
                f.write(ffs)
            # 重定向到同一页面以更新文件列表
            return redirect(url_for('suricata_check.check'))

        if 'execute' in request.form:  # 确保表单中有一个name为execute的提交按钮 如果用户点击了“执行Suricata检查”按钮
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            output = stdout.decode() + stderr.decode()

            # 如果检测成功，跳转到 Detect 检查流程
            if 'Info: counters: Alerts: 1' in output or '<Info> - Alerts: 1' in output:
                clear_logs()
                # 返回一个带有延迟执行脚本的页面
                message = "即将运行 Detect 检查，请稍后"
                script = '''
                    setTimeout(function() {{
                        window.location.href = "/run_detect?rule_path={}&pcap_path={}";
                    }}, 2000);
                '''.format(selected_rule_path, selected_pcap_path)
                return render_template('intermediate.html', message=message, script=script,
                                       rule_path=selected_rule_path, pcap_path=selected_pcap_path)
            else:
                # 返回检测结果到页面中
                return render_template('suricata_check_result.html', output=output)
        if 'detect' in request.form:
            message = "即将运行 Detect 检查，请稍后"
            script = '''
                setTimeout(function() {{
                    window.location.href = "/run_detect?rule_path={}&pcap_path={}";
                }}, 2000);
            '''.format(selected_rule_path, selected_pcap_path)
            return render_template('intermediate.html', message=message, script=script,
                                   rule_path=selected_rule_path, pcap_path=selected_pcap_path)

    # 渲染文件选择页面，展示可用的规则和PCAP文件
    return render_template('suricata_check.html', rule_files=rule_files, pcap_files=pcap_files,
                           previous_page='generate_pcap.generate',)


@suricata_check.route('/load_rules_content')
def load_rules_content():
    """
    加载指定的规则文件内容并返回。

    :return: 成功时返回文件内容（str），失败时返回错误信息和HTTP状态码。
    :raises FileNotFoundError: 如果指定文件不存在。
    """
    file_name = request.args.get('file')
    # 防止路径遍历攻击
    research = re.search(r'(\x2e{1,}\x3b{0,}[\x5c\x2f]+){1,}', file_name)
    if research:
        return "别乱搞啊", 400
    if file_name:
        file_path = os.path.join(rule_files_dir, file_name)
        if not os.path.exists(file_path):
            return "文件不存在", 404
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            return f"Error loading file: 错误不给你看了还是", 500
    return "No file specified", 400
