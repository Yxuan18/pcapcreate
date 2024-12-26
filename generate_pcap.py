# -- coding: utf-8 -- 
# Name: generate_pcap.py
# Where:
# 作用：提供生成PCAP文件的接口，支持选择HTTP请求和响应模板，并生成可下载的PCAP文件

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, send_from_directory
import os
import time
from pcaps_create import creat_http_pcap, fix_content_length, fix_response_content_length  # 确保此路径正确
from http_requests import standard_get, ordinary_post, form_submission
from http_responses import http_response_200, http_response_302, http_response_404, http_response_502
import surui_de

# 创建一个Blueprint对象，用于注册与PCAP生成相关的路由
generate_pcap = Blueprint('generate_pcap', __name__, template_folder='./')


@generate_pcap.route('/generate_pcap', methods=['GET', 'POST'])
def generate():
    """
    处理PCAP文件生成的请求，支持选择HTTP请求和响应模板，以及自定义HTTP请求和响应内容。

    :return: 渲染后的HTML页面，或在生成PCAP文件后重定向到下载路由。
    """
    template_response = ""  # 用于存放选择的模板响应内容
    request_body = ""  # 用于存放请求体的内容

    if request.method == 'POST':
        # 处理生成操作
        if 'generate' in request.form:
            request_body = request.form.get('request_body', '')
            response_body = request.form.get('response_body', '')
            file_name = request.form.get('file_name', '')

            # 确保生成的文件名安全，去除路径字符
            if '/' in file_name or '../' in file_name:
                file_name = file_name.replace('/','').replace('..', '')

            # 如果未指定文件名，使用当前时间生成文件名
            if file_name == '':
                file_name = time.strftime('%H-%M', time.localtime(time.time()))

            # 调整Content-Length并生成PCAP文件
            fixs = fix_content_length(request_body=request_body)
            response_body = fix_response_content_length(response_body)
            file_path = creat_http_pcap(request_str=fixs, response_str=response_body, pcapname=file_name)
            # 提取文件名，假设file_path是完整的文件路径,并重定向到下载路由
            filename = os.path.basename(file_path)
            return redirect(url_for('generate_pcap.download_file', filename=filename))

    # 渲染生成PCAP页面，提供选择模板和生成文件的接口
    return render_template('generate_pcap.html', template_response=template_response,
                               request_body_content=request_body, previous_page='home', next_page='suricata_check.check',
                           )


@generate_pcap.route('/generate_pcap/template')
def template():
    """
    根据模板名称返回相应的HTTP请求模板内容。

    :return: 返回HTTP请求模板内容，或404错误如果模板不存在。
    """
    template_type = request.args.get('type')  # 获取模板类型（request 或 response）
    template_name = request.args.get('name')  # 获取模板名称
    if template_type == 'request':
        if template_name == "标准GET":
            return standard_get()
        elif template_name == "普通POST":
            return ordinary_post()
        elif template_name == "FORM提交":
            return form_submission()
        else:
            return "模板不存在", 404
    # Handle response templates
    elif template_type == 'response':
        if template_name == "模板200":
            return http_response_200()
        elif template_name == "模板302":
            return http_response_302()
        elif template_name == "模板404":
            return http_response_404()
        elif template_name == "模板502":
            return http_response_502()
        else:
            return "响应模板不存在", 404

    # Return error if neither request nor response template type is specified
    return "模板类型无效", 400

@generate_pcap.route('/download/<filename>')
def download_file(filename):
    """
    提供生成的PCAP文件的下载功能。

    :param filename: 要下载的PCAP文件名 (str)
    :return: 响应对象，下载指定的PCAP文件。
    """
    # 假设所有生成的 .pcap 文件都保存在 'generated_pcaps' 目录中
    directory = surui_de.webs_path.get('pcap')

    return send_from_directory(directory, filename, as_attachment=True)