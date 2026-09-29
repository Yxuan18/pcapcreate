# -- coding: utf-8 --
"""
PCAP 生成模块
提供 HTTP 请求/响应模板选择和自定义 PCAP 文件生成功能。
"""

import logging
import os
import time

from flask import Blueprint, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

from http_requests import standard_get, ordinary_post, form_submission
from http_responses import http_response_200, http_response_302, http_response_404, http_response_502
from pcaps_create import creat_http_pcap, fix_content_length, fix_response_content_length
from utils import parse_templates, download_file, PCAP_DIR

logger = logging.getLogger(__name__)

generate_pcap = Blueprint('generate_pcap', __name__, template_folder='./')


@generate_pcap.route('/generate_pcap', methods=['GET', 'POST'])
def generate():
    """
    处理 PCAP 文件生成请求。

    支持选择 HTTP 请求和响应模板，以及自定义内容。
    """
    template_response = ""
    request_body = ""

    if request.method == 'POST':
        if 'generate' in request.form:
            request_body = request.form.get('request_body', '')
            response_body = request.form.get('response_body', '')
            file_name = secure_filename(request.form.get('file_name', ''))

            # 未指定文件名时使用时间戳
            if not file_name:
                file_name = time.strftime('%H-%M', time.localtime(time.time()))

            # 解析模板并生成 PCAP
            request_body_rep = parse_templates(content=request_body)
            fixs = fix_content_length(request_body=request_body_rep)

            response_body_rep = parse_templates(content=response_body)
            response_body = fix_response_content_length(response_body_rep)

            file_path = creat_http_pcap(request_str=fixs, response_str=response_body, pcapname=file_name)
            filename = os.path.basename(file_path)

            logger.info("生成 PCAP 文件: %s", filename)
            return redirect(url_for('generate_pcap.download_pcap_file', filename=filename))

    return render_template(
        'generate_pcap.html',
        template_response=template_response,
        request_body_content=request_body,
        previous_page='detect_check.check',
        next_page='generate_udp.generate'
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

@generate_pcap.route('/download/<path:filename>')
def download_pcap_file(filename):
    """
    提供生成的PCAP文件的下载功能。

    :param filename: 要下载的PCAP文件名 (str)
    :return: 响应对象，下载指定的PCAP文件。
    """
    # 防止路径遍历攻击
    safe_filename = os.path.basename(filename)
    if not safe_filename or safe_filename != filename:
        return "非法文件名", 400
    # directory = surui_de.webs_path.get('pcap')
    return download_file(PCAP_DIR, safe_filename)