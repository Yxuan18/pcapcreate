# -- coding: utf-8 --
"""
PCAP 生成模块
提供 HTTP 请求/响应模板选择和自定义 PCAP 文件生成功能。
"""

import logging
import os

from flask import Blueprint, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

from http_requests import standard_get, ordinary_post, form_submission
from http_responses import http_response_200, http_response_302, http_response_404, http_response_502
from payload_expand import (
    expand_payload, expand_request, expand_response, is_complete_request,
    split_request_response,
)
from pcaps_create import creat_http_pcap, fix_content_length, fix_response_content_length
from utils import parse_templates, download_file, PCAP_DIR, inc_gen_count, unique_stamp, unique_path

logger = logging.getLogger(__name__)

generate_pcap = Blueprint('generate_pcap', __name__, template_folder='./')

# 响应体留空时使用的默认 HTTP 响应。按需修改此处即可。
# 刻意不写 Content-Length：fix_response_content_length 会按实际字节补全，
# 改 body 时不必手动同步长度。
DEFAULT_RESPONSE_BODY = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<html><body>OK</body></html>"
)

# 生成时是否自动把简要 payload 补成完整报文。前端失焦补全只负责预览，
# 真正的保证在这里；需要逐字节原样发送时置 false 关闭。
_AUTO_EXPAND_ENABLED = os.getenv(
    "WEB_APPS_PAYLOAD_AUTO_EXPAND", "true"
).lower() in ("true", "1", "yes")


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

            # 请求框里可能粘着"请求 + 响应"连体（抓包、WAF 日志常见）。
            # 拆出来的响应只在用户没填响应框时顶上去——用户明确填了响应，
            # 拆出的那段就无处安放，这时不拆（整体当请求体），至少不丢内容。
            if _AUTO_EXPAND_ENABLED:
                if response_body.strip():
                    request_body = expand_request(request_body)
                else:
                    request_body, split_response = expand_payload(request_body)
                    if split_response:
                        logger.info("请求框中拆出响应片段，用作响应报文")
                        response_body = split_response

            # 响应体为空时用默认合法 HTTP 响应，保证 PCAP 里仍有可解析的
            # HTTP 事务；默认值见文件顶部 DEFAULT_RESPONSE_BODY。
            if not response_body.strip():
                logger.info("响应体为空，使用 DEFAULT_RESPONSE_BODY 生成 PCAP")
                response_body = DEFAULT_RESPONSE_BODY

            # 前端 blur 已就地补全，这里再补一次：两者幂等，且能兜住
            # "补全请求在途时用户就点了生成"这种前端竞态。
            if _AUTO_EXPAND_ENABLED:
                response_body = expand_response(response_body)

            # L 系列：默认文件名改用 unique_stamp（含 8 位 hex 后缀），
            # 杜绝同一分钟/秒内多用户生成重名文件互相覆盖。
            # 自定义文件名走 unique_path 查重——同名自动追加 _1 / _2 ...
            if not file_name:
                file_name = f"{unique_stamp()}.pcap"
            else:
                file_name = unique_path(PCAP_DIR, file_name)
                file_name = os.path.basename(file_name)

            # 解析模板并生成 PCAP
            request_body_rep = parse_templates(content=request_body)
            fixs = fix_content_length(request_body=request_body_rep)

            response_body_rep = parse_templates(content=response_body)
            response_body = fix_response_content_length(response_body_rep)

            file_path = creat_http_pcap(request_str=fixs, response_str=response_body, pcapname=file_name)
            filename = os.path.basename(file_path)

            logger.info("生成 PCAP 文件: %s", filename)
            inc_gen_count("generate_pcap")
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

@generate_pcap.route('/generate_pcap/expand', methods=['POST'])
def expand():
    """
    把简要 payload 扩展为完整 HTTP 报文，供前端按钮就地替换文本框内容。

    两种模式：
    - request：首行可只有路径，缺 Host / Content-Type / Content-Length 时补全。
      粘着响应片段（"GET /x HTTP/1.1" 之后跟 "200" 与响应头体）时拆开：
      请求留在本框，响应放进 split_response 由前端填入响应框。
    - response：可只给状态码，或只给响应体

    首行已是完整请求行的不处理——用户可能刻意构造畸形报文做解析器测试。
    """
    payload = request.form.get('payload', '')
    kind = request.form.get('kind', 'request')
    if kind not in ('request', 'response'):
        return {'error': 'kind 只能是 request 或 response'}, 400

    if not payload.strip():
        return {'error': '内容为空'}, 400

    response_part = ''
    if kind == 'request':
        # 响应框已有内容时，前端无处安放拆出的响应：硬拆等于把那段从页面上
        # 删掉。这时不动请求框，返回 skipped_split 让前端提示用户手动处理。
        if request.form.get('response_filled') == '1' and \
                split_request_response(payload)[1]:
            return {'content': payload, 'changed': False,
                    'split_response': '', 'skipped_split': True}
        expanded, response_part = expand_payload(payload)
        # 没有响应片段、且补全后字节不变：原样返回，不动用户刻意构造的畸形报文。
        # 两个条件都要——连体报文哪怕补全后一字不差，也得拆出响应。
        if not response_part and is_complete_request(payload):
            return {'content': payload, 'changed': False,
                    'split_response': '', 'skipped_split': False}
    else:
        expanded = expand_response(payload)

    # 换行符归一后比较：浏览器把 textarea 的 CRLF 存成 LF，直接比字面量会让
    # 已补全的内容在每次失焦时都被判成"有改动"，反复弹提示。
    changed = expanded.replace('\r\n', '\n') != payload.replace('\r\n', '\n')
    logger.info("扩展 %s payload: %d → %d 字节（changed=%s，拆出响应=%d 字节）",
                kind, len(payload), len(expanded), changed, len(response_part))
    return {'content': expanded, 'changed': changed,
            'split_response': response_part, 'skipped_split': False}


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