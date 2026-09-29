# -- coding: utf-8 --
import logging
import os
import time

from flask import Blueprint, render_template, request, redirect, url_for
from scapy.all import wrpcap
from utils import parse_templates, download_file, PCAP_DIR
from tcp_utils import build_tcp_session, send_stream, build_tcp_teardown

logger = logging.getLogger(__name__)

generate_tcp = Blueprint('generate_tcp', __name__)


@generate_tcp.route('/generate_tcp', methods=['GET', 'POST'])
def generate():
    if request.method == 'POST':
        src_ip = request.form.get('src_ip', '192.168.1.1')
        dst_ip = request.form.get('dst_ip')
        src_port = int(request.form.get('src_port', 12345))
        dst_port = int(request.form.get('dst_port', 80))
        payload_str = request.form.get('payload', '')
        res_payload_str = request.form.get('res_payload', '')

        if not dst_ip:
            return "目的 IP 是必填项", 400

        # 解析载荷模板
        payload = parse_templates(payload_str).encode('latin-1')
        res_payload = parse_templates(res_payload_str).encode('latin-1')

        # 构建 TCP 会话基础结构
        session = build_tcp_session(src_ip, dst_ip, src_port, dst_port)
        pkts = session["pkts"]
        client_seq = session["client_seq"]
        server_seq = session["server_seq"]

        # 数据传输
        if payload:
            client_seq, server_seq = send_stream(
                pkts,
                session["client_mac"], session["server_mac"],
                session["src_ip"], session["dst_ip"],
                session["src_port"], session["dst_port"],
                client_seq, server_seq, payload
            )

        if res_payload:
            server_seq, client_seq = send_stream(
                pkts,
                session["server_mac"], session["client_mac"],
                session["dst_ip"], session["src_ip"],
                session["dst_port"], session["src_port"],
                server_seq, client_seq, res_payload
            )

        # 更新会话序列号
        session["client_seq"] = client_seq
        session["server_seq"] = server_seq

        # TCP 四次挥手
        build_tcp_teardown(pkts, session)

        # 保存文件
        try:
            os.makedirs(PCAP_DIR, exist_ok=True)
        except OSError as e:
            logger.exception("创建目录 %s 失败: %s", PCAP_DIR, e)

        filename = f"tcp_{int(time.time())}.pcap"
        filepath = os.path.join(PCAP_DIR, filename)
        wrpcap(filepath, pkts)

        return redirect(url_for('generate_tcp.download_tcp_file', filename=filename))

    return render_template(
        'generate_tcp.html',
        previous_page='generate_icmp.generate',
        next_page='generate_smtp.generate_smtp_pcap'
    )


@generate_tcp.route('/download_tcp/<path:filename>')
def download_tcp_file(filename):
    # 防止路径遍历攻击
    safe_filename = os.path.basename(filename)
    if not safe_filename or safe_filename != filename:
        return "非法文件名", 400
    return download_file(PCAP_DIR, safe_filename)
