# -- coding: utf-8 --
"""
SMTP PCAP 生成模块
使用 Scapy 构建完整的 SMTP 会话流量。
"""

import logging
import os
import random
import time

from flask import Blueprint, render_template, request, redirect, url_for
from scapy.all import wrpcap
from utils import parse_templates, download_file, PCAP_DIR
from tcp_utils import build_tcp_pkt, send_stream, build_tcp_session, build_tcp_teardown

logger = logging.getLogger(__name__)

generate_smtp = Blueprint('generate_smtp', __name__)


@generate_smtp.route('/generate_smtp', methods=['GET', 'POST'])
def generate_smtp_pcap():
    """
    生成 SMTP 流量的 PCAP 文件。

    请求参数:
        src_ip: 源 IP 地址（默认 192.168.1.100）
        dst_ip: 目的 IP 地址（必填）
        src_port: 源端口（默认随机 20000-60000）
        dst_port: 目的端口（默认 25）
        sender: 发件人邮箱
        recipient: 收件人邮箱
        subject: 邮件主题
        body: 邮件正文
        helo_domain: HELO/EHLO 域名
        mail_hostname: 服务器主机名
    """
    if request.method == 'POST':
        src_ip = request.form.get('src_ip', '192.168.1.100')
        dst_ip = request.form.get('dst_ip')
        src_port = int(request.form.get('src_port', random.randint(20000, 60000)))
        dst_port = int(request.form.get('dst_port', 25))

        sender = request.form.get('sender', 'sender@example.com').strip()
        recipient = request.form.get('recipient', 'recipient@example.com').strip()
        subject = request.form.get('subject', 'Test Mail')
        body = request.form.get('body', 'This is a test SMTP message.')
        helo_domain = request.form.get('helo_domain', 'client.example.com').strip()
        mail_hostname = request.form.get('mail_hostname', 'mail.example.com').strip()

        if not dst_ip:
            return "目的 IP 是必填项", 400

        # 构建 TCP 会话基础结构
        session = build_tcp_session(src_ip, dst_ip, src_port, dst_port)
        pkts = session["pkts"]
        client_seq = session["client_seq"]
        server_seq = session["server_seq"]

        # SMTP 协议交互序列（按 RFC 5321）
        smtp_banner = parse_templates(
            f"220 {mail_hostname} ESMTP Service Ready\r\n"
        )

        ehlo_cmd = parse_templates(
            f"EHLO {helo_domain}\r\n"
        )

        ehlo_resp = parse_templates(
            f"250-{mail_hostname} Hello [{src_ip}]\r\n"
            f"250-PIPELINING\r\n"
            f"250-8BITMIME\r\n"
            f"250-SIZE 10485760\r\n"
            f"250 OK\r\n"
        )

        mail_from_cmd = parse_templates(
            f"MAIL FROM:<{sender}>\r\n"
        )
        mail_from_resp = b"250 2.1.0 Ok\r\n"

        rcpt_to_cmd = parse_templates(
            f"RCPT TO:<{recipient}>\r\n"
        )
        rcpt_to_resp = b"250 2.1.5 Ok\r\n"

        data_cmd = b"DATA\r\n"
        data_resp = b"354 End data with <CR><LF>.<CR><LF>\r\n"

        message_data = parse_templates(
            f"From: <{sender}>\r\n"
            f"To: <{recipient}>\r\n"
            f"Subject: {subject}\r\n"
            f"Date: Tue, 14 Apr 2026 12:00:00 +0800\r\n"
            f"Message-ID: <{int(time.time())}.{random.randint(1000,9999)}@{helo_domain}>\r\n"
            f"MIME-Version: 1.0\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Transfer-Encoding: 8bit\r\n"
            f"\r\n"
            f"{body}\r\n"
            f".\r\n"
        )
        message_resp = b"250 2.0.0 Ok: queued as ABC12345\r\n"

        quit_cmd = b"QUIT\r\n"
        quit_resp = b"221 2.0.0 Bye\r\n"

        # 服务端发送 banner
        server_seq, _ = send_stream(
            pkts,
            session["server_mac"], session["client_mac"],
            session["dst_ip"], session["src_ip"],
            session["dst_port"], session["src_port"],
            server_seq, client_seq, smtp_banner
        )

        # 客户端 EHLO
        client_seq, _ = send_stream(
            pkts,
            session["client_mac"], session["server_mac"],
            session["src_ip"], session["dst_ip"],
            session["src_port"], session["dst_port"],
            client_seq, server_seq, ehlo_cmd
        )

        # 服务端 EHLO 响应
        server_seq, _ = send_stream(
            pkts,
            session["server_mac"], session["client_mac"],
            session["dst_ip"], session["src_ip"],
            session["dst_port"], session["src_port"],
            server_seq, client_seq, ehlo_resp
        )

        # MAIL FROM
        client_seq, _ = send_stream(
            pkts,
            session["client_mac"], session["server_mac"],
            session["src_ip"], session["dst_ip"],
            session["src_port"], session["dst_port"],
            client_seq, server_seq, mail_from_cmd
        )
        server_seq, _ = send_stream(
            pkts,
            session["server_mac"], session["client_mac"],
            session["dst_ip"], session["src_ip"],
            session["dst_port"], session["src_port"],
            server_seq, client_seq, mail_from_resp
        )

        # RCPT TO
        client_seq, _ = send_stream(
            pkts,
            session["client_mac"], session["server_mac"],
            session["src_ip"], session["dst_ip"],
            session["src_port"], session["dst_port"],
            client_seq, server_seq, rcpt_to_cmd
        )
        server_seq, _ = send_stream(
            pkts,
            session["server_mac"], session["client_mac"],
            session["dst_ip"], session["src_ip"],
            session["dst_port"], session["src_port"],
            server_seq, client_seq, rcpt_to_resp
        )

        # DATA 命令
        client_seq, _ = send_stream(
            pkts,
            session["client_mac"], session["server_mac"],
            session["src_ip"], session["dst_ip"],
            session["src_port"], session["dst_port"],
            client_seq, server_seq, data_cmd
        )
        server_seq, _ = send_stream(
            pkts,
            session["server_mac"], session["client_mac"],
            session["dst_ip"], session["src_ip"],
            session["dst_port"], session["src_port"],
            server_seq, client_seq, data_resp
        )

        # 邮件正文
        client_seq, _ = send_stream(
            pkts,
            session["client_mac"], session["server_mac"],
            session["src_ip"], session["dst_ip"],
            session["src_port"], session["dst_port"],
            client_seq, server_seq, message_data
        )
        server_seq, _ = send_stream(
            pkts,
            session["server_mac"], session["client_mac"],
            session["dst_ip"], session["src_ip"],
            session["dst_port"], session["src_port"],
            server_seq, client_seq, message_resp
        )

        # QUIT
        client_seq, _ = send_stream(
            pkts,
            session["client_mac"], session["server_mac"],
            session["src_ip"], session["dst_ip"],
            session["src_port"], session["dst_port"],
            client_seq, server_seq, quit_cmd
        )
        server_seq, _ = send_stream(
            pkts,
            session["server_mac"], session["client_mac"],
            session["dst_ip"], session["src_ip"],
            session["dst_port"], session["src_port"],
            server_seq, client_seq, quit_resp
        )

        # 更新序列号并执行四次挥手
        session["client_seq"] = client_seq
        session["server_seq"] = server_seq
        build_tcp_teardown(pkts, session)

        # 保存 PCAP
        try:
            os.makedirs(PCAP_DIR, exist_ok=True)
        except OSError as e:
            logger.exception("创建目录 %s 失败: %s", PCAP_DIR, e)

        filename = f"smtp_{int(time.time())}.pcap"
        filepath = os.path.join(PCAP_DIR, filename)
        wrpcap(filepath, pkts)

        return redirect(url_for('generate_smtp.download_smtp_file', filename=filename))

    return render_template(
        'generate_smtp.html',
        previous_page='generate_tcp.generate',
        next_page='home'
    )


@generate_smtp.route('/download_smtp/<path:filename>')
def download_smtp_file(filename):
    """
    下载生成的 SMTP PCAP 文件。

    Args:
        filename: 文件名（路径遍历防护：仅允许基本文件名）
    """
    safe_filename = os.path.basename(filename)
    if not safe_filename or safe_filename != filename:
        return "非法文件名", 400
    return download_file(PCAP_DIR, safe_filename)
