# -- coding: utf-8 --
"""
UDP PCAP 生成模块
提供 UDP 流量包生成功能，支持双向交互。
"""

import logging
import os
import time

from flask import Blueprint, render_template, request, redirect, url_for
from scapy.all import Ether, IP, UDP, Raw, wrpcap

from utils import parse_templates, download_file, PCAP_DIR

logger = logging.getLogger(__name__)

generate_udp = Blueprint('generate_udp', __name__, template_folder='./')


@generate_udp.route('/generate_udp', methods=['GET', 'POST'])
def generate():
    """
    生成 UDP 流量包。

    支持自定义源/目标 IP、端口和负载内容。
    """
    if request.method == 'POST':
        src_ip = request.form.get('src_ip', '192.168.1.1')
        dst_ip = request.form.get('dst_ip', '192.168.1.2')
        src_port = int(request.form.get('src_port', 12345))
        dst_port = int(request.form.get('dst_port', 80))
        req_payload = request.form.get('payload', 'UDP Request')
        res_payload = request.form.get('res_payload', 'UDP Response')

        if not dst_ip:
            return "目的 IP 不能为空", 400

        req_payload = parse_templates(content=req_payload)
        res_payload = parse_templates(content=res_payload)

        src_mac = "c0:25:a5:80:a4:79"
        dst_mac = "c0:26:a5:80:a4:79"

        packets = []

        # 请求包
        req_pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=src_port, dport=dst_port)
            / Raw(load=req_payload.encode('latin-1') if isinstance(req_payload, str) else req_payload)
        )
        packets.append(req_pkt)

        # 响应包
        res_pkt = (
            Ether(src=dst_mac, dst=src_mac)
            / IP(src=dst_ip, dst=src_ip)
            / UDP(sport=dst_port, dport=src_port)
            / Raw(load=res_payload.encode('latin-1') if isinstance(res_payload, str) else res_payload)
        )
        packets.append(res_pkt)

        try:
            os.makedirs(PCAP_DIR, exist_ok=True)
        except OSError as e:
            logger.exception("创建目录 %s 失败", PCAP_DIR)
            return f"目录创建失败: {e}", 500

        filename = f"udp_{int(time.time())}.pcap"
        filepath = os.path.join(PCAP_DIR, filename)
        wrpcap(filepath, packets)

        logger.info("生成 UDP PCAP: %s", filename)
        return redirect(url_for('generate_udp.download_udp_file', filename=filename))

    return render_template(
        'generate_udp.html',
        previous_page='generate_pcap.generate',
        next_page='generate_icmp.generate'
    )


@generate_udp.route('/download_udp/<path:filename>')
def download_udp_file(filename):
    """下载 UDP PCAP 文件。"""
    safe_filename = os.path.basename(filename)
    if safe_filename != filename:
        logger.warning("路径遍历尝试: %s", filename)
        return "非法文件名", 400
    return download_file(PCAP_DIR, safe_filename)
