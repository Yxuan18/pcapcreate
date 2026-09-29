# -- coding: utf-8 --
"""
ICMP PCAP 生成模块
提供 ICMP 流量包生成功能，支持 Request/Reply 交互。
"""

import logging
import os
import random
import time

from flask import Blueprint, render_template, request, redirect, url_for
from scapy.all import Ether, IP, ICMP, Raw, wrpcap

from utils import parse_templates, download_file, PCAP_DIR

logger = logging.getLogger(__name__)

generate_icmp = Blueprint('generate_icmp', __name__, template_folder='./')


@generate_icmp.route('/generate_icmp', methods=['GET', 'POST'])
def generate():
    """
    生成 ICMP 流量包。

    支持自定义 ICMP 类型、代码和负载内容。
    """
    if request.method == 'POST':
        src_ip = request.form.get('src_ip', '192.168.1.1')
        dst_ip = request.form.get('dst_ip', '192.168.1.2')
        icmp_type = int(request.form.get('icmp_type', 8))
        icmp_code = int(request.form.get('icmp_code', 0))
        icmp_id = int(request.form.get('icmp_id', random.randint(1000, 65535)))
        icmp_seq = int(request.form.get('icmp_seq', random.randint(1, 1000)))
        req_payload = request.form.get('payload', 'Hello ICMP Request')
        res_payload = request.form.get('res_payload', 'Hello ICMP Reply')

        if not dst_ip:
            return "目的 IP 不能为空", 400

        req_payload = parse_templates(content=req_payload)
        res_payload = parse_templates(content=res_payload)

        src_mac = "c0:25:a5:80:a4:79"
        dst_mac = "c0:26:a5:80:a4:79"

        packets = []

        # Echo Request
        req_pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / ICMP(type=icmp_type, code=icmp_code, id=icmp_id, seq=icmp_seq)
            / Raw(load=req_payload.encode('latin-1') if isinstance(req_payload, str) else req_payload)
        )
        packets.append(req_pkt)

        # Echo Reply：交换地址对并设为 Type 0，使 Wireshark/Suricata 能区分
        res_pkt = (
            Ether(src=dst_mac, dst=src_mac)
            / IP(src=dst_ip, dst=src_ip)
            / ICMP(type=0, code=0, id=icmp_id, seq=icmp_seq)
            / Raw(load=res_payload.encode('latin-1') if isinstance(res_payload, str) else res_payload)
        )
        packets.append(res_pkt)

        try:
            os.makedirs(PCAP_DIR, exist_ok=True)
        except OSError as e:
            logger.exception("创建目录 %s 失败", PCAP_DIR)
            return f"目录创建失败: {e}", 500

        filename = f"icmp_{int(time.time())}.pcap"
        filepath = os.path.join(PCAP_DIR, filename)
        wrpcap(filepath, packets)

        logger.info("生成 ICMP PCAP: %s", filename)
        return redirect(url_for('generate_icmp.download_icmp_file', filename=filename))

    return render_template(
        'generate_icmp.html',
        previous_page='generate_udp.generate',
        next_page='generate_tcp.generate'
    )


@generate_icmp.route('/download_icmp/<path:filename>')
def download_icmp_file(filename):
    """下载 ICMP PCAP 文件。"""
    safe_filename = os.path.basename(filename)
    if safe_filename != filename:
        logger.warning("路径遍历尝试: %s", filename)
        return "非法文件名", 400
    return download_file(PCAP_DIR, safe_filename)
