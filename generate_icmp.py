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

from utils import (
    parse_templates, download_file, PCAP_DIR, inc_gen_count, unique_stamp,
    _parse_int_field, _parse_ip_field, ensure_dir,
)

logger = logging.getLogger(__name__)

generate_icmp = Blueprint('generate_icmp', __name__, template_folder='./')


@generate_icmp.route('/generate_icmp', methods=['GET', 'POST'])
def generate():
    """
    生成 ICMP 流量包。

    支持自定义 ICMP 类型、代码和负载内容。
    """
    if request.method == 'POST':
        # M-3 防护：所有外部输入经 _parse_*_field 校验后才进入下游。
        src_ip, err = _parse_ip_field(request, 'src_ip', default='192.168.1.1', label='源 IP')
        if err is not None: return err
        dst_ip, err = _parse_ip_field(request, 'dst_ip', default='192.168.1.2', label='目的 IP')
        if err is not None: return err

        # ICMP type 0-255、code 0-15、id/seq 0-65535
        icmp_type, err = _parse_int_field(request, 'icmp_type', default=8, lo=0, hi=255, label='ICMP type')
        if err is not None: return err
        icmp_code, err = _parse_int_field(request, 'icmp_code', default=0, lo=0, hi=15, label='ICMP code')
        if err is not None: return err
        icmp_id, err = _parse_int_field(request, 'icmp_id', default=1000, lo=0, hi=65535, label='ICMP id')
        if err is not None: return err
        icmp_seq, err = _parse_int_field(request, 'icmp_seq', default=1, lo=0, hi=65535, label='ICMP seq')
        if err is not None: return err
        req_payload = request.form.get('payload', 'Hello ICMP Request')
        res_payload = request.form.get('res_payload', 'Hello ICMP Reply')

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
            ensure_dir(PCAP_DIR)
        except OSError as e:
            logger.exception("创建目录 %s 失败", PCAP_DIR)
            return f"目录创建失败: {e}", 500

        filename = f"icmp_{unique_stamp()}.pcap"
        filepath = os.path.join(PCAP_DIR, filename)
        wrpcap(filepath, packets)

        logger.info("生成 ICMP PCAP: %s", filename)
        inc_gen_count("generate_icmp")
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
