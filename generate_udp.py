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

from utils import (
    parse_templates, download_file, PCAP_DIR, inc_gen_count, unique_stamp,
    _parse_int_field, _parse_ip_field, ensure_dir,
)

logger = logging.getLogger(__name__)

generate_udp = Blueprint('generate_udp', __name__, template_folder='./')


@generate_udp.route('/generate_udp', methods=['GET', 'POST'])
def generate():
    """
    生成 UDP 流量包。

    支持自定义源/目标 IP、端口和负载内容。
    """
    if request.method == 'POST':
        # M-3 防护：所有外部输入经 _parse_*_field 校验后才进入下游。
        src_ip, err = _parse_ip_field(request, 'src_ip', default='192.168.1.1', label='源 IP')
        if err is not None: return err
        dst_ip, err = _parse_ip_field(request, 'dst_ip', default='192.168.1.2', label='目的 IP')
        if err is not None: return err

        src_port, err = _parse_int_field(request, 'src_port', default=12345, lo=1, hi=65535, label='源端口')
        if err is not None: return err
        dst_port, err = _parse_int_field(request, 'dst_port', default=80, lo=1, hi=65535, label='目的端口')
        if err is not None: return err
        req_payload = request.form.get('payload', 'UDP Request')
        res_payload = request.form.get('res_payload', 'UDP Response')

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
            ensure_dir(PCAP_DIR)
        except OSError as e:
            logger.exception("创建目录 %s 失败", PCAP_DIR)
            return f"目录创建失败: {e}", 500

        filename = f"udp_{unique_stamp()}.pcap"
        filepath = os.path.join(PCAP_DIR, filename)
        wrpcap(filepath, packets)

        logger.info("生成 UDP PCAP: %s", filename)
        inc_gen_count("generate_udp")
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
