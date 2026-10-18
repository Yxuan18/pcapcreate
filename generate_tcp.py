# -- coding: utf-8 --
import logging
import os
import time

from flask import Blueprint, render_template, request, redirect, url_for
from scapy.all import wrpcap
from utils import (
    parse_templates, download_file, PCAP_DIR, inc_gen_count, unique_stamp,
    _parse_int_field, _parse_ip_field, ensure_dir,
)
from tcp_utils import build_tcp_session, send_stream, build_tcp_teardown

logger = logging.getLogger(__name__)

generate_tcp = Blueprint('generate_tcp', __name__)


@generate_tcp.route('/generate_tcp', methods=['GET', 'POST'])
def generate():
    if request.method == 'POST':
        # M-3 防护：把"取值 + 类型 + 范围"集中到 _parse_*_field。
        # 之前 int(request.form.get(...)) 让 'abc' / '70000' / 'not-an-ip'
        # 全部抛 ValueError/TypeError/gaierror，被 Flask 转 500。
        src_ip, err = _parse_ip_field(request, 'src_ip', default='192.168.1.1', label='源 IP')
        if err is not None: return err
        # dst_ip 是必填项，default=None 让 _parse_ip_field 在用户没填时返回 400
        dst_ip, err = _parse_ip_field(request, 'dst_ip', default=None, label='目的 IP')
        if err is not None: return err

        src_port, err = _parse_int_field(request, 'src_port', default=12345, lo=1, hi=65535, label='源端口')
        if err is not None: return err
        dst_port, err = _parse_int_field(request, 'dst_port', default=80, lo=1, hi=65535, label='目的端口')
        if err is not None: return err

        payload_str = request.form.get('payload', '')
        res_payload_str = request.form.get('res_payload', '')

        # 解析载荷模板（返回 bytes，模板原始字节与 UTF-8 文本直接拼接）
        payload = parse_templates(payload_str)
        res_payload = parse_templates(res_payload_str)

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
            ensure_dir(PCAP_DIR)
        except OSError as e:
            logger.exception("创建目录 %s 失败: %s", PCAP_DIR, e)

        # L 系列：filename 加 8 位 hex 后缀，杜绝同秒内并发同名覆盖。
        filename = f"tcp_{unique_stamp()}.pcap"
        filepath = os.path.join(PCAP_DIR, filename)
        wrpcap(filepath, pkts)
        inc_gen_count("generate_tcp")
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
