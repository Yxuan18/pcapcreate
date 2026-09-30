# -- coding: utf-8 -- 
# Name: pcaps_create.py
# Where:


import os
import math
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from scapy.all import *
from scapy.utils import wrpcap
from scapy.layers.inet import IP, TCP, Ether
import os
import random
import re

from utils import PCAP_DIR


def _to_bytes(payload) -> bytes:
    """载荷统一转 bytes（str 按 UTF-8 编码），长度计算才和线上字节一致。"""
    if isinstance(payload, str):
        return payload.encode('utf-8')
    return payload


def fix_content_length(request_body):
    """
    修正HTTP请求内容的Content-Length头部值。

    如果请求方法不是GET且Content-Length字段不存在，将自动添加此字段并设置为请求体的长度。

    :param request_body: 原始HTTP请求内容（str 或 bytes）
    :return: 修正Content-Length头部后的HTTP请求内容（bytes）
    """
    request_body = _to_bytes(request_body)

    # 处理GET请求中的空格问题
    if request_body.startswith(b'GET'):
        # 正则表达式匹配GET后的所有字符直到HTTP/，替换其中的空格为+
        request_body = re.sub(rb'GET ([^\r\n]*?) HTTP/',
                              lambda m: b'GET ' + m.group(1).replace(b' ', b'+') + b' HTTP/',
                              request_body)

    # 尝试分割请求头和请求体（支持 \r\n\r\n 或 \n\n 两种格式）
    # 先尝试 \r\n\r\n，再尝试 \n\n
    header, _, body = request_body.partition(b'\r\n\r\n')

    # 检查是否已存在Content-Length字段
    content_length_match = re.search(rb'Content-Length: (\d+)', header, re.IGNORECASE)

    # 如果存在，则更新长度，否则添加字段
    if content_length_match:
        expected_length = int(content_length_match.group(1))
        # Content-Length 是字节长度，中文按 UTF-8 编码后字符数 != 字节数
        actual_length = len(body)
        if actual_length != expected_length:
            # 更新Content-Length字段
            header = re.sub(rb'Content-Length: \d+', b'Content-Length: %d' % actual_length,
                            header, flags=re.IGNORECASE)
    else:
        # 对于非GET请求，添加Content-Length字段
        if not header.startswith(b'GET'):
            actual_length = len(body)
            header += b'\r\nContent-Length: %d' % actual_length

    # 重新组装请求头和请求体
    updated_request_body = header + b'\r\n\r\n' + body

    return updated_request_body


def fix_response_content_length(response_body):
    """
    修正HTTP响应的Content-Length头部值。

    如果响应中存在Content-Length字段，将根据响应体的长度自动更新该字段。
    如果Content-Length字段不存在，将自动添加该字段并设置为响应体的长度。

    :param response_body: 原始HTTP响应内容（str 或 bytes）
    :return: 修正Content-Length头部后的HTTP响应内容（bytes）
    """
    response_body = _to_bytes(response_body)

    # 确保是HTTP响应
    if not response_body.startswith(b'HTTP/'):
        raise ValueError("Invalid HTTP response format")

    # 尝试分割响应头和响应体（支持 \r\n\r\n 或 \n\n 两种格式）
    header, _, body = response_body.partition(b'\r\n\r\n')

    # 检查是否已存在Content-Length字段
    content_length_match = re.search(rb'Content-Length: (\d+)', header, re.IGNORECASE)

    # 计算实际响应体长度（字节）
    actual_length = len(body)

    # 如果存在，则更新长度，否则添加字段
    if content_length_match:
        expected_length = int(content_length_match.group(1))
        if actual_length != expected_length:
            # 更新Content-Length字段
            header = re.sub(rb'Content-Length: \d+', b'Content-Length: %d' % actual_length,
                            header, flags=re.IGNORECASE)
    else:
        # 添加Content-Length字段
        header += b'\r\nContent-Length: %d' % actual_length

    # 重新组装响应头和响应体
    updated_response_body = header + b'\r\n\r\n' + body

    return updated_response_body


def creat_http_pcap(request_str, response_str, pcapname=''):
    """
    创建一个模拟HTTP请求和响应的PCAP文件。
    这个函数可以用，而且可以用 Detect 校验

    :param request_str: HTTP请求内容（str 按 UTF-8 编码，或 bytes）
    :param response_str: HTTP响应内容（str 按 UTF-8 编码，或 bytes）
    :param pcapname: 生成的PCAP文件名称
    """
    request_bytes = _to_bytes(request_str)
    response_bytes = _to_bytes(response_str)

    dst_port = 8000
    src_mac = "c0:25:a5:80:a4:79"
    dst_mac = "c0:26:a5:80:a4:79"
    src_ip = "192.168.0.1"
    dst_ip = "192.168.0.2"

    ipsrc = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip)
    ipdst = Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip)

    seq = random.randint(10, 5000)
    seq2 = random.randint(10, 5000)
    src_port = random.randint(20000, 50000)

    syn_packet = ipsrc / TCP(sport=src_port, dport=dst_port, seq=seq, flags="S")

    syn_ack_packet = ipdst / TCP(sport=dst_port, dport=src_port, flags="SA", seq=seq2, ack=syn_packet[TCP].seq + 1)

    ack_packet = ipsrc / TCP(sport=src_port, dport=dst_port, flags="A", seq=syn_ack_packet[TCP].ack,
                             ack=syn_ack_packet[TCP].seq + 1)

    http_request_packet = ipsrc / TCP(sport=src_port, dport=dst_port, flags=24, seq=ack_packet[TCP].seq,
                                      ack=syn_ack_packet[TCP].seq + 1) / Raw(load=request_bytes)

    httpack = ipdst / TCP(sport=dst_port, dport=src_port, seq=http_request_packet[TCP].ack,
                          # TCP 序列号按字节推进，中文 UTF-8 编码后字符数 != 字节数
                          ack=http_request_packet[TCP].seq + len(request_bytes), flags='A')

    http_response_packet = ipdst / TCP(sport=dst_port, dport=src_port, flags=24, seq=httpack[TCP].seq,
                                       ack=httpack[TCP].ack) / Raw(load=response_bytes)

    fin_packet = ipsrc / TCP(sport=src_port, dport=dst_port, flags="FA", seq=http_response_packet[TCP].ack,
                             ack=http_response_packet[TCP].seq + len(response_bytes))

    ack_packet_close = ipdst / TCP(sport=dst_port, dport=src_port, flags="A", seq=fin_packet[TCP].ack,
                                   ack=fin_packet[TCP].seq + 1)

    ack_packet_close2 = ipdst / TCP(sport=dst_port, dport=src_port, flags="FA", seq=ack_packet_close[TCP].seq,
                                    ack=fin_packet[TCP].seq + 1)

    fin_packet_ack = ipsrc / TCP(sport=src_port, dport=dst_port, flags="A", seq=ack_packet_close2[TCP].ack,
                                 ack=ack_packet_close2[TCP].seq + 1)

    http_traffic = [syn_packet, syn_ack_packet, ack_packet, http_request_packet, httpack, http_response_packet,
                    fin_packet, ack_packet_close, ack_packet_close2, fin_packet_ack]
    # 与 download 共用 utils.PCAP_DIR，下载端点才能找到生成的文件。
    # 不能 str(Path(.../ 'pcapss/')) 再字符串拼接——pathlib 会去掉尾斜杠，
    # 'pcapss' + name 拼出 'pcapssXXX.pcap' 落在上级目录。
    os.makedirs(PCAP_DIR, exist_ok=True)
    file_paths = os.path.join(PCAP_DIR, f'{pcapname}.pcap')

    wrpcap(file_paths, http_traffic)
    return file_paths


@dataclass
class PcapNetworkConfig:
    """网络参数配置，集中管理、一处修改。"""
    src_mac: str = "c0:25:a5:80:a4:79"
    dst_mac: str = "c0:26:a5:80:a4:79"
    src_ip: str = "192.168.0.1"
    dst_ip: str = "192.168.0.2"
    src_port: int = 0          # 0 表示随机
    dst_port: int = 8000
    mss: int = 1460            # 最大分段大小（以太网典型值）
    output_dir: str = ""       # 为空时取脚本同级 pcapss/


    def __post_init__(self):
        if self.src_port == 0:
            self.src_port = random.randint(20000, 50000)
        if not self.output_dir:
            # 与 creat_http_pcap / download 共用 utils.PCAP_DIR
            self.output_dir = PCAP_DIR







def creat_http_pcap_new(request_str: str,response_str: str,pcapname: str,config: Optional[PcapNetworkConfig] = None,) -> str:
    """
    创建一个【协议完整、设备友好】的 HTTP PCAP 文件。


    **关键特性**：
      - TCP 三次握手 + 四次挥手，状态机完整
      - 超长 payload 自动按 MSS 分段，兼容硬件设备
      - seq / ack 全程用变量维护，严格正确


    :param request_str:  HTTP 请求原始文本
    :param response_str: HTTP 响应原始文本
    :param pcapname:     输出文件名（不含扩展名）
    :param config:       网络配置，为 None 时使用默认值
    :return:             生成的 pcap 文件绝对路径
    """


    # ── 0. 参数校验 ──
    if not request_str or not response_str:
        raise ValueError("request_str 和 response_str 均不能为空")
    if not pcapname or not pcapname.strip():
        raise ValueError("pcapname 不能为空")


    cfg = config or PcapNetworkConfig()


    # ── 1. 准备以太网 / IP 模板 ──
    ether_c2s = Ether(src=cfg.src_mac, dst=cfg.dst_mac)
    ether_s2c = Ether(src=cfg.dst_mac, dst=cfg.src_mac)
    ip_c2s = IP(src=cfg.src_ip, dst=cfg.dst_ip)
    ip_s2c = IP(src=cfg.dst_ip, dst=cfg.src_ip)


    # ── 2. 初始化序列号 ──
    seq_c: int = random.randint(1000, 50000)   # 客户端 ISN
    seq_s: int = random.randint(1000, 50000)   # 服务端 ISN


    packets: List[Packet] = []


    # ────────────────────────────────
    #  辅助：构造单个 TCP 包
    # ────────────────────────────────
    def _tcp_pkt(ether, ip, sport, dport, flags, seq, ack, payload: bytes = b"") -> Packet:
        pkt = ether / ip / TCP(sport=sport, dport=dport,flags=flags, seq=seq, ack=ack,)
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt


    # ────────────────────────────────
    #  辅助：将 payload 按 MSS 分段发送
    #  返回发送方新的 seq
    # ────────────────────────────────
    def _send_segments(ether, ip, sport, dport,ether_r, ip_r,sender_seq: int,receiver_seq: int,payload: bytes,) -> tuple:
        """
        将 payload 切片后逐段发送，并为每段生成对端 ACK。
        :return: (更新后的 sender_seq, receiver_seq)
        """
        mss = cfg.mss
        total = len(payload)
        seg_count = math.ceil(total / mss) if total > 0 else 1


        for i in range(seg_count):
            chunk = payload[i * mss : (i + 1) * mss]
            is_last = (i == seg_count - 1)


            # PSH+ACK 仅在最后一个分段上设置 PSH
            flags = "PA" if is_last else "A"


            seg = _tcp_pkt(
                ether, ip, sport, dport,
                flags=flags,
                seq=sender_seq,
                ack=receiver_seq,
                payload=chunk,
            )
            packets.append(seg)
            sender_seq += len(chunk)


            # 对端回 ACK（每段都回，保持状态机简洁）
            ack_pkt = _tcp_pkt(
                ether_r, ip_r, dport, sport,
                flags="A",
                seq=receiver_seq,
                ack=sender_seq,
            )
            packets.append(ack_pkt)


        return sender_seq, receiver_seq


    # ── 3. TCP 三次握手 ──
    packets.append(_tcp_pkt(
        ether_c2s, ip_c2s, cfg.src_port, cfg.dst_port,
        flags="S", seq=seq_c, ack=0,
    ))
    seq_c += 1  # SYN 消耗 1 个序列号


    packets.append(_tcp_pkt(
        ether_s2c, ip_s2c, cfg.dst_port, cfg.src_port,
        flags="SA", seq=seq_s, ack=seq_c,
    ))
    seq_s += 1  # SYN-ACK 消耗 1 个序列号


    packets.append(_tcp_pkt(
        ether_c2s, ip_c2s, cfg.src_port, cfg.dst_port,
        flags="A", seq=seq_c, ack=seq_s,
    ))


    # ── 4. HTTP 请求（客户端 → 服务端） ──
    request_bytes = request_str.encode("utf-8")
    seq_c, seq_s = _send_segments(
        ether_c2s, ip_c2s, cfg.src_port, cfg.dst_port,
        ether_s2c, ip_s2c,
        sender_seq=seq_c,
        receiver_seq=seq_s,
        payload=request_bytes,
    )


    # ── 5. HTTP 响应（服务端 → 客户端） ──
    response_bytes = response_str.encode("utf-8")
    seq_s, seq_c = _send_segments(
        ether_s2c, ip_s2c, cfg.dst_port, cfg.src_port,
        ether_c2s, ip_c2s,
        sender_seq=seq_s,
        receiver_seq=seq_c,
        payload=response_bytes,
    )


    # ── 6. TCP 四次挥手 ──
    # 客户端 FIN
    packets.append(_tcp_pkt(
        ether_c2s, ip_c2s, cfg.src_port, cfg.dst_port,
        flags="FA", seq=seq_c, ack=seq_s,
    ))
    seq_c += 1  # FIN 消耗 1 个序列号


    # 服务端 FIN+ACK（合并）
    packets.append(_tcp_pkt(
        ether_s2c, ip_s2c, cfg.dst_port, cfg.src_port,
        flags="FA", seq=seq_s, ack=seq_c,
    ))
    seq_s += 1


    # 客户端 LAST-ACK
    packets.append(_tcp_pkt(
        ether_c2s, ip_c2s, cfg.src_port, cfg.dst_port,
        flags="A", seq=seq_c, ack=seq_s,
    ))


    # ── 7. 写文件 ──
    os.makedirs(cfg.output_dir, exist_ok=True)
    filepath = os.path.join(cfg.output_dir, f"{pcapname}.pcap")
    wrpcap(filepath, packets)


    return filepath


