# -- coding: utf-8 --
# TCP 通用工具函数，供 generate_tcp.py 和 generate_smtp.py 共用

import random
import logging

from scapy.all import Ether, IP, TCP, Raw

logger = logging.getLogger(__name__)

# 默认 MAC 地址
DEFAULT_CLIENT_MAC = "c0:25:a5:80:a4:79"
DEFAULT_SERVER_MAC = "c0:26:a5:80:a4:79"


def build_tcp_pkt(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str,
                   src_port: int, dst_port: int, flags: str,
                   seq: int, ack: int, payload: bytes = b"") -> Ether:
    """
    构建单个 TCP 数据包。

    :param src_mac: 源 MAC 地址
    :param dst_mac: 目标 MAC 地址
    :param src_ip: 源 IP 地址
    :param dst_ip: 目标 IP 地址
    :param src_port: 源端口
    :param dst_port: 目标端口
    :param flags: TCP 标志位（如 'S', 'SA', 'A', 'PA', 'FA'）
    :param seq: 序列号
    :param ack: 确认号
    :param payload: 负载数据，默认为空
    :return: 构建好的 Ether 数据包
    """
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, flags=flags, seq=seq, ack=ack)
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def send_stream(pkts: list, src_mac: str, dst_mac: str,
                src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                seq: int, ack: int, payload: bytes) -> tuple:
    """
    发送一段 TCP 应用层数据，并自动补对端 ACK。
    返回新的 seq 和 ack 值。

    :param pkts: 数据包列表（会被追加）
    :param src_mac: 源 MAC 地址
    :param dst_mac: 目标 MAC 地址
    :param src_ip: 源 IP 地址
    :param dst_ip: 目标 IP 地址
    :param src_port: 源端口
    :param dst_port: 目标端口
    :param seq: 当前序列号
    :param ack: 当前确认号
    :param payload: 要发送的数据
    :return: (new_seq, new_ack) 元组
    """
    if not payload:
        return seq, ack

    data_pkt = build_tcp_pkt(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        "PA", seq, ack, payload
    )
    pkts.append(data_pkt)
    new_seq = seq + len(payload)

    ack_pkt = build_tcp_pkt(
        dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port,
        "A", ack, new_seq
    )
    pkts.append(ack_pkt)

    return new_seq, ack


def build_tcp_session(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                       client_mac: str = DEFAULT_CLIENT_MAC,
                       server_mac: str = DEFAULT_SERVER_MAC) -> dict:
    """
    构建 TCP 会话基础结构，返回握手数据包和初始序列号。

    :param src_ip: 客户端 IP 地址
    :param dst_ip: 服务端 IP 地址
    :param src_port: 客户端端口
    :param dst_port: 服务端端口
    :param client_mac: 客户端 MAC 地址
    :param server_mac: 服务端 MAC 地址
    :return: dict 包含 pkts, client_seq, server_seq
    """
    pkts = []
    isn_client = random.getrandbits(32)
    isn_server = random.getrandbits(32)

    # TCP 三次握手
    syn = build_tcp_pkt(
        client_mac, server_mac, src_ip, dst_ip, src_port, dst_port,
        "S", isn_client, 0
    )
    pkts.append(syn)

    syn_ack = build_tcp_pkt(
        server_mac, client_mac, dst_ip, src_ip, dst_port, src_port,
        "SA", isn_server, isn_client + 1
    )
    pkts.append(syn_ack)

    ack = build_tcp_pkt(
        client_mac, server_mac, src_ip, dst_ip, src_port, dst_port,
        "A", isn_client + 1, isn_server + 1
    )
    pkts.append(ack)

    return {
        "pkts": pkts,
        "client_seq": isn_client + 1,
        "server_seq": isn_server + 1,
        "client_mac": client_mac,
        "server_mac": server_mac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def build_tcp_teardown(pkts: list, session: dict) -> None:
    """
    向已有数据包列表追加 TCP 四次挥手。

    :param pkts: 数据包列表（会被追加）
    :param session: build_tcp_session 返回的会话字典
    """
    client_seq = session["client_seq"]
    server_seq = session["server_seq"]

    # 客户端发起 FIN
    fin_client = build_tcp_pkt(
        session["client_mac"], session["server_mac"],
        session["src_ip"], session["dst_ip"],
        session["src_port"], session["dst_port"],
        "FA", client_seq, server_seq
    )
    pkts.append(fin_client)
    client_seq += 1

    # 服务端 ACK
    ack_fin_client = build_tcp_pkt(
        session["server_mac"], session["client_mac"],
        session["dst_ip"], session["src_ip"],
        session["dst_port"], session["src_port"],
        "A", server_seq, client_seq
    )
    pkts.append(ack_fin_client)

    # 服务端 FIN
    fin_server = build_tcp_pkt(
        session["server_mac"], session["client_mac"],
        session["dst_ip"], session["src_ip"],
        session["dst_port"], session["src_port"],
        "FA", server_seq, client_seq
    )
    pkts.append(fin_server)
    server_seq += 1

    # 客户端 ACK
    ack_fin_server = build_tcp_pkt(
        session["client_mac"], session["server_mac"],
        session["src_ip"], session["dst_ip"],
        session["src_port"], session["dst_port"],
        "A", client_seq, server_seq
    )
    pkts.append(ack_fin_server)
