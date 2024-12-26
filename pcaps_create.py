# -- coding: utf-8 -- 
# Name: pcaps_create.py
# Where:

from scapy.all import *
from scapy.utils import wrpcap
from scapy.layers.inet import IP, TCP, Ether
import re


def fix_content_length(request_body: str):
    """
    修正HTTP请求内容的Content-Length头部值。

    如果请求方法不是GET且Content-Length字段不存在，将自动添加此字段并设置为请求体的长度。

    :param request_body: 原始HTTP请求内容字符串
    :return: 修正Content-Length头部后的HTTP请求内容字符串
    """
    # 处理GET请求中的空格问题
    if request_body.startswith('GET'):
        # 正则表达式匹配GET后的所有字符直到HTTP/，替换其中的空格为+
        request_body = re.sub(r'GET ([^\r\n]*?) HTTP/', lambda m: 'GET ' + m.group(1).replace(' ', '+') + ' HTTP/', request_body)

    # 尝试分割请求头和请求体
    header, _, body = request_body.partition('\r\n\r\n')

    # 检查是否已存在Content-Length字段
    content_length_match = re.search(r'Content-Length: (\d+)', header, re.IGNORECASE)

    # 如果存在，则更新长度，否则添加字段
    if content_length_match:
        expected_length = int(content_length_match.group(1))
        actual_length = len(body)
        if actual_length != expected_length:
            # 更新Content-Length字段
            header = re.sub(r'Content-Length: \d+', f'Content-Length: {actual_length}', header, flags=re.IGNORECASE)
    else:
        # 对于非GET请求，添加Content-Length字段
        if not header.startswith('GET'):
            actual_length = len(body)
            header += f'\r\nContent-Length: {actual_length}'

    # 重新组装请求头和请求体
    updated_request_body = header + '\r\n\r\n' + body

    return updated_request_body


def fix_response_content_length(response_body: str):
    """
    修正HTTP响应的Content-Length头部值。

    如果响应中存在Content-Length字段，将根据响应体的长度自动更新该字段。
    如果Content-Length字段不存在，将自动添加该字段并设置为响应体的长度。

    :param response_body: 原始HTTP响应内容字符串
    :return: 修正Content-Length头部后的HTTP响应内容字符串
    """
    # 确保是HTTP响应
    if not response_body.startswith('HTTP/'):
        raise ValueError("Invalid HTTP response format")

    # 尝试分割响应头和响应体
    header, _, body = response_body.partition('\r\n\r\n')

    # 检查是否已存在Content-Length字段
    content_length_match = re.search(r'Content-Length: (\d+)', header, re.IGNORECASE)

    # 计算实际响应体长度
    actual_length = len(body)

    # 如果存在，则更新长度，否则添加字段
    if content_length_match:
        expected_length = int(content_length_match.group(1))
        if actual_length != expected_length:
            # 更新Content-Length字段
            header = re.sub(r'Content-Length: \d+', f'Content-Length: {actual_length}', header, flags=re.IGNORECASE)
    else:
        # 添加Content-Length字段
        header += f'\r\nContent-Length: {actual_length}'

    # 重新组装响应头和响应体
    updated_response_body = header + '\r\n\r\n' + body

    return updated_response_body


def creat_http_pcap(request_str: str, response_str: str, pcapname=''):
    """
    创建一个模拟HTTP请求和响应的PCAP文件。
    这个函数可以用，而且可以用 Detect 校验

    :param request_str: HTTP请求内容
    :param response_str: HTTP响应内容
    :param pcapname: 生成的PCAP文件名称
    """

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
                                      ack=syn_ack_packet[TCP].seq + 1) / request_str.encode()

    httpack = ipdst / TCP(sport=dst_port, dport=src_port, seq=http_request_packet[TCP].ack,
                          ack=http_request_packet[TCP].seq + len(request_str), flags='A')

    http_response_packet = ipdst / TCP(sport=dst_port, dport=src_port, flags=24, seq=httpack[TCP].seq,
                                       ack=httpack[TCP].ack) / response_str.encode()

    fin_packet = ipsrc / TCP(sport=src_port, dport=dst_port, flags="FA", seq=http_response_packet[TCP].ack,
                             ack=http_response_packet[TCP].seq + len(response_str))

    ack_packet_close = ipdst / TCP(sport=dst_port, dport=src_port, flags="A", seq=fin_packet[TCP].ack,
                                   ack=fin_packet[TCP].seq + 1)

    ack_packet_close2 = ipdst / TCP(sport=dst_port, dport=src_port, flags="FA", seq=ack_packet_close[TCP].seq,
                                    ack=fin_packet[TCP].seq + 1)

    fin_packet_ack = ipsrc / TCP(sport=src_port, dport=dst_port, flags="A", seq=ack_packet_close2[TCP].ack,
                                 ack=ack_packet_close2[TCP].seq + 1)

    http_traffic = [syn_packet, syn_ack_packet, ack_packet, http_request_packet, httpack, http_response_packet,
                    fin_packet, ack_packet_close, ack_packet_close2, fin_packet_ack]
    pcap_files_dir = os.path.join(os.path.dirname(__file__), 'pcapss/')
    file_paths = pcap_files_dir + pcapname + '.pcap'

    # 确保保存文件的目录存在
    directory = os.path.dirname(file_paths)
    if not os.path.exists(directory):
        os.makedirs(directory)  # 创建目录，如果不存在的话

    wrpcap(file_paths, http_traffic)
    return file_paths



