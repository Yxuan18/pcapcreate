# -- coding: utf-8 --
import base64
import binascii
import logging
import os
import re

from flask import send_from_directory

import surui_de

logger = logging.getLogger(__name__)

# 统一的文件目录配置（集中化管理）
BASE_DIR = os.getenv("WEB_APPS_BASE_DIR", os.getcwd())
PCAP_DIR = os.getenv("WEB_APPS_PCAP_DIR", os.path.join(BASE_DIR, 'pcapss'))
RULES_DIR = os.getenv("WEB_APPS_RULES_DIR", os.path.join(BASE_DIR, 'ruless'))


def parse_templates(content):
    """
    解析多种模板格式，支持hex、base64、file等。

    返回 bytes：模板产生的原始字节与普通文本（按 UTF-8 编码）直接拼接。
    不能先按 Latin-1 解码成 str 再让调用方编码——字节 >= 0x80 会在
    UTF-8 编码时变形（如 {{hex(ff)}} 变成 c3bf），二进制特征样本就错了。
    """
    match = re.search(r'\x7b\x7b(\w+)\x28(.*?)\x29\x7d\x7d', content)
    if not match:
        return content.encode('utf-8')
    func_name = match.group(1)
    value = match.group(2)
    alls_ = match.group(0)

    try:
        if func_name == 'hex':
            # 处理十六进制
            raw = binascii.unhexlify(value)
        elif func_name == 'base64':
            # 处理base64
            raw = base64.b64decode(value)
        elif func_name == 'file':
            # 仅允许读取特定的系统信息文件（用于 WAF 检测规则测试）
            ALLOWED_FILES = {'/etc/passwd', 'c:/windows/win.ini', 'c:\\windows\\win.ini'}
            if value.lower().replace('\\', '/') not in {p.lower() for p in ALLOWED_FILES}:
                return content.encode('utf-8')
            with open(value, 'rb') as f:
                raw = f.read()
        else:
            return content.encode('utf-8')
    except Exception as e:
        logger.exception("解析模板失败: %s", e)
        return content.encode('utf-8')

    # 等价于原 content.replace(alls_, ...)：同一模板串出现几次就替换几次
    return raw.join(part.encode('utf-8') for part in content.split(alls_))


def download_file(directory: str, filename: str):
    """
    通用文件下载函数
    """
    return send_from_directory(directory, filename, as_attachment=True)


def get_detect_status() -> dict:
    """
    探测本地 Detect 套件可用性（依赖 surui_de.detect_path 的 bin_ 配置）。

    放在 utils 而非 detect_check：suricata_check 与 detect_check 互相已有
    导入关系，状态探测放共享层避免循环导入。

    Returns:
        {'available': bool, 'bin': str}
        bin_ 为空、路径不存在或不可执行时均视为未配置。
    """
    detect_bin = surui_de.detect_path.get('bin_', '')
    available = bool(detect_bin) and os.path.isfile(detect_bin) and os.access(detect_bin, os.X_OK)
    return {'available': available, 'bin': detect_bin}