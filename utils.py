# -- coding: utf-8 --
import base64
import binascii
import logging
import os
import re

from flask import send_from_directory

logger = logging.getLogger(__name__)

# 统一的文件目录配置（集中化管理）
BASE_DIR = os.getenv("WEB_APPS_BASE_DIR", os.getcwd())
PCAP_DIR = os.getenv("WEB_APPS_PCAP_DIR", os.path.join(BASE_DIR, 'pcapss'))
RULES_DIR = os.getenv("WEB_APPS_RULES_DIR", os.path.join(BASE_DIR, 'ruless'))


def parse_templates(content):
    """
    解析多种模板格式，支持hex、base64、file等
    """
    match = re.search(r'\x7b\x7b(\w+)\x28(.*?)\x29\x7d\x7d', content)
    if not match:
        return content
    func_name = match.group(1)
    value = match.group(2)
    alls_ = match.group(0)

    try:
        if func_name == 'hex':
            # 处理十六进制
            hex_code = binascii.unhexlify(value).decode('latin-1')
            contents = content.replace(alls_, hex_code)
            return contents
        elif func_name == 'base64':
            # 处理base64
            base64_code = base64.b64decode(value).decode('latin-1')
            contents = content.replace(alls_, base64_code)
            return contents
        elif func_name == 'file':
            # 仅允许读取特定的系统信息文件（用于 WAF 检测规则测试）
            ALLOWED_FILES = {'/etc/passwd', 'c:/windows/win.ini', 'c:\\windows\\win.ini'}
            if value.lower().replace('\\', '/') not in {p.lower() for p in ALLOWED_FILES}:
                return content
            with open(value, 'rb') as f:
                file_code = f.read().decode('latin-1')
            contents = content.replace(alls_, file_code)
            return contents
    except Exception as e:
        logger.exception("解析模板失败: %s", e)
        return content
    return content


def download_file(directory: str, filename: str):
    """
    通用文件下载函数
    """
    return send_from_directory(directory, filename, as_attachment=True)