# -- coding: utf-8 --
# 统一文件下载路由，支持 PCAP 目录下的所有文件下载

import os
import logging
from flask import Blueprint, send_from_directory

logger = logging.getLogger(__name__)

download_bp = Blueprint('download', __name__)

# 统一的文件目录
PCAP_DIR = os.path.join(os.getcwd(), 'pcapss')
RULES_DIR = os.path.join(os.getcwd(), 'ruless')


@download_bp.route('/download/pcap/<path:filename>')
def download_pcap(filename):
    """
    统一 PCAP 文件下载路由。

    :param filename: 要下载的文件名（相对路径）
    :return: 文件下载响应
    """
    # 防止路径遍历
    safe_filename = os.path.basename(filename)
    if safe_filename != filename:
        logger.warning("路径遍历尝试: %s -> %s", filename, safe_filename)
        return "非法文件名", 400

    return send_from_directory(PCAP_DIR, safe_filename, as_attachment=True)


@download_bp.route('/download/rules/<path:filename>')
def download_rules(filename):
    """
    统一规则文件下载路由。

    :param filename: 要下载的文件名（相对路径）
    :return: 文件下载响应
    """
    # 防止路径遍历
    safe_filename = os.path.basename(filename)
    if safe_filename != filename:
        logger.warning("路径遍历尝试: %s -> %s", filename, safe_filename)
        return "非法文件名", 400

    return send_from_directory(RULES_DIR, safe_filename, as_attachment=True)
