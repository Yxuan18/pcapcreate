# -- coding: utf-8 --
# 统一文件下载路由，支持 PCAP 目录下的所有文件下载

import os
import logging
from flask import Blueprint, send_from_directory

# 目录配置复用 web_apps/utils.py（与 app.py 的 clear_directories、生成端一致）。
# 这里原先自己算 os.getcwd()/pcapss，是唯一不读环境变量的模块——环境变量重定向后
# 生成写到新目录、下载读旧目录，两边彻底分家。
# 平铺导入（from utils import ...）是 web_apps 内部惯例（app.py / generate_pcap.py
# 同样写法）；web_apps 目录作为 cwd 或 sys.path 首位时解析到的是 web_apps/utils.py。
import utils

logger = logging.getLogger(__name__)

# 目录常量必须来自 web_apps/utils.py。仓库根也有个同名 utils/ 包（空壳），
# 平铺导入一旦解析到它就没有 PCAP_DIR——与其在请求时炸 AttributeError，
# 不如在导入时就说清楚是谁、为什么。
if not hasattr(utils, 'PCAP_DIR'):
    raise ImportError(
        "download.py 解析到的 utils 不是 web_apps/utils.py："
        f"{getattr(utils, '__file__', '?')}（缺少 PCAP_DIR）。"
        "web_apps 必须以自身目录为 cwd 或 sys.path 首位运行。"
    )

download_bp = Blueprint('download', __name__)


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

    # 请求时才取目录：与 app.clear_directories 一致，配置改了立即生效
    return send_from_directory(utils.PCAP_DIR, safe_filename, as_attachment=True)


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

    # 请求时才取目录：与 app.clear_directories 一致，配置改了立即生效
    return send_from_directory(utils.RULES_DIR, safe_filename, as_attachment=True)

