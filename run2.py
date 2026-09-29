# -- coding: utf-8 --
"""
Detect 检测工作流
执行清理、加密、打包及检测流程。
"""

import logging
import os
import subprocess
import shutil
import sys
from pathlib import Path
from typing import Optional, Tuple

import surui_de

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 魔法字符串常量化
SDB_CRYPT_BIN = './sdbCrypt'
TAR_BIN = 'tar'
TICRYPT_BIN = './tiCrypt'
DETECT_BIN_NAME = 'Detect'
OUTPUT_SDB = 'huoyan.sdb'
OUTPUT_TAR = 'spe-detect.tar.gz'
OUTPUT_ENCRYPTED = 'spe-detect.ti'
TAR_CONTENTS = ('classification.sdb', 'reference.sdb')


def clear_directory(directory: Path) -> None:
    """
    清空指定目录下的所有文件和子目录，但不删除目录本身。

    Args:
        directory: 目标目录路径
    """
    if not directory.exists():
        return

    for item in directory.iterdir():
        try:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
            logger.info("已删除: %s", item)
        except OSError as e:
            logger.exception("删除 %s 失败", item)


def remove_files(directory: Path, pattern: str = '*.rules') -> None:
    """
    删除指定目录下符合匹配模式的文件。

    Args:
        directory: 目标目录
        pattern: 文件匹配模式，默认 '*.rules'
    """
    for file in directory.glob(pattern):
        try:
            file.unlink()
            logger.info("已删除: %s", file)
        except OSError as e:
            logger.exception("删除 %s 失败", file)


def encrypt_files(sdb_file_name: str, rules_file: str) -> None:
    """
    对规则文件进行加密。

    Args:
        sdb_file_name: 输出的加密文件名
        rules_file: 需要加密的规则文件

    Raises:
        SystemExit: 加密失败时退出
    """
    result = subprocess.run(
        [SDB_CRYPT_BIN, '-t', '1', '-i', rules_file, '-o', sdb_file_name],
        timeout=300
    )
    if result.returncode != 0:
        logger.error("规则文件加密失败")
        sys.exit(1)


def main(rules_file: str, pcaps_file: str) -> Tuple[bool, str]:
    """
    主流程：清理、加密、打包、执行检测、返回结果。

    工作目录切换说明：
    Detect 程序依赖相对路径的配置文件和日志目录，
    因此需要切换到其所在目录执行。执行完成后不恢复，
    因为这是批处理脚本，不影响 Web 请求处理。

    Args:
        rules_file: 规则文件路径
        pcaps_file: PCAP 文件路径

    Returns:
        (success: bool, result: str)
        成功时 result 为 eve.json 内容，失败时为规则文件内容
    """
    # 切换到 Detect 所在目录（Detect 依赖相对路径的配置文件）
    bin_path = Path(surui_de.detect_path.get('bin_', ''))
    os.chdir(bin_path)

    log_dir = bin_path / 'log'
    pcap_dir = bin_path / 'pcap'
    sdb_file = bin_path / SDB_CRYPT_BIN
    sdb_file_name = SDB_CRYPT_BIN  # 相对路径，加密工具在当前目录
    detect_bin = bin_path / DETECT_BIN_NAME

    # 清理旧文件
    logger.info("开始清理...")
    clear_directory(log_dir)
    clear_directory(pcap_dir)
    remove_files(bin_path)

    if sdb_file.exists():
        sdb_file.unlink()

    # 加密规则文件
    logger.info("加密规则文件...")
    encrypt_files(sdb_file_name, rules_file)

    # 打包
    logger.info("打包文件...")
    tar_result = subprocess.run(
        [TAR_BIN, '-cvf', OUTPUT_TAR] + list(TAR_CONTENTS) + [sdb_file_name],
        timeout=300
    )
    if tar_result.returncode == 0:
        logger.info("打包成功")
    else:
        logger.error("打包失败")
        sys.exit(1)

    # 加密 tar.gz
    logger.info("加密打包文件...")
    crypt_result = subprocess.run(
        [TICRYPT_BIN, '-f', '-t', '1', '-i', OUTPUT_TAR, '-o', OUTPUT_ENCRYPTED],
        timeout=300
    )
    if crypt_result.returncode == 0:
        logger.info("文件加密成功")
    else:
        logger.error("文件加密失败")
        sys.exit(1)

    # 清理中间文件
    if sdb_file.exists():
        sdb_file.unlink()
    remove_files(bin_path)

    # 执行 Detect
    logger.info("执行 Detect 程序...")
    subprocess.run([str(detect_bin), '-r', pcaps_file], timeout=300)

    # 检查结果
    eve_json_path = log_dir / 'eve.json'
    if eve_json_path.exists():
        result = read_eve_json(eve_json_path)
        logger.info("检测完成，结果已生成")
        return True, result
    else:
        logger.warning("未检测到告警，请检查 PCAP 文件或规则文件")
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules_context = f.read()
        except OSError:
            rules_context = "(无法读取规则文件)"
        return False, rules_context


def read_eve_json(filename: Path) -> str:
    """
    读取 eve.json 文件内容。

    Args:
        filename: eve.json 文件路径

    Returns:
        文件内容字符串
    """
    with open(filename, 'r', encoding='utf-8') as f:
        return f.read()


if __name__ == '__main__':
    main(rules_file=sys.argv[1], pcaps_file=sys.argv[2])
