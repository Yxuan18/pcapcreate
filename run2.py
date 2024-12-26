# -- coding: utf-8 -- 
# Name: run2.py
# Where:
import sys
import os
import surui_de
import subprocess
import shutil
import logging
from pathlib import Path


# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def clear_directory(directory):
    """
    清空指定目录下的所有文件和子目录，但不删除目录本身。

    :param directory: 需要清空的目录路径 (str or Path)
    :return: None
    """
    for item in Path(directory).iterdir():
        try:
            if item.is_dir():
                shutil.rmtree(item)   # 递归删除子目录
            else:
                item.unlink()   # 删除文件
            logging.info(f"Deleted {item}")
        except Exception as e:
            logging.error(f"Failed to delete {item}: {str(e)}")


def remove_files(directory, pattern='*.rules'):
    """
    删除指定目录下符合匹配模式的文件。

    :param directory: 目标目录 (Path)
    :param pattern: 文件的匹配模式，默认为 '*.rules' (str)
    :return: None
    """
    for file in directory.glob(pattern):
        try:
            file.unlink()   # 删除匹配的文件
            logging.info(f"Deleted {file}")
        except Exception as e:
            logging.error(f"Failed to delete {file}: {str(e)}")


def encrypt_files(sdb_file_name, rules_file):
    """
    对指定的规则文件进行加密。

    :param sdb_file_name: 输出的加密文件名 (str)
    :param rules_file: 需要加密的规则文件 (str)
    :return: None

    :raises SystemExit: 如果加密失败，则退出程序。
    """
    result = subprocess.run(['./sdbCrypt', '-t', '1', '-i', rules_file, '-o', sdb_file_name])
    if result.returncode != 0:
        logging.error("Encryption failed!")
        sys.exit(1)


def main(rules_file, pcaps_file):
    """
    主函数，执行清理、加密、打包及检测流程。

    :param rules_file: 需要加密的规则文件路径 (str)
    :param pcaps_file: 待检测的PCAP流量包文件路径 (str)
    :return: tuple，包含两个元素，第一个是布尔值，表示是否成功，第二个是日志或错误信息。
    """
    # 定义路径
    bin_path = Path(surui_de.detect_path.get('bin_', ''))
    os.chdir(bin_path)  # 更改当前工作目录到指定的 bin_ 路径
    log_dir = bin_path / 'log'   # 日志目录
    pcap_dir = bin_path / 'pcap'   # pcap文件目录
    sdb_file = bin_path / 'huoyan.sdb'  # 输出的加密文件名
    sdb_file_name = 'huoyan.sdb'    # SDB文件名
    tar_file = 'spe-detect.tar.gz'  # 打包的tar文件名
    tar_input_files = ['classification.sdb', 'reference.sdb']   # 打包文件列表
    encrypted_tar_file = 'spe-detect.ti'    # 加密的tar文件名
    detect_bin = bin_path / 'Detect'        # Detect程序的路径

    # 开始清理日志和流量包
    logging.info("Starting cleanup...")
    clear_directory(log_dir)    # 清空日志目录
    clear_directory(pcap_dir)   # 清空PCAP目录
    remove_files(bin_path)      # 删除规则文件
    logging.info(f"删除 {sdb_file}")
    if sdb_file.exists():
        sdb_file.unlink()       # 如果SDB文件存在则删除(删除加密后生成的SDB文件)

    # 加密规则文件
    logging.info("加密规则文件...")
    encrypt_files(sdb_file_name, rules_file)

    # 打包为tar.gz
    # 加密打包文件
    logging.info("打包文件...")
    cmd = ['tar', '-cvf', tar_file] + tar_input_files + [sdb_file_name]
    if subprocess.run(cmd).returncode == 0:
        logging.info("打包成功。")
    else:
        logging.info("打包失败！")
        sys.exit(1)

    # 加密tar.gz文件
    logging.info("加密打包文件...")
    if subprocess.run(['./tiCrypt', '-f', '-t', '1', '-i', tar_file, '-o', encrypted_tar_file]).returncode == 0:
        logging.info("文件加密成功。")
    else:
        logging.info("文件加密失败！")
        sys.exit(1)

    if sdb_file.exists():
        sdb_file.unlink()
    remove_files(bin_path)  # 删除所有 .rules 文件
    # 执行Detect程序
    logging.info("执行Detect程序...")
    subprocess.run([detect_bin, '-r', pcaps_file])

    # 检查日志目录下是否有 eve.json
    eve_json_name = log_dir / 'eve.json'
    if (eve_json_name).exists():
        eve_json_read = read_eve_json(filename=eve_json_name)
        logging.info(eve_json_read)
        logging.info("结果已产生。")
        return True, eve_json_read          # 返回成功标志及日志信息
    else:
        logging.info(f"请检查 PCAP 文件或 {rules_file}。")
        with open(rules_file, 'r', encoding='utf-8') as ffs:
            rules_context = str(ffs.read())
            return False, rules_context     # 返回错误标志及规则文件内容


def read_eve_json(filename):
    """
    读取 eve.json 文件的内容。

    :param filename: eve.json 文件的路径 (str)
    :return: 文件内容 (str)
    """
    with open(filename, 'r', encoding='utf-8') as ffs:
        files_context = ffs.read()
        return files_context


if __name__ == '__main__':
    # 从命令行参数接收规则文件和PCAP文件路径
    main(rules_file=sys.argv[1], pcaps_file=sys.argv[2])
