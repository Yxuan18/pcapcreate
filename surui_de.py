# -- coding: utf-8 -- 
# Name: surui_de.py
# Where:
import os
import platform

# 获取操作系统类型
system_platform = platform.system()

webs_path = {
    'pcap': os.path.join(os.getcwd(), "pcapss")
}

# Detect 安装目录：必须先给默认值——原来只在 Linux 分支定义，
# macOS/Windows 上访问 surui_de.detect_path 直接 AttributeError。
# 未配置（bin_ 为空或路径无效）时，web 前端隐藏 Detect 入口。
detect_path = {
    'bin_': os.environ.get('WEB_APPS_DETECT_BIN', ''),
}

if system_platform == 'Windows':
    suri_path = {
        'bin_': 'C:/SEC/Suricata/suricata.exe',
        'yaml': 'C:/SEC/Suricata/suricata.yaml',
    }

elif system_platform == 'Linux':
    suri_path = {
        'bin_': '/usr/bin/suricata',
        'yaml': '/etc/suricata/suricata.yaml',
    }

    if not detect_path['bin_']:
        detect_path['bin_'] = '/home/Detect'

else:
    # 默认配置或其他系统处理
    suri_path = {
        'bin_': '/usr/local/bin/suricata',
        'yaml': '/usr/local/etc/suricata/suricata.yaml',
    }

