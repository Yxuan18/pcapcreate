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

    detect_path = {
        'bin_': '/home/Detect',
    }

else:
    # 默认配置或其他系统处理
    suri_path = {
        'bin_': '/usr/local/bin/suricata',
        'yaml': '/usr/local/etc/suricata/suricata.yaml',
    }

