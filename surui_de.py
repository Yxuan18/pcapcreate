# -- coding: utf-8 --
# Name: surui_de.py
# Where:
"""路径配置：自动探测 Suricata / Detect 的安装位置。

解析优先级（逐级回退）：
1. 环境变量（SURICATA_BIN / SURICATA_YAML / WEB_APPS_DETECT_BIN）
2. 自动探测（shutil.which 找可执行文件；按平台常见目录找 yaml / Detect）
3. 平台默认值（仅 Suricata；探测失败时兜底，页面提示可据此定位）

找不到时返回空字符串，由 web 前端门控隐藏对应入口
（见 utils.get_detect_status / suricata_check.get_suricata_status）。
"""
import os
import platform
import shutil

# 获取操作系统类型
system_platform = platform.system()

webs_path = {
    'pcap': os.path.join(os.getcwd(), "pcapss")
}

# 平台默认路径：自动探测失败时的兜底值（与旧版硬编码一致）
_PLATFORM_DEFAULTS = {
    'Windows': {
        'bin_': 'C:/SEC/Suricata/suricata.exe',
        'yaml': 'C:/SEC/Suricata/suricata.yaml',
    },
    'Linux': {
        'bin_': '/usr/bin/suricata',
        'yaml': '/etc/suricata/suricata.yaml',
    },
    'Darwin': {
        'bin_': '/opt/homebrew/bin/suricata',
        'yaml': '/opt/homebrew/etc/suricata/suricata.yaml',
    },
}

# yaml 按平台常见目录搜索；bin 位置推断出的目录会动态插到最前
_YAML_SEARCH_DIRS = {
    'Windows': ['C:/SEC/Suricata', 'C:/Program Files/Suricata'],
    'Linux': ['/etc/suricata', '/usr/local/etc/suricata'],
    'Darwin': ['/opt/homebrew/etc/suricata', '/usr/local/etc/suricata'],
}

# Detect 安装目录候选（bin_ 语义是目录：run2/detect_check 在其下拼 log/、pcap/）
_DETECT_DIR_CANDIDATES = {
    'Linux': ['/home/Detect', '/opt/Detect'],
    'Darwin': ['/opt/Detect', os.path.expanduser('~/Detect')],
    'Windows': ['C:/SEC/Detect', 'C:/Detect'],
}


def _find_file(filename: str, search_dirs: list) -> str:
    """返回 search_dirs 中第一个存在的 filename 完整路径，找不到返回空串。"""
    for d in search_dirs:
        path = os.path.join(d, filename)
        if os.path.isfile(path):
            return path
    return ""


def _yaml_search_dirs(suri_bin: str) -> list:
    """
    组装 yaml 搜索目录（去重保序）：
    环境变量 SURICATA_CONF_DIR > bin 同级/上级推断 > 平台常见目录。
    """
    dirs = []
    env_dir = os.environ.get('SURICATA_CONF_DIR', '')
    if env_dir:
        dirs.append(env_dir)
    if suri_bin:
        bin_dir = os.path.dirname(suri_bin)
        # Homebrew 布局: bin/suricata 与 etc/suricata/ 同级
        dirs.append(os.path.join(os.path.dirname(bin_dir), 'etc', 'suricata'))
        # 源码编译布局: yaml 与可执行文件同目录
        dirs.append(bin_dir)
    dirs.extend(_YAML_SEARCH_DIRS.get(system_platform, []))
    seen = set()
    return [d for d in dirs if not (d in seen or seen.add(d))]


def _find_detect_dir() -> str:
    """查找 Detect 安装目录，找不到返回空串（前端隐藏 Detect 入口）。"""
    for d in _DETECT_DIR_CANDIDATES.get(system_platform, []):
        if os.path.isdir(d):
            return d
    return ""


# ---- Suricata：环境变量 > 自动探测 > 平台默认 ----
_defaults = _PLATFORM_DEFAULTS.get(system_platform, _PLATFORM_DEFAULTS['Darwin'])
_suri_bin = shutil.which('suricata') or ''

suri_path = {
    'bin_': os.environ.get('SURICATA_BIN') or _suri_bin or _defaults['bin_'],
    'yaml': (os.environ.get('SURICATA_YAML')
             or _find_file('suricata.yaml', _yaml_search_dirs(_suri_bin))
             or _defaults['yaml']),
}

# ---- Detect：环境变量 > 自动探测；为空时前端隐藏 Detect 入口 ----
# 必须先给默认值——原来只在 Linux 分支定义，
# macOS/Windows 上访问 surui_de.detect_path 直接 AttributeError。
detect_path = {
    'bin_': os.environ.get('WEB_APPS_DETECT_BIN') or _find_detect_dir(),
}
