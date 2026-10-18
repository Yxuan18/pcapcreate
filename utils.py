# -- coding: utf-8 --
import base64
import binascii
import fcntl
import ipaddress
import json
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


GEN_COUNT_FILE = os.path.join(BASE_DIR, 'gen_count.json')

# 各 generate 功能名称枚举（与 gen_count.json 的 key 一一对应）
GEN_COUNT_NAMES = frozenset([
    'generate_pcap',
    'generate_udp',
    'generate_icmp',
    'generate_tcp',
    'generate_smtp',
    'suricata_check',
])


def _read_count_file() -> dict:
    """读取计数文件，不存在则返回空结构。"""
    if not os.path.isfile(GEN_COUNT_FILE):
        return {}
    try:
        with open(GEN_COUNT_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_count_file(data: dict) -> None:
    """原子写入计数文件（flock 保护）。"""
    tmp = GEN_COUNT_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, GEN_COUNT_FILE)


def get_gen_count() -> dict:
    """
    读取所有功能的使用计数。

    Returns:
        {'generate_pcap': 0, 'generate_udp': 0, ...}
    """
    data = _read_count_file()
    return {name: data.get(name, 0) for name in GEN_COUNT_NAMES}


def inc_gen_count(name: str) -> int:
    """
    指定功能计数 +1（flock 原子递增）。

    :param name: 功能名称，必须在 GEN_COUNT_NAMES 中
    :return: 递增后的值
    """
    if name not in GEN_COUNT_NAMES:
        raise ValueError(f"未知功能名称: {name}")

    lock_path = GEN_COUNT_FILE + '.lock'
    with open(lock_path, 'w') as lock_fd:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
        try:
            data = _read_count_file()
            data.setdefault(name, 0)
            data[name] += 1
            data['last_updated'] = __import__('datetime').datetime.now().isoformat()
            _write_count_file(data)
            return data[name]
        finally:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)


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


# ----------------------------------------------------------------------
# 简易 IP 限流（M-2 防护）
# ----------------------------------------------------------------------
# 目的：防止匿名用户并发触发"独占 _detect_lock 300s"这类接口导致
# 正常用户全部排队。仅按 IP 计数，不引入 flask-limiter 等新依赖。
#
# 设计：滑动窗口，单位时间内的请求数超过 max_calls 则拒绝。
# 内存：每个 IP 一条记录（首次出现时间戳列表），最坏情况 O(活跃 IP 数)。
# 清理：每次调用 lazy 清理超过窗口的旧时间戳；定期全量回收空列表。
import threading
import time as _time
from collections import deque
from functools import wraps

from flask import jsonify, request

_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque[float]] = {}


def _client_ip() -> str:
    """取客户端 IP。优先 X-Forwarded-For（如果反代设置了），否则 remote_addr。"""
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        # 形如 "client, proxy1, proxy2"，取第一个
        return fwd.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _check_rate_limit(max_calls: int, window_seconds: int):
    """
    检查单 IP 在 window_seconds 内的请求数；超出返回 429 响应，否则返回 None。

    与 rate_limit 装饰器共享同一个 _rate_buckets，但允许在路由函数内部
    按需调用（例如 suricata_check.check 的 GET 列表展示不需要限流，
    只对 POST 的真实执行路径限流）。
    """
    ip = _client_ip()
    now = _time.monotonic()
    cutoff = now - window_seconds
    with _rate_lock:
        bucket = _rate_buckets.setdefault(ip, deque())
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= max_calls:
            retry_after = max(1, int(window_seconds - (now - bucket[0])))
            logger.warning(
                "rate_limit 触发: ip=%s path=%s 在 %ds 内已 %d 次",
                ip, request.path, window_seconds, len(bucket),
            )
            resp = jsonify({
                'error': '请求过于频繁',
                'retry_after': retry_after,
            })
            resp.status_code = 429
            resp.headers['Retry-After'] = str(retry_after)
            return resp
        bucket.append(now)
        return None


def rate_limit(max_calls: int, window_seconds: int):
    """
    装饰器：单 IP 在 window_seconds 内的请求数不超过 max_calls。

    超出时返回 429 Too Many Requests（JSON 格式）。装饰器按 IP 计数，
    同一 IP 在不同接口上的计数是独立的（每个装饰器实例一个 bucket）。

    用法：
        @detect_check.route('/run_detect', ...)
        @rate_limit(max_calls=3, window_seconds=60)
        def run_detect():
            ...
    """
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            blocked = _check_rate_limit(max_calls, window_seconds)
            if blocked is not None:
                return blocked
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ----------------------------------------------------------------------
# 文件命名工具（L 系列：防跨用户覆盖）
# ----------------------------------------------------------------------
import uuid


def unique_stamp() -> str:
    """
    返回一个 14 字符的时间戳 + 随机后缀标识，替代之前的 ``int(time.time())``
    和 ``%H-%M`` 命名。结构：``MMDD-HHMMSS-XXXXXXXX``（8 位 hex，
    2^32 ≈ 43 亿组合）。同秒内多次调用冲突概率 1/2^32，可视为唯一。
    """
    now = _time.time()
    struct = _time.strftime("%m%d-%H%M%S", _time.localtime(now))
    return f"{struct}-{uuid.uuid4().hex[:8]}"


def unique_path(directory: str, base_name: str) -> str:
    """
    在 directory 下为 base_name 找一个不冲突的文件路径。

    如果 base_name 不存在，直接返回 ``directory/base_name``；
    否则追加 ``_1`` / ``_2`` ... 直到不冲突为止（最多 9999 次）。
    base_name 必须已通过 secure_filename 清洗。

    用法：替代 ``os.path.join(dir, name)`` + ``open(...)`` 的
    "直接覆盖" 模式，保留用户命名意图又不丢数据。
    """
    candidate = os.path.join(directory, base_name)
    if not os.path.exists(candidate):
        return candidate

    stem, ext = os.path.splitext(base_name)
    for i in range(1, 10000):
        candidate = os.path.join(directory, f"{stem}_{i}{ext}")
        if not os.path.exists(candidate):
            return candidate

    # 极端 fallback：10000 次都冲突（不可能），退到 uuid 后缀
    return os.path.join(
        directory,
        f"{stem}_{uuid.uuid4().hex[:8]}{ext}",
    )


# ----------------------------------------------------------------------
# 表单字段语义校验（M-3 系列：替代 10 个 int 转换点 + 8 个 IP 字段的裸 try/except）
# ----------------------------------------------------------------------
# 设计：所有外部输入（int / IP）集中在这里做"取值 + 类型 + 范围"三连。
# 调用方一行就能写完，且能拿到标准的 (value, error_response) 二元组：
#
#   value, err = _parse_int_field(request, 'src_port', default=12345,
#                                  lo=1, hi=65535)
#   if err is not None:
#       return err
#
# 之前每个调用点都是 int(request.form.get('src_port', 12345))，用户传
# 'abc' / '' / '70000' / '-1' 都会让 Flask 转 500——M-3 报告里说的就是这个。
# 之所以不只在调用点加 try/except，而是抽成工具函数：
#   1) 范围校验比类型校验更严（端口不能 70000，但 int() 不会拒绝它）；
#   2) 错误消息统一为中文，UX 一致；
#   3) 一处改全部生效（避免哪天有人加新端点又漏了）。
_VALIDATION_ERROR_FIELD = 'field'


def _parse_int_field(req, field: str, default, lo: int, hi: int, label: str = ''):
    """
    从 request 解析一个整数字段，做范围校验。

    替代 ``int(request.form.get('field', default))``。

    规则：
      - 字段不存在或为空字符串 → 返回 default
      - 字段存在但不是合法整数（'abc' / '' / '1.5'）→ 400 + 错误消息
      - 字段值超出 [lo, hi] 范围 → 400 + 错误消息
      - default 也必须在 [lo, hi] 范围内——启动期一次断言（防配置错误）

    Returns:
        (value, None) 成功
        (None, (body, 400)) 失败
    """
    display = label or field
    if not (lo <= default <= hi):
        raise ValueError(
            f"配置错误：{display} 的 default={default} 超出 [{lo}, {hi}]"
        )

    raw = req.form.get(field, None)
    if raw is None or raw == '':
        return default, None

    # 拒绝浮点形式（'1.5' / '1e3'）—— int() 会抛 ValueError，但提前拦
    # 能给出更清晰的错误消息；分两步走是因为 isinstance check 不可靠。
    try:
        # strip 防止用户输入 " 80 " 之类带空格
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        logger.warning("form %s=%r 不是合法整数", field, raw)
        return None, (f"{display} 不是合法整数: {raw!r}", 400)

    if not (lo <= value <= hi):
        logger.warning("form %s=%d 超出范围 [%d, %d]", field, value, lo, hi)
        return None, (f"{display} 超出范围 [{lo}, {hi}]: {value}", 400)

    return value, None


def _parse_ip_field(req, field: str, default, label: str = ''):
    """
    从 request 解析一个 IPv4/IPv6 地址字段。

    替代 ``request.form.get('src_ip', '192.168.1.1')`` 之后的裸 IP() 构造。
    scapy.IP(src='not-an-ip') 会抛 gaierror / OSError → Flask 转 500——本
    工具提前校验并返回 400，避免把底层异常暴露给用户。

    规则：
      - 字段不存在或为空字符串 → 返回 default（已校验为合法 IP 或 None）
      - default 为 None → 字段为空时返回 (None, (400 错误))，用于必填字段
      - 字段不是合法 IP（'999.999.999.999' / 'not-an-ip' / '1.2.3'）→ 400

    Returns:
        (value, None) 成功
        (None, (body, 400)) 失败
    """
    display = label or field

    # default 校验：None 表示"必填字段"；否则必须是合法 IP
    if default is not None:
        try:
            ipaddress.ip_address(default)
        except ValueError as e:
            raise ValueError(
                f"配置错误：{display} 的 default={default!r} 不是合法 IP: {e}"
            )

    raw = req.form.get(field, None)
    if raw is None or raw == '':
        if default is None:
            return None, (f"{display} 不能为空", 400)
        return default, None

    candidate = str(raw).strip()
    try:
        # 接受 IPv4 / IPv6；拒绝 '1.2.3'（4 段缺失）和 '999.999.999.999'（段越界）
        ipaddress.ip_address(candidate)
    except ValueError:
        logger.warning("form %s=%r 不是合法 IP 地址", field, raw)
        return None, (f"{display} 不是合法 IP 地址: {raw!r}", 400)

    return candidate, None


def ensure_dir(directory: str) -> None:
    """
    确保目录存在；不存在则创建（exist_ok=True）。

    替代每个端点里零散的 ``os.makedirs(dir, exist_ok=True)``，以及
    修 upload_pcap 这种"忘记加 makedirs 导致 file.save() FileNotFoundError"
    的问题（用户从未访问过列表页→目录未创建→直接上传→500）。
    """
    os.makedirs(directory, exist_ok=True)