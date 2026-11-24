# -- coding: utf-8 --
"""
Suricata 检测模块
提供 PCAP 和规则文件的上传、Suricata 检测、以及规则文件内容加载功能。
"""

import logging
import os
import re
import shutil
import tempfile
from typing import Optional

import subprocess
from flask import Blueprint, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

import surui_de
from utils import (
    PCAP_DIR as pcap_files_dir, RULES_DIR as rule_files_dir,
    get_detect_status, inc_gen_count, rate_limit, _check_rate_limit,
    unique_stamp, unique_path, ensure_dir,
)

logger = logging.getLogger(__name__)

# 魔法字符串常量化
# 必须匹配任意条数，不能写死 1：Suricata 8.0.7 实测 `Alerts: 1`、`Alerts: 2`
# 都是同一格式，写死 1 会让 2 条及以上告警判成"无告警"。
# 该计数行只在 -v 下输出（实测无 -v 时 grep Alerts 命中 0）。
SURICATA_ALERT_PATTERN = re.compile(r'Alerts: (\d+)')
# fast.log 回退判定的扫描上限：只需知道"有没有告警"，不需要精确总数
_FAST_LOG_SCAN_LINES = 1000
LOG_FILES = ('suricata.log', 'eve.json', 'fast.log', 'stats.log')
ALLOWED_EXTENSIONS = ('.pcap', '.pcapng', '.rules')

# 规则加载摘要行（Suricata 8.0.7 实测格式）：
# Info: detect: N rule files processed. M rules successfully loaded, K rules failed, J rules skipped
# 全部规则无效时这行不出现，只出现 Warning: ... no rules were loaded!
_RULE_LOAD_PATTERN = re.compile(
    r'(\d+) rules successfully loaded, (\d+) rules failed, (\d+) rules skipped'
)
# 规则一条都没加载上的 warning（退出码仍是 0，容易被误当成"没命中"）
_NO_RULES_PATTERN = re.compile(r'no rules were loaded')


def count_alerts(raw_output: str) -> int:
    """从 Suricata 的 -v 输出里取告警条数；取不到按 0 处理。

    取不到不等于 0 告警——命令没带 -v 时也不会有这一行。调用方要同时
    检查 fast.log 是否存在，两者都空才判定"无告警"。
    """
    match = SURICATA_ALERT_PATTERN.search(raw_output)
    if not match:
        return 0
    try:
        return int(match.group(1))
    except ValueError:
        return 0


def has_alert_counter(raw_output: str) -> bool:
    """输出里是否有 -v 的告警计数行（区分"计数为 0"和"计数行缺失"）。

    count_alerts 对两种情况都返回 0，但判定逻辑里含义完全不同：
    "跑了、命中 0 条"可以下结论，"没拿到计数行"不能。
    """
    return SURICATA_ALERT_PATTERN.search(raw_output) is not None


def parse_rule_load(raw_output: str) -> tuple[Optional[int], Optional[int]]:
    """解析规则加载摘要行，返回 (loaded, failed)。

    摘要行缺失时 loaded 为 None（未知），不是 0——"加载了 0 条"和
    "不知道加载了几条"在判定逻辑里必须分开：前者是故障，后者同样是故障，
    但提示用户的说法不同。
    """
    match = _RULE_LOAD_PATTERN.search(raw_output)
    if not match:
        return None, None
    try:
        return int(match.group(1)), int(match.group(2))
    except ValueError:
        return None, None


def evaluate_verdict(
    raw_output: str,
    returncode: int,
    fast_log_alerts: int = 0,
) -> dict:
    """把一次 Suricata 执行的原始输出判成三态。

    返回 {'status', 'error', 'notice', 'has_alerts', 'alerts'}：
      - status == 'error'：检测没有完成，不能据此判断是否存在告警；
      - status == 'ok' 且 has_alerts 为 True：有告警，走 Detect；
      - status == 'ok' 且 has_alerts 为 False：本次未发现告警。

    判定顺序不能反：先看退出码（引擎没跑起来），再看规则有没有加载上，
    最后才数告警。顺序反了会把"规则全无效"判成"未发现告警"。
    """
    result = {
        'status': 'ok',
        'error': '',
        'notice': '',
        'has_alerts': False,
        'alerts': None,
    }

    # 1) 引擎没跑起来：退出码非 0 时任何计数都不可信。
    if returncode != 0:
        logger.error("Suricata 执行失败: returncode=%s", returncode)
        result['status'] = 'error'
        result['error'] = (
            f'Suricata 执行失败（退出码 {returncode}），'
            '本次检测没有完成，不能据此判断是否存在告警。'
            '请检查 Suricata 安装、配置文件与 PCAP 文件。'
        )
        return result

    # 2) 规则没加载上：退出码 0 但规则无效，与"规则有效但没命中"无法区分。
    loaded, failed = parse_rule_load(raw_output)
    if _NO_RULES_PATTERN.search(raw_output):
        result['status'] = 'error'
        result['error'] = (
            'Suricata 没有加载到任何规则（规则文件不存在或全部无效），'
            '本次检测没有完成，不能据此判断是否存在告警。'
        )
        return result
    if loaded is None:
        result['status'] = 'error'
        result['error'] = (
            'Suricata 输出里没有规则加载摘要，无法确认规则是否加载成功，'
            '不能据此判断是否存在告警。'
        )
        return result
    if loaded == 0:
        result['status'] = 'error'
        result['error'] = (
            'Suricata 加载了 0 条规则，本次检测没有完成，'
            '不能据此判断是否存在告警。'
        )
        return result

    # 3) 规则加载 OK，才进入告警计数。
    notice = ''
    if failed and failed > 0:
        notice = f'有 {failed} 条规则加载失败，本次告警结果可能不完整。'

    if has_alert_counter(raw_output):
        alerts = count_alerts(raw_output)
        result['alerts'] = alerts
        result['has_alerts'] = alerts > 0
    elif fast_log_alerts > 0:
        # 降级回退：计数行缺失时用本次运行的 fast.log，只判"有没有"，
        # 不当精确条数用。
        result['alerts'] = fast_log_alerts
        result['has_alerts'] = True
        notice = (notice + ' ' if notice else '') + (
            '本次输出缺少告警计数行，告警数量以 fast.log 为准。'
        )
    else:
        result['status'] = 'error'
        result['error'] = (
            'Suricata 没有输出告警计数行，本次运行也没有产生 fast.log 记录，'
            '无法确认告警数量，不能据此判断是否存在告警。'
        )
        return result

    result['notice'] = notice
    return result


def _count_fast_log_alerts(log_dir: str) -> int:
    """数指定目录里 fast.log 的告警行数；文件不存在或读不了返回 0。

    作为 count_alerts 的回退证据：Suricata 每命中一条规则就往 fast.log 写一行。
    只用于判定"有没有告警"，不读全文件——超过 _FAST_LOG_SCAN_LINES 行就停。
    log_dir 必须是本次运行专用的临时日志目录：cwd 下的 fast.log 是历史遗留，
    拿它当证据会把上一次的告警算到这一次头上。
    """
    total = 0
    path = os.path.join(log_dir, 'fast.log')
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            for total, _line in enumerate(handle, start=1):
                if total >= _FAST_LOG_SCAN_LINES:
                    break
    except FileNotFoundError:
        return 0
    except OSError as exc:
        logger.warning("读取 fast.log 失败: %s", exc)
        return 0
    return total


# PCAP 文件魔数
PCAP_MAGIC_BIG_ENDIAN = b'\xa1\xb2\xc3\xd4'   # 大端序
PCAP_MAGIC_LITTLE_ENDIAN = b'\xd4\xc3\xb2\xa1'  # 小端序
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'             # PCAPNG

# 绝对路径正则：盘符路径（C:\ / C:/）或 POSIX 绝对路径，路径段由分隔符串起来。
# 前视断言排除紧跟在单词字符/点/冒号/斜杠之后的 "/"，
# 否则 `msg:"/index"`、`http://1.2.3.4/x` 里的斜杠会被当成路径起点。
_SENSITIVE_PATH_PATTERN = re.compile(
    r'(?:[A-Za-z]:[\\/]|(?<![\w.:/])/)[^\s/\\:*?"<>|]+(?:[\\/][^\s/\\:*?"<>|]+)*'
)

# 原样保留的行前缀：规则正文（action 开头）与 HTTP 请求行。
# 这些行是用户自己写的规则/URI，不是引擎泄漏的部署路径；
# 对它们做路径替换会把告警证据本身抹掉（规则里本来就有 /var/www 这类内容）。
_RULE_LINE_PREFIXES = ('alert ', 'pass ', 'drop ', 'reject ', 'log ', 'sdrop ',
                       'GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ',
                       'PATCH ', 'CONNECT ', 'TRACE ')


def _sanitize_output(output: str) -> str:
    """隐藏 Suricata 输出里的绝对路径，防止泄漏部署目录结构。

    逐行判定：豁免前缀行（用户规则正文 / HTTP 请求行）原样保留，
    其余行一律把绝对路径替换成 [路径已隐藏]。

    旧实现按关键词白名单放行（`'Info' in line` 等），而 `-v` 输出的
    `Info: pcap: Starting file run for /绝对路径` 同时命中了白名单和
    "Info 放行"分支，路径就从这个缺口漏了出去。改成正向豁免清单后，
    新增的引擎日志行默认走脱敏，不会再靠"记得加关键词"来堵漏。

    Args:
        output: 原始 stdout/stderr 输出

    Returns:
        路径已脱敏的输出
    """
    safe_lines = []
    for line in output.splitlines():
        if line.strip().startswith(_RULE_LINE_PREFIXES):
            safe_lines.append(line)
        else:
            safe_lines.append(_SENSITIVE_PATH_PATTERN.sub('[路径已隐藏]', line))
    return '\n'.join(safe_lines)


def verify_pcap_file(file_stream, filename: str) -> bool:
    """
    校验文件内容是否为合法的 PCAP 或 PCAPNG 文件。

    通过读取文件头魔数来判断，而非依赖后缀。
    保存后返回前会恢复文件指针。

    Args:
        file_stream: 已打开的文件流（必须可读）
        filename: 文件名（用于日志）

    Returns:
        True 是合法 PCAP/PCAPNG 文件，False 不是
    """
    try:
        header = file_stream.read(4)
        if not header or len(header) < 4:
            logger.warning("文件 %s 太短，无法读取魔数", filename)
            return False

        # 恢复文件指针（供后续 save() 使用）
        file_stream.seek(0)

        if header == PCAP_MAGIC_BIG_ENDIAN or header == PCAP_MAGIC_LITTLE_ENDIAN:
            return True
        if header == PCAPNG_MAGIC:
            return True

        logger.warning("文件 %s 不是有效的 PCAP/PCAPNG 文件，魔数: %s",
                       filename, header.hex())
        return False

    except OSError:
        logger.exception("读取文件 %s 头失败", filename)
        return False


# reference 的值是自由文本（URL 里带括号很常见）：reference:url,...,CN/);
# 里面的 ')' 是数据。引号掩码挡不住它，单独再掩一层。
_REFERENCE_RE = re.compile(r'\breference:[^;]*;')
# 完整规则的开头：动作 + 协议（后面一定还有源地址等字段）
_ACTION_WORDS = ('alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst', 'sdrop', 'log')
_COMPLETE_RULE_RE = re.compile(r'^(?:' + '|'.join(_ACTION_WORDS) + r')\s+\S+\s')

# 编辑区一次能提交的上限。按典型 ET 规则 1KB/条估算，512KB ≈ 500 条，
# 够用且不会让落盘文件失控（真正的大规则库走上传通道）。
MAX_PASTE_BYTES = 512 * 1024


_PCRE_OPEN_RE = re.compile(r'pcre:\s*"')


def _mask_pcre(text: str) -> str:
    """先单独掩掉 pcre 的值，再交给通用引号扫描。

    pcre 的值是正则，里面可以出现裸引号：``pcre:"/^["']?post/Ri"`` 在字符类
    里就有两个 ``"``。按"遇到引号就收尾"的通用规则走，会在这里提前断开，
    把后面的结构误当数据，最终报"引号未闭合"——ET 库里有这类规则。

    Suricata 判定 pcre 结尾的规则是：引号后面（跳过空格）紧跟 ``;``。
    按这条找结束位置，与引擎口径一致。
    """
    out = text
    pos = 0
    while True:
        match = _PCRE_OPEN_RE.search(out, pos)
        if not match:
            return out
        start = match.end() - 1  # 开引号位置

        end = -1
        for i in range(start + 1, len(out)):
            if out[i] != '"':
                continue
            j = i + 1
            while j < len(out) and out[j] in ' \t':
                j += 1
            if j < len(out) and out[j] == ';':
                end = i
                break
        if end == -1:
            # 没有"引号+分号"结构（畸形规则），保持原样交给后面的闭合检查
            return out

        out = out[:start] + '"' + ' ' * (end - start - 1) + '"' + out[end + 1:]
        pos = end + 1


def _scan_and_mask(text: str) -> tuple[str, bool]:
    """把引号内的内容换成等长空格，同时报告引号是否闭合。

    ``content:".SetShapeNodeType("`` 里的括号、``content:"->"`` 里的箭头、
    ``pcre:"..."`` 里的分号都是**数据**不是结构。直接对原始行 count 会把
    合法规则误判成"括号不配对"——实测 ET 全量规则库 52768 条里有 1064 条
    因此被误拒。

    必须等长替换：``options_block`` 是按索引从原行切出来的，长度变了就错位。

    必须逐字符扫描而不是 ``re.sub(r'"[^"]*"')``：``pcre:"/^[a-f0-9]{32}\\"/R"``
    里的 ``\\"`` 是转义引号，正则会在那里提前收尾，把后面的结构当成数据。

    Returns:
        (masked, balanced)。balanced 为 False 表示引号未闭合——此时后面
        的一切都会被当数据、结构校验全部失效，调用方必须直接拒绝。
    """
    text = _mask_pcre(text)
    out = []
    in_quote = False
    escaped = False
    for ch in text:
        if not in_quote:
            if ch == '"':
                in_quote = True
            out.append(ch)
            continue
        if escaped:
            escaped = False
            out.append(' ')
        elif ch == '\\':
            escaped = True
            out.append(' ')
        elif ch == '"':
            in_quote = False
            out.append('"')
        else:
            out.append(' ')
    masked = ''.join(out)
    # reference 的值同样是数据（URL 里的括号、分号）
    masked = _REFERENCE_RE.sub(
        lambda m: 'reference:' + ' ' * (len(m.group(0)) - len('reference:') - 1) + ';',
        masked,
    )
    return masked, not in_quote


def _mask_quoted(text: str) -> str:
    """只取掩码结果（调用方已确认引号闭合）。"""
    return _scan_and_mask(text)[0]


def _has_unbalanced_quotes(text: str) -> bool:
    """未闭合的引号会让后面的一切都被当数据，掩码后结构校验全失效，必须单独拦。"""
    return not _scan_and_mask(text)[1]


def verify_rules_file(file_stream, filename: str) -> tuple[bool, str]:
    """
    校验文件内容是否符合 Suricata 规则语法。

    Suricata 规则格式：action protocol src dst direction (options) sid:xxx;
    每行可以是：
    - 空行（跳过）
    - 注释行（# 开头，跳过）
    - 有效规则（必须包含 action、protocol、方向和括号内选项）

    Args:
        file_stream: 已打开的文件流
        filename: 文件名（用于日志）

    Returns:
        (True, '') 校验通过
        (False, '错误信息') 校验失败，包含失败原因
    """
    try:
        content = file_stream.read().decode('utf-8', errors='replace')
    except OSError:
        logger.exception("读取文件 %s 失败", filename)
        return False, "文件读取失败"

    # 常见 action 和 protocol。
    # PROTOCOLS 白名单只用于"识别这一行像不像一条规则"，不再是语法裁决者——
    # 原来硬编码的列表把 http1 / pkthdr / ike / mqtt / rfb 等合法协议全部
    # 拒掉（ET 全量库里 1400+ 条），真正对不对由 Suricata 自己说了算。
    ACTIONS = set(_ACTION_WORDS)
    PROTOCOLS = {
        # 传输层 / 网络层
        'tcp', 'udp', 'icmp', 'icmpv6', 'ip', 'ipv6', 'sctp', 'pkthdr',
        'tcp-pkt', 'tcp-stream', 'vlan', 'gre',
        # 应用层（Suricata 8 --list-app-layer-protos）
        'http', 'http1', 'http2', 'ftp', 'ftp-data', 'smtp', 'ssh', 'dns',
        'tls', 'dcerpc', 'nfs', 'smb', 'imap', 'pop3', 'sip', 'rdp',
        'snmp', 'dhcp', 'ike', 'krb5', 'ldap', 'mdns', 'mqtt', 'ntp',
        'quic', 'rfb', 'telnet', 'tftp', 'websocket', 'doh2',
        'bittorrent-dht',
    }
    DIRECTIONS = {'->', '<>', '<-'}

    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        # 跳过空行和注释行
        if not stripped or stripped.startswith('#'):
            continue

        if _has_unbalanced_quotes(stripped):
            logger.warning("文件 %s 第 %d 行：引号未闭合", filename, lineno)
            return False, f"第 {lineno} 行：引号未闭合"

        # 结构性符号只在引号外计数：content:"(" / pcre:"a;b" 里的符号是数据。
        # 用等长掩码而非删除，保证下面按索引切 options_block 不错位。
        masked = _mask_quoted(stripped)

        # 检查括号配对（规则主体在括号内）
        if masked.count('(') != masked.count(')'):
            logger.warning("文件 %s 第 %d 行：括号不配对", filename, lineno)
            return False, f"第 {lineno} 行：括号不配对"

        # 最小结构：必须包含方向符号和括号
        has_direction = any(d in masked for d in DIRECTIONS)
        has_paren = '(' in masked and ')' in masked
        if not (has_direction and has_paren):
            logger.warning("文件 %s 第 %d 行：缺少方向符号或括号", filename, lineno)
            return False, f"第 {lineno} 行：缺少方向符号或括号"

        # 提取 action（第一个词）
        parts = stripped.split()
        if not parts:
            continue
        action = parts[0]
        if action not in ACTIONS:
            logger.warning("文件 %s 第 %d 行：未知 action '%s'，期望 %s",
                          filename, lineno, action, ACTIONS)
            return False, f"第 {lineno} 行：未知 action '{action}'"

        # 提取 protocol（第二个词，必须在白名单内）。
        # PROTOCOLS 覆盖 Suricata 8 的全部规则协议关键字，逐条用
        # `suricata -T -S` 验过。裸 `any` 这类不是合法规则协议，仍然拒。
        # 换 Suricata 版本后若冒出新的协议关键字，报错信息会带上名字，
        # 加到 PROTOCOLS 即可。
        if len(parts) >= 2 and parts[1] not in PROTOCOLS:
            logger.warning("文件 %s 第 %d 行：未知 protocol '%s'",
                          filename, lineno, parts[1])
            return False, f"第 {lineno} 行：未知 protocol '{parts[1]}'"

        # 检查括号内是否有 sid
        paren_start = masked.index('(')
        paren_end = masked.rindex(')')
        options_block = masked[paren_start + 1:paren_end]

        # sid 格式：sid:数字;（sid 前后可能有空格）
        if not re.search(r'\bsid\s*:\s*\d+\s*;', options_block):
            logger.warning("文件 %s 第 %d 行：缺少 sid（格式应为 sid:数字;）", filename, lineno)
            return False, f"第 {lineno} 行：缺少 sid（格式应为 sid:数字;）"

    # 全部通过或仅空文件
    return True, ""


def _validate_rule_fragment(fragment: str) -> tuple[bool, str]:
    """
    校验编辑区里**单条 options 片段**（不含 action/方向/外层括号）。

    该片段的语义是"被注入到 alert proto any any -> any any (msg:"X"; <fragment> sid:Y;)
    模板的 options 部分"。完整规则行走 `_is_complete_rule_line` 走另一条路径，
    不经过这里。

    因此必须满足：
      1) 无换行（调用方已按行切分，这里只兜底）；
      2) 括号配对—— 防止 `)` 提前闭合外层 `(`；
      3) 不嵌入 Suricata 规则开头/方向符号—— 防止把模板拆成多行；
      4) 长度上限—— 防止单条规则失控；
      5) 以分号结尾—— options 片段的最低形态。

    引号允许出现（``content:"foo"`` 是标准写法），且判定前先把引号内容掩码：
    ``content:"("`` 里的括号是数据，不是结构。

    Layer 1 拦截最常见的畸形输入；Layer 2（合成后再调 verify_rules_file）
    兜底，两层口径有偏差时也能被拦下。
    """
    if not fragment:
        return False, "内容为空"

    if len(fragment) > 1024:
        return False, "单条规则片段超过 1024 字符"

    # 单行：拒绝任何换行（\r \n \r\n \v \f）
    if any(c in fragment for c in '\r\n\v\f'):
        return False, "禁止换行"

    if _has_unbalanced_quotes(fragment):
        return False, "引号未闭合"

    masked = _mask_quoted(fragment)

    # 括号配对：括号必须成对出现，否则会提前闭合外层
    if masked.count('(') != masked.count(')'):
        return False, "括号不配对"

    # Suricata 规则头部 / 方向符号：嵌入会把模板拆成多行。
    # 引号内已掩码——content:"->" 是数据，放行。
    forbidden_markers = tuple(f'{a} ' for a in _ACTION_WORDS) + ('->', '<>', '<-')
    lowered = masked.lower()
    for marker in forbidden_markers:
        if marker in lowered:
            return False, f"片段内禁止出现 {marker.strip()}（写完整规则请另起一行）"

    # options 片段的格式：以分号结尾的 key:value; 序列
    # 不强制每个 kv 都合法（key/value 字符范围广），verify_rules_file 会兜底——
    # 这里只做"分号结尾"的最低形态校验。
    if not fragment.rstrip().endswith(';'):
        return False, "必须以分号 ; 结尾"

    return True, ""


def _is_complete_rule_line(line: str) -> bool:
    """该行是否自带 action + 协议（即用户直接写的完整规则）。"""
    return bool(_COMPLETE_RULE_RE.match(line))


_GENERATED_SID_MIN = 9_000_000
_GENERATED_SID_MAX = 9_999_999


def _guess_protocol(fragment: str) -> str:
    """片段对应的 Suricata 协议关键字：metadata:service 优先，其次按粘性缓冲区推断。"""
    match = re.search(r'metadata:service\s+(\w+);', fragment)
    if match:
        return match.group(1)
    if '; http.' in fragment or fragment.startswith('http.'):
        return 'http'
    return 'udp'


_SID_RE = re.compile(r'\bsid\s*:\s*(\d+)\s*;')


def _next_free_sid(taken: set[int]) -> int:
    """在自动分配号段里找一个没被占用的 sid。

    原来是 ``randint`` 撞了就重抽的 while 循环——在 _GENERATED_SID_MIN 到
    MAX 这 100 万个号里，只要已占用数远小于号段容量，循环几乎不会真的多转。
    改成从号段起点顺次找空位，行为可预测、不会因极端输入退化成死循环。
    """
    sid = _GENERATED_SID_MIN
    while sid in taken and sid <= _GENERATED_SID_MAX:
        sid += 1
    if sid > _GENERATED_SID_MAX:
        # 号段用尽（需要同时粘贴 100 万条片段才会到这里）：回落到用户号段之外，
        # 保持"不撞号"这个唯一要求，不为了概率为零的情况牺牲正确性。
        sid = max(taken, default=0) + 1
    return sid


def _duplicate_sid_groups(text: str) -> dict[int, list[int]]:
    """找出同一份规则里 sid 重复的行：``{sid: [行号, ...]}``，只留出现 ≥2 次的。

    这里只做统计，不做拦截。理由见 `_renumber_duplicate_sids`。
    """
    seen: dict[int, list[int]] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.strip().startswith('#'):
            continue
        match = _SID_RE.search(_mask_quoted(line))
        if match:
            seen.setdefault(int(match.group(1)), []).append(lineno)
    return {sid: lns for sid, lns in seen.items() if len(lns) > 1}


def _renumber_duplicate_sids(text: str) -> tuple[str, list[tuple[int, int, int]]]:
    """为本地 Suricata 验证生成一份 sid 互不相同的临时规则文本。

    为什么不拦截重复 sid：sid 唯一是 **Suricata 单机引擎**的限制，不是规则
    语义的要求。Detect（本工具的真实交付目标）对同 sid 的多条规则全部加载、
    全部生效——rulelib 日志实测 5 条 sid 全为 98 的规则 `ok(5) fail(0)`，且
    各自命中。拿下游引擎的限制去拦上游输入，是把约束装错了地方。

    为什么不干脆放着不管：Suricata 遇到同 sid 只保留一条，退出码仍是 0。于是
    "测了 5 条"和"测了 1 条"在页面上长得一模一样，用户会把漏测当成"其余规则
    不匹配"。这比直接报错更危险，所以本地验证这一步必须让每条规则都真正参与
    匹配。

    做法：同一 sid 保留第一处原样，后续出现依次换成未占用的新 sid。只改 sid
    数字，其余逐字不动。sid 不参与任何匹配逻辑（content/pcre/flowbits 都不
    引用它），改它不改变检测语义。

    Returns:
        (临时规则文本, [(行号, 原 sid, 新 sid), ...])
    """
    groups = _duplicate_sid_groups(text)
    if not groups:
        return text, []

    taken = {sid for sid in (_SID_RE.search(_mask_quoted(line))
                             for line in text.splitlines() if line.strip())
             if sid}
    taken = {int(m.group(1)) for m in taken}
    # 从现有最大 sid 之后找空位，避开用户和自动分配用过的号段
    next_sid = max(max(taken, default=0) + 1, _GENERATED_SID_MIN)

    remap: list[tuple[int, int, int]] = []
    # sid -> 已经用掉几次（第一次保持原值）
    occurrences: dict[int, int] = {}
    out_lines = []
    for lineno, line in enumerate(text.splitlines(), 1):
        match = _SID_RE.search(_mask_quoted(line))
        if not match or _is_comment_or_blank(line):
            out_lines.append(line)
            continue
        sid = int(match.group(1))
        occurrences[sid] = occurrences.get(sid, 0) + 1
        if occurrences[sid] == 1:
            out_lines.append(line)
            continue
        while next_sid in taken:
            next_sid += 1
        new_sid = next_sid
        taken.add(new_sid)
        next_sid += 1
        # 只替换这一处 sid 的数字（用掩码后的位置去切原文，避开 content 里的假 sid）
        start, end = match.span(1)
        out_lines.append(f'{line[:start]}{new_sid}{line[end:]}')
        remap.append((lineno, sid, new_sid))

    return '\n'.join(out_lines) + '\n', remap


def _is_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith('#')


def _rules_for_local_verify(rule_path: str) -> tuple[str, list[tuple[int, int, int]], str]:
    """给本地 Suricata 准备规则文件路径：有重复 sid 就生成一份临时去重副本。

    Returns:
        (要传给 -S 的路径, 改号记录, 需要删除的临时文件路径或 '')
        没有重复时原样返回 (rule_path, [], '')，不产生任何临时文件。
    """
    try:
        with open(rule_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError:
        # 读不出来就交给 Suricata 自己报错，这里不吞异常信息
        logger.warning("读取规则文件失败，按原路径交给 Suricata: %s", rule_path)
        return rule_path, [], ''

    if not _duplicate_sid_groups(text):
        return rule_path, [], ''

    rewritten, remap = _renumber_duplicate_sids(text)
    # 放在同目录（Suricata 的 -S 不吃相对路径以外的位置也无所谓，这里图省事；
    # 关键是文件名以 . 开头，不会出现在规则下拉列表里——列表过滤的是 .rules 后缀，
    # 所以再显式排除一次，避免用户把它当成自己的规则文件）。
    tmp_path = os.path.join(
        os.path.dirname(rule_path) or '.',
        f'.verify-{unique_stamp()}.rules',
    )
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            f.write(rewritten)
    except OSError:
        logger.exception("写临时验证规则失败，退回原路径（可能少测规则）")
        return rule_path, [], ''
    return tmp_path, remap, tmp_path


def _assemble_rules(text: str) -> tuple[str, str]:
    """
    把编辑区内容整理成可直接落盘的 .rules 文本。

    支持两种输入形态，且允许在同一份粘贴里混用：
      - 完整规则行：``alert tcp any any -> any 139,445 (msg:"..."; sid:59816; rev:2;)``
        → 原样保留（多行 = 多条规则，这是本函数存在的原因）；
      - options 片段：``flow:to_server; http.uri; content:"/index"; metadata:service http;``
        → 套上模板生成一条规则，自动分配 sid。

    空行与 ``#`` 注释行原样保留，保证返回内容的行号与用户编辑区一致——
    否则 verify_rules_file 报的"第 N 行"对不上用户看到的位置。

    Returns:
        (rule_text, '') 成功；('', 错误信息) 失败，错误信息面向用户。
    """
    if not text.strip():
        return '', '内容为空'

    if len(text.encode('utf-8')) > MAX_PASTE_BYTES:
        return '', f'内容超过 {MAX_PASTE_BYTES // 1024}KB，大规则库请用上传通道'

    out_lines = []
    # 已占用的 sid：既包括粘贴里用户自己写的，也包括本次自动分配的
    used_sids = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        stripped = line.strip()

        if not stripped or stripped.startswith('#'):
            out_lines.append(line)
            continue

        if _is_complete_rule_line(stripped):
            # 完整规则原样保留；同时登记它的 sid，让后面自动分配避开已有号段
            for sid in _SID_RE.findall(stripped):
                used_sids.add(int(sid))
            out_lines.append(stripped)
            continue

        ok, reason = _validate_rule_fragment(stripped)
        if not ok:
            return '', f'第 {lineno} 行：{reason}'

        # 自动分配的 sid 必须互不相同：同 sid 在 Suricata 侧会互相顶掉，
        # 而这几条是用户"分两行写的不同检测意图"，撞号纯属我们没分配好。
        sid = _next_free_sid(used_sids)
        used_sids.add(sid)

        out_lines.append(
            f'alert {_guess_protocol(stripped)} any any -> any any '
            f'(msg:"{unique_stamp()}"; {stripped} sid:{sid};)'
        )

    # 重复 sid 不拦。sid 唯一是 Suricata 单机引擎的限制，Detect 侧同 sid
    # 全部生效（见 _renumber_duplicate_sids 的实测记录）。真正落盘的内容原样
    # 保留重复，只有本地验证那一步才用临时去重副本。
    return '\n'.join(out_lines) + '\n', ''


# 蓝图定义
suricata_check = Blueprint('suricata_check', __name__, template_folder='./')


def clear_logs() -> None:
    """
    删除当前目录下的 Suricata 日志文件。

    原因：确保每次检测前环境干净，避免旧日志干扰分析。
    """
    for file_name in LOG_FILES:
        try:
            os.remove(file_name)
        except FileNotFoundError:
            pass  # 文件不存在，忽略
        except OSError:
            logger.exception("删除日志文件 %s 失败", file_name)


def get_suricata_status() -> dict:
    """
    探测本地 Suricata 可用性：配置路径（surui_de.suri_path）优先，PATH 兜底。

    Returns:
        {'available': bool, 'bin': str, 'version': str}
        bin 为实际可执行的路径；不可用时为配置路径，供页面提示定位。
    """
    configured = surui_de.suri_path.get('bin_', '')
    candidates = [configured, shutil.which('suricata')]
    bin_path = next(
        (c for c in candidates if c and os.path.isfile(c) and os.access(c, os.X_OK)),
        ''
    )
    if not bin_path:
        return {'available': False, 'bin': configured, 'version': ''}

    version = ''
    try:
        result = subprocess.run(
            [bin_path, '-V'], capture_output=True, timeout=10
        )
        version = (result.stdout + result.stderr).decode('utf-8', errors='ignore').strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        # 版本探测失败不等于不可用，只降级为无版本信息
        logger.warning("获取 Suricata 版本失败: %s", e)
    return {'available': True, 'bin': bin_path, 'version': version}


def _build_dup_sid_notice(filename: str) -> str:
    """刚保存的规则文件若有重复 sid，生成一句说明；否则返回空串。

    文案由服务端读文件得出，不信任 URL 参数里的任何内容——URL 里只传文件名，
    且文件名要过 realpath 白名单校验（见调用处）。
    """
    if not filename or not filename.endswith('.rules'):
        return ''
    safe = os.path.realpath(os.path.join(rule_files_dir, filename))
    if not safe.startswith(os.path.realpath(rule_files_dir) + os.sep):
        return ''
    try:
        with open(safe, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError:
        return ''

    groups = _duplicate_sid_groups(text)
    if not groups:
        return ''
    detail = '、'.join(
        f'sid:{sid}（第 {"、".join(str(n) for n in lns)} 行）'
        for sid, lns in sorted(groups.items())
    )
    return (
        f'已按原样保存到 {filename}。规则里有重复 sid：{detail}。'
        f'Detect 侧会全部生效；本地 Suricata 验证时每个 sid 只保留首条，'
        f'其余不参与匹配（验证时会自动用临时去重副本，结果不受影响）。'
    )


def get_sorted_files(directory: str, suffixes: str | list[str], display_count: Optional[int] = None) -> list[str]:
    """
    获取指定目录下按创建时间倒序排列的文件列表。

    Args:
        directory: 目录路径
        suffixes: 文件后缀（单个或列表）
        display_count: 显示数量上限，None 表示不限制

    Returns:
        按创建时间倒序排列的文件名列表
    """
    if isinstance(suffixes, str):
        suffixes = [suffixes]

    # 确保目录存在
    os.makedirs(directory, exist_ok=True)

    # 过滤符合后缀的文件。以 . 开头的跳过——本地验证用的临时副本
    # （.verify-*.rules）也带 .rules 后缀，不能出现在用户的下拉列表里。
    files = [
        f for f in os.listdir(directory)
        if not f.startswith('.') and any(f.endswith(suffix) for suffix in suffixes)
    ]

    # 按创建时间倒序
    files.sort(key=lambda x: os.path.getctime(os.path.join(directory, x)), reverse=True)

    if display_count is not None and len(files) > display_count:
        return files[:display_count]
    return files


@suricata_check.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    """
    处理 PCAP 或 RULES 文件上传，保存到预定义目录。

    Returns:
        成功消息或错误信息和 HTTP 状态码
    """
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    if not file.filename:
        return "No selected file", 400

    # secure_filename 会把非 ASCII 字符整个丢掉：'测试.rules' → 'rules'，
    # '规则集2024.rules' → '2024.rules'——扩展名跟着一起没了，后面按后缀
    # 分派的分支全部落空。中文文件名在规则库里很常见（msg 本来就是中文），
    # 所以扩展名单独保留，只清洗主名；主名洗空就用 upload 兜底。
    stem, ext = os.path.splitext(file.filename)
    ext = ext.lower()
    filename = (secure_filename(stem) or 'upload') + ext if ext in ALLOWED_EXTENSIONS \
        else secure_filename(file.filename)
    if not filename:
        return "Invalid file name", 400

    if filename.endswith('.pcap') or filename.endswith('.pcapng'):
        # 先校验文件内容是否为合法的 PCAP/PCAPNG
        if not verify_pcap_file(file, filename):
            return "Invalid PCAP file content", 400
        # L 系列：同名不覆盖。unique_path 查重后追加 _1 / _2 ...，
        # 既保留用户命名意图，又不污染别人的文件。
        # M-3 防护：用户从未访问过列表页时目录未创建，file.save() 会
        # FileNotFoundError → 500。这里 ensure_dir 兜底。
        file.seek(0)  # 重置指针后再保存
        ensure_dir(pcap_files_dir)
        target = unique_path(pcap_files_dir, filename)
        file.save(target)
        actual = os.path.basename(target)
        if actual != filename:
            logger.info("上传重名自动改名: %s -> %s", filename, actual)
        return "PCAP File uploaded successfully", 200
    elif filename.endswith('.rules'):
        # 校验规则文件语法
        ok, err = verify_rules_file(file, filename)
        if not ok:
            return err, 400
        file.seek(0)  # 重置指针后再保存
        # M-3 防护：同上，ruless 目录可能未创建。
        ensure_dir(rule_files_dir)
        target = unique_path(rule_files_dir, filename)
        file.save(target)
        actual = os.path.basename(target)
        if actual != filename:
            logger.info("上传重名自动改名: %s -> %s", filename, actual)
        return "RULES File uploaded successfully", 200
    else:
        return "Invalid file type", 400


@suricata_check.route('/suricata_check', methods=['GET', 'POST'])
def check():
    """
    显示可用的 PCAP 和 RULES 文件，POST 时执行 Suricata 检测。

    流程：
    1. 获取所有 pcap 和 rules 文件
    2. 若提交规则内容，创建以时间戳命名的新规则文件
    3. 若执行检测，调用 Suricata，成功后跳转到 Detect 检查流程
    """
    rule_files = get_sorted_files(rule_files_dir, '.rules')
    pcap_files = get_sorted_files(pcap_files_dir, ['.pcap', '.pcapng'])
    suricata_status = get_suricata_status()
    detect_status = get_detect_status()

    output = ""
    # 刚保存带重复 sid 的规则时，跳转会带上文件名，这里据实生成提示。
    # 放在 GET 分支而不是 POST：刷新页面不会重复提交，提示也还在。
    notice = _build_dup_sid_notice(request.args.get('saved', ''))

    if request.method == 'POST':
        # M-2 限流：POST 才会触发 Suricata/Detect 子进程；GET 只是展示
        # 文件列表（用户正常浏览）。3 次/分钟——既能挡匿名 flood，
        # 也不影响正常使用（一次完整检测流程 5~10s 一次，3/min 远高于
        # 实际使用频率）。
        blocked = _check_rate_limit(max_calls=3, window_seconds=60)
        if blocked is not None:
            return blocked

        selected_rule = request.form.get('file_select')
        selected_pcap = request.form.get('pcap_select')

        # 路径安全校验
        safe_rule_path = None
        safe_pcap_path = None

        if selected_rule:
            safe_rule_path = os.path.realpath(os.path.join(rule_files_dir, selected_rule))
            if not safe_rule_path.startswith(os.path.realpath(rule_files_dir) + os.sep):
                return "非法规则文件路径", 400

        if selected_pcap:
            safe_pcap_path = os.path.realpath(os.path.join(pcap_files_dir, selected_pcap))
            if not safe_pcap_path.startswith(os.path.realpath(pcap_files_dir) + os.sep):
                return "非法 PCAP 文件路径", 400

        suri_bin = suricata_status['bin']
        suri_yaml = surui_de.suri_path['yaml']
        # 不再回退到目录：-r <dir> 会静默跑完目录下所有 pcap。留 None 让执行
        # 分支明确拒绝（见下方 safe_pcap_path 守卫）；仅保存规则时不走执行分支，
        # None 不会被使用。
        selected_pcap_path = safe_pcap_path
        # 规则路径保持原值：只有执行检测才需要它。保存规则（load_rules）
        # 不依赖 Suricata，用户完全可以写完规则再选文件去跑。
        selected_rule_path = safe_rule_path

        # 保存新的规则内容
        if 'file_content_edit' in request.form and 'load_rules' in request.form:
            raw_content = request.form.get('file_content_edit', '')
            if raw_content.strip():
                # 编辑区支持多种形态：单条 options 片段、整条规则、以及多条
                # 规则（每行一条）。_assemble_rules 按行分派并保留行号，
                # 校验失败时能指到用户看到的第几行。
                rule_content, reason = _assemble_rules(raw_content)
                if reason:
                    logger.warning(
                        "拒绝非法的规则内容: %s (user_input=%r)",
                        reason, raw_content[:120],
                    )
                    return f"规则内容非法: {reason}", 400

                # L 系列：文件名加 8 位 hex 后缀（unique_stamp），杜绝
                # 同秒内多用户提交同名规则的覆盖问题。原代码 2 位数字
                # 后缀（100 组合）每秒 100+ 提交就冲突。
                new_rule_path = unique_path(
                    rule_files_dir, f"{unique_stamp()}.rules",
                )

                # 落盘的是用户原样内容：sid 重复照原样保留。Detect 侧同 sid
                # 全部生效，改号会在交付件里引入用户没要求的差异。
                with open(new_rule_path, 'w', encoding='utf-8') as f:
                    f.write(rule_content)

                # H-3 纵深防御：把合成后的完整规则再过一遍 verify_rules_file，
                # 防止 validator 与 Suricata 实际解析口径有偏差时仍有漏网之鱼。
                with open(new_rule_path, 'rb') as f:
                    ok, reason = verify_rules_file(f, new_rule_path)
                if not ok:
                    logger.error(
                        "合成后规则未通过 verify_rules_file: %s", reason,
                    )
                    try:
                        os.remove(new_rule_path)
                    except OSError:
                        pass
                    return f"规则内容非法: {reason}", 400

                dup_groups = _duplicate_sid_groups(rule_content)
                logger.info("创建新规则文件: %s（%d 条，%d 个重复 sid）",
                            new_rule_path,
                            sum(1 for ln in rule_content.splitlines()
                                if ln.strip() and not ln.strip().startswith('#')),
                            len(dup_groups))

                if dup_groups:
                    # 不拦，但要让用户知道后果。提示不放这里的原因：redirect
                    # 会丢掉本次响应里的变量，而直接渲染又会带来"刷新即重提交"。
                    # 改成跳转时带上刚存的文件名，由 GET 分支读文件自行生成提示——
                    # 既能刷新，文案也来自服务端事实而不是 URL 里的字面量。
                    return redirect(url_for(
                        'suricata_check.check',
                        saved=os.path.basename(new_rule_path),
                    ))

            return redirect(url_for('suricata_check.check'))

        # 执行 Suricata 检测
        if 'execute' in request.form:
            # -s 只认单个文件（实测 Suricata 8.0.7：传目录不报错、加载 0 条，
            # 然后 yaml 里自带的 ET 规则库照旧生效——用户看到的告警来自上游
            # 规则库而不是自己选的规则，且毫无提示）。没选规则文件就明确拒绝。
            if not safe_rule_path:
                logger.warning("未选择规则文件，拒绝执行: rule_files_dir=%s", rule_files_dir)
                return render_template(
                    'suricata_check.html',
                    rule_files=rule_files,
                    pcap_files=pcap_files,
                    suricata_status=suricata_status,
                    detect_status=detect_status,
                    error='请先在下拉框选择一个 .rules 文件后再执行检查',
                    previous_page='home',
                    next_page='detect_check.check'
                )
            # Suricata 不可用时服务端再挡一道（前端 disabled 可被直接 POST 绕过）
            if not suricata_status['available']:
                logger.warning("Suricata 不可用，拒绝执行检查: %s", suricata_status['bin'])
                return render_template(
                    'suricata_check.html',
                    rule_files=rule_files,
                    pcap_files=pcap_files,
                    suricata_status=suricata_status,
                    detect_status=detect_status,
                    error='未检测到本地 Suricata，无法执行检查',
                    previous_page='home',
                    next_page='detect_check.check'
                )
            # 没选 pcap 同样明确拒绝。-r 传目录不报错、退出码 0，会把目录下
            # 所有 pcap 一起跑（实测 read 2 files, 20 packets），用户以为测的是
            # 自己选的流量，实际测的是别人的全部样本，且页面不提示用了哪些。
            if not safe_pcap_path:
                logger.warning("未选择 PCAP 文件，拒绝执行: pcap_files_dir=%s", pcap_files_dir)
                return render_template(
                    'suricata_check.html',
                    rule_files=rule_files,
                    pcap_files=pcap_files,
                    suricata_status=suricata_status,
                    detect_status=detect_status,
                    error='请先在下拉框选择一个 .pcap / .pcapng 文件后再执行检查',
                    previous_page='home',
                    next_page='detect_check.check'
                )
            # 本地验证用 sid 去重后的临时副本：Suricata 同 sid 只保留一条，
            # 不去重就会静默少测规则。原文件不动，验证完即删。
            verify_rule_path, sid_remap, cleanup_path = _rules_for_local_verify(
                selected_rule_path
            )
            if sid_remap:
                logger.info(
                    "本地验证临时改号 %d 处（原文件保持不变）: %s",
                    len(sid_remap),
                    ', '.join(f'第{n}行 sid {o}→{x}' for n, o, x in sid_remap[:10]),
                )

            # 本次运行专用的日志目录：-l 指向它，fast.log 等日志全部落在这里。
            # 必须在 Popen 之前建好——Suricata 遇到不存在的 -l 目录会自己
            # 退出码 1，等于自己制造一次"引擎故障"。
            # 建目录也可能失败（/tmp 满、TMPDIR 指向不存在的路径）。失败时走
            # 与 Popen 失败同一条 error 渲染路径：响亮地报"检测没做成"，
            # 而不是让 Flask 返回通用 500 错误页。
            # log_dir 先置 None：建目录失败时下面 finally 的 rmtree 拿它当
            # 无条件依据，不能因未定义而 NameError。
            log_dir = None
            # 临时验证副本与临时日志目录必须无条件删掉——下面有 3 条 return
            # 分支，任何一条漏了都会在 ruless/ 里留垃圾或在 /tmp 里留目录。
            # 建目录也在这个 try 里：它失败时同样要走到 finally 删掉规则副本，
            # 否则每次建目录失败都会在 ruless/ 留一份垃圾。
            try:
                try:
                    log_dir = tempfile.mkdtemp(prefix='suricata_check_')
                except OSError as exc:
                    logger.error("创建临时日志目录失败: %s", exc)
                    return render_template(
                        'suricata_check_result.html',
                        output='',
                        error=(
                            'Suricata 执行失败（无法创建临时日志目录），'
                            '本次检测没有完成，不能据此判断是否存在告警。'
                        ),
                        previous_page='suricata_check.check',
                        next_page='detect_check.check'
                    )
                # 构建命令（避免 shell 注入）
                # 保留 -v：告警计数行 "Info: counters: Alerts: N" 只在 -v 下输出，
                # 去掉它就没有任何告警数量信息（实测无 -v 时 grep Alerts 命中 0），
                # 页面会永远显示"无告警"。路径泄漏由 _sanitize_output 负责，不靠砍 -v。
                # -l 指向本次运行专用临时目录：cwd 下的 fast.log 是历史遗留，
                # 拿它当证据会把上一次的告警算到这一次头上（P0-2）。
                command = [
                    suri_bin,
                    '-c', suri_yaml,
                    '-S', verify_rule_path,
                    '-r', selected_pcap_path,
                    '-l', log_dir,
                    '-k', 'none',
                    '-v',
                ]

                # 清 cwd 下的历史日志：从"判定有告警之后"提前到"执行之前"。
                # 本次运行的日志已经落在临时目录里，cwd 下的是上一轮遗留，
                # 执行前删掉不会影响本次判定，却能杜绝残留 fast.log 伪造告警。
                clear_logs()

                try:
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except OSError as exc:
                    # 引擎根本没起来（可执行文件没了/权限没了）。退出码都拿不到，
                    # 同样不能判成"未发现告警"。
                    logger.error("启动 Suricata 失败: %s", exc)
                    return render_template(
                        'suricata_check_result.html',
                        output='',
                        error=(
                            'Suricata 执行失败（无法启动进程），'
                            '本次检测没有完成，不能据此判断是否存在告警。'
                        ),
                        previous_page='suricata_check.check',
                        next_page='detect_check.check'
                    )
                # M-2 修复：communicate() 必须有 timeout。恶意构造的 pcap 可能
                # 让 Suricata 长时间卡住（上传只校验 4 字节魔数），无 timeout 会
                # 永久占住 worker 线程。timeout=300 对齐 run2.py 的 subprocess
                # 行为（Detect 流程同样 300s 上限）。
                try:
                    stdout, stderr = process.communicate(timeout=300)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    logger.warning("Suricata 检测超时（>300s），已终止子进程")
                    return render_template(
                        'suricata_check.html',
                        rule_files=rule_files,
                        pcap_files=pcap_files,
                        suricata_status=suricata_status,
                        detect_status=detect_status,
                        error='Suricata 检测超时（>300s），请检查 PCAP 或规则文件',
                        previous_page='home',
                        next_page='detect_check.check'
                    )
                raw_output = stdout.decode() + stderr.decode()
                # fast.log 只从本次运行的临时目录读，且必须在 finally 清目录
                # 之前读——否则目录没了就永远拿不到回退证据。
                fast_log_alerts = _count_fast_log_alerts(log_dir)
            finally:
                if cleanup_path:
                    try:
                        os.remove(cleanup_path)
                    except OSError:
                        logger.warning("删除临时验证规则失败: %s", cleanup_path)
                if log_dir:
                    shutil.rmtree(log_dir, ignore_errors=True)

            # 过滤敏感路径信息，防止路径泄漏
            output = _sanitize_output(raw_output)
            inc_gen_count("suricata_check")

            # 三态判定：故障 / 有告警 / 未发现告警。顺序不能反——
            # 退出码非 0 或规则没加载上时，任何计数都不可信。
            verdict = evaluate_verdict(
                raw_output, process.returncode, fast_log_alerts=fast_log_alerts,
            )

            if verdict['status'] == 'error':
                logger.warning("Suricata 检测未能完成: %s", verdict['error'])
                return render_template(
                    'suricata_check_result.html',
                    output=output,
                    error=verdict['error'],
                    notice=verdict['notice'],
                    previous_page='suricata_check.check',
                    next_page='detect_check.check'
                )

            notice = verdict['notice']
            if not verdict['has_alerts']:
                # 引擎正常退出、规则已加载、没命中：这是"未发现告警"，
                # 措辞上与故障态区分开，避免用户把两种情况看成同一件事。
                notice = (notice + ' ' if notice else '') + '本次检查未发现告警。'

            # 检测到告警时跳转到 Detect 检查（使用原始输出检测，过滤后的输出可能丢失特征）
            if verdict['has_alerts']:
                message = "即将运行 Detect 检查，请稍后"
                # 跳 Detect 用原始文件（不是临时改号副本）——Detect 支持同 sid，
                # 交付件必须是用户原样的规则。
                redirect_url = url_for('detect_check.run_detect', rule_path=selected_rule_path, pcap_path=selected_pcap_path)
                script = f'setTimeout(function() {{ window.location.href = "{redirect_url}"; }}, 2000);'
                return render_template(
                    'intermediate.html',
                    message=message,
                    script=script,
                    rule_path=selected_rule_path,
                    pcap_path=selected_pcap_path,
                    notice=notice,
                    previous_page='suricata_check.check',
                    next_page='detect_check.check'
                )
            else:
                return render_template(
                    'suricata_check_result.html',
                    output=output,
                    notice=notice,
                    previous_page='suricata_check.check',
                    next_page='detect_check.check'
                )

        if 'detect' in request.form:
            # Detect 未配置时拦截（前端按钮已隐藏，这里防直接 POST 绕过）
            if not detect_status['available']:
                logger.warning("Detect 未配置，拒绝执行: %r", detect_status['bin'])
                return render_template(
                    'suricata_check.html',
                    rule_files=rule_files,
                    pcap_files=pcap_files,
                    suricata_status=suricata_status,
                    detect_status=detect_status,
                    error='本机未配置 Detect（安装目录不存在或 bin_ 为空），无法执行检测',
                    previous_page='home',
                    next_page='detect_check.check'
                )
            message = "即将运行 Detect 检查，请稍后"
            redirect_url = url_for('detect_check.run_detect', rule_path=selected_rule_path, pcap_path=selected_pcap_path)
            script = f'setTimeout(function() {{ window.location.href = "{redirect_url}"; }}, 2000);'
            return render_template(
                'intermediate.html',
                message=message,
                script=script,
                rule_path=selected_rule_path,
                pcap_path=selected_pcap_path,
                previous_page='suricata_check.check',
                next_page='detect_check.check'
            )

    return render_template(
        'suricata_check.html',
        rule_files=rule_files,
        pcap_files=pcap_files,
        suricata_status=suricata_status,
        detect_status=detect_status,
        notice=notice,
        previous_page='home',
        next_page='detect_check.check'
    )


@suricata_check.route('/load_rules_content')
def load_rules_content():
    """
    加载指定规则文件内容。

    路径遍历防护：仅允许读取 rules 目录下的文件。
    """
    file_name = request.args.get('file')
    if not file_name:
        return "No file specified", 400

    safe_dir = os.path.realpath(rule_files_dir)
    file_path = os.path.realpath(os.path.join(rule_files_dir, file_name))

    if not file_path.startswith(safe_dir + os.sep) and file_path != safe_dir:
        logger.warning("路径遍历尝试: %s", file_name)
        return "非法路径", 400

    if not os.path.exists(file_path):
        return "文件不存在", 404

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read(), 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except OSError:
        logger.exception("读取规则文件失败: %s", file_name)
        return "文件读取失败", 500
