# -- coding: utf-8 --
"""
简要 payload → 完整 HTTP 请求 / 响应报文

定位：把从 WAF 规则、告警日志里直接复制来的片段补成 Suricata 能解析的完整
报文，省去每次在请求体文本框里手工补 method、HTTP 版本、Host、Content-Length
的重复劳动。

与 waf-tools/rule_verify_payload.py 的区别：那个模块为「触发 WAF 规则」服务，
会改写 Content-Type（JSON→表单）、把连续 7 个以上的同字母扩张到 310 个、
丢弃混入的响应片段；本模块只补结构不动内容——报文要忠实反映输入，否则
生成的 PCAP 与用户意图不符。

规则：
- 首行可能是 "POST /path HTTP/1.1"、"/path"，也可能直接是 "admin.php"
- 首行之后、首个空行之前，形如 "Name: value" 的行是请求头，其余行是报文主体
- 请求框里粘着"请求 + 响应"（抓包、WAF 日志常见形态）时，请求体为空的位置
  出现的状态行及其后内容是响应，由 split_request_response 拆出
- 请求行里不能裸出现的空格与 # 会被转义（空格会被当作 request-target 结束，
  # 会被当作 fragment 起点而丢弃其后路径）
- 缺 Host 时补默认值（HTTP/1.1 必需，Suricata 也靠它建事务）
- 有主体但缺 Content-Type 时按内容推断，缺 Content-Length 时按字节数补
- 请求体里出现表单分部标记（``filename="1.php"``、``name="f"``、
  ``Content-Disposition: form-data``）时补成完整 multipart/form-data：
  分隔线、每个分部的 Content-Disposition、以及头部的 Content-Type 全部补齐
  （见 _build_multipart）。仅补结构，分部内容的字节不动
- 响应：以 HTTP/ 开头的按原样规整；"200"/"404 Not Found" 这样的状态行补齐；
  其余内容整体当作 200 响应的 body
- 响应部分里形如 "Name: value" 的行是响应头，其后为响应体
"""
import logging
import re

logger = logging.getLogger(__name__)

# HTTP/1.1 缺 Host 时的兜底值
DEFAULT_HOST = 'yixuan.com'
# 未声明 Content-Type 时的兜底值，请求与响应分开定，都不做内容推断。
# 之所以敢按方向一刀切：实测 Suricata 的 http.request_body 与声明的类型无关
# ——同一段 JSON 分别声明 application/json 与 form-urlencoded，正文规则命中
# 完全一致（Suricata 8.0.7）。所以"猜得准"换不到额外命中，猜错倒让报文
# 声明与实际不符。
DEFAULT_REQUEST_CONTENT_TYPE = 'application/x-www-form-urlencoded'
# 响应侧用实际服务端最常见的声明
DEFAULT_RESPONSE_CONTENT_TYPE = 'text/html; charset=UTF-8'
# 状态行里的原因短语（只收录常用的，其余留空）
STATUS_REASONS = {
    '200': 'OK',
    '301': 'Moved Permanently',
    '302': 'Found',
    '403': 'Forbidden',
    '404': 'Not Found',
    '500': 'Internal Server Error',
    '502': 'Bad Gateway',
}

METHODS = ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT')

# 首行的 method 前缀：GET /path。method 必须是大写字母词，避免把 "a=1" 当 method
_METHOD_PREFIX_RE = re.compile(r'^([A-Z]{3,8})[ \t]+(.+)$')
# 首行末尾夹带的 HTTP 版本号（"GET /path HTTP/1.1" 或 "/path HTTP/1.1"）
_VERSION_SUFFIX_RE = re.compile(r'\s+HTTP/[\d.]+\s*$', re.IGNORECASE)
# 请求头行：RFC 7230 token 作名字，值可空（"Host:" 这种也算头）
_HEADER_LINE_RE = re.compile(r"^([A-Za-z0-9!#$%&'*+.^_`|~-]+):(?:[ \t]*(.*))?$")
# 响应状态行：HTTP/1.1 200 OK
_RESPONSE_LINE_RE = re.compile(r'^HTTP/[\d.]+\s+\d{3}', re.IGNORECASE)
# 裸状态码行："200" 或 "404 Not Found"
_STATUS_CODE_RE = re.compile(r'^(\d{3})(?:\s+(.*))?$')
# 请求行中不能裸出现的字符 → 百分号编码
PATH_UNSAFE_ENCODING = str.maketrans({
    ' ': '%20',
    '#': '%23',
})
# 完整的分部头：Content-Disposition: form-data; name="f"; filename="1.php"
_PART_DISPOSITION_RE = re.compile(r'^content-disposition\s*:\s*form-data\b(.*)$', re.IGNORECASE)
# 裸分部属性行（payload 里常只写这一截）：name="f"、filename="1.php"
# 捕获组：属性名、值、行内剩余内容（``filename="1.php" a.aspx`` 这种）
_BARE_PART_RE = re.compile(
    r'^(name|filename)\s*=\s*"([^"]*)"(?:\s+(.*))?$', re.IGNORECASE,
)
# multipart 分隔线：--boundary 或结束线 --boundary--
_BOUNDARY_LINE_RE = re.compile(r'^--(\S+?)(--)?\s*$')
# 从分部头里取 name / filename 属性
_PART_ATTR_RE = re.compile(r'\b(name|filename)\s*=\s*"([^"]*)"', re.IGNORECASE)
# 分部自己的头（不是字段内容），只在分部头区域生效。白名单而非任意 "X: y"，
# 否则值为 "a: b" 的普通内容行会被误当成头
_PART_HEADER_RE = re.compile(r'^(?:content-type|content-transfer-encoding)\s*:', re.IGNORECASE)
# Content-Type 里声明的 boundary
_BOUNDARY_RE = re.compile(r'boundary\s*=\s*"?([^";\s]+)"?', re.IGNORECASE)
# 未声明 boundary 时的分隔串。必须是固定值：每次随机的话，同一段 payload
# 补全两次得到不同报文，前端失焦补全就会反复改写用户的内容。
DEFAULT_BOUNDARY = '----WebKitFormBoundaryPayloadExpand'
# 只给了 filename 时字段名无从得知，用与 waf-tools/rule_verify_payload.py
# 相同的默认值，两个工具的产物才能互相对照
DEFAULT_FIELD_NAME = 'file'


def is_complete_request(text: str) -> bool:
    """
    报文是否已经完整到"再扩展一次也原样不变"。

    不用"首行是否有 HTTP 版本"判断：stats.ccs 里 "POST /path HTTP/1.1" 加
    裸 body 的片段很常见，首行完整但报文缺 Host/Content-Length，仍然需要补。
    改用幂等性判断，对所有形态都成立。

    比较前归一换行符：浏览器 textarea 提交的是 LF，扩展产物是 CRLF，
    直接比字面量会把已补全的内容误判成"还需补全"，导致反复改写。
    """
    if not text or not text.strip():
        return False
    rebuilt = _join_messages(*expand_payload(text))
    return rebuilt.replace('\r\n', '\n') == text.replace('\r\n', '\n')


def expand_payload(payload: str) -> tuple:
    """
    连体 payload 一次拆完并分别补全（请求框里粘进"请求 + 响应"时用）。

    :return: (请求报文, 响应报文)；不含响应片段时响应报文为 ''
    """
    request_part, response_part = split_request_response(payload)
    return (
        expand_request(request_part),
        expand_response(response_part) if response_part else '',
    )


def _join_messages(request_message: str, response_message: str) -> str:
    """把已补全的请求与响应拼回一段文本（抓包里连体的展示形态）。"""
    if not response_message:
        return request_message
    return request_message + response_message


def _split_lines(text: str) -> list:
    """统一行尾后切行（CRLF / CR / LF 混用都能处理）。"""
    return text.replace('\r\n', '\n').replace('\r', '\n').split('\n')


def _is_status_line(line: str) -> bool:
    """这一行像响应起始行吗："HTTP/1.1 200 OK"、"200"、"200 OK"。"""
    return bool(_RESPONSE_LINE_RE.match(line) or _STATUS_CODE_RE.match(line))


def split_request_response(payload: str) -> tuple:
    """
    拆出粘在请求后面的响应片段，返回 (请求片段, 响应片段)。

    抓包与 WAF 告警日志里"请求 + 响应"连体很常见，粘进请求框时响应会被
    当成请求体发给服务端，报文就错了。

    切分点：请求行之后，第一条形如 ``200`` / ``200 OK`` / ``HTTP/1.1 200``
    的行。它之前是请求，之后是响应；状态行之后形如 "Name: value" 的行由
    expand_response 认成响应头，再往下是响应体。

    不做"请求体已开始就不再判状态行"的保护，也不要求请求头没声明
    Content-Length。理由：连体报文里请求体的声明长度往往只覆盖请求体本身
    （用户按原报文照抄的），拿它当"后面绝无响应"的证据会把响应原样粘进
    请求体发出去——那种静默错误比多切一次的代价大。请求体里真有单独一行
    ``200`` 的场合极少，真遇到时把响应框留空、请求框里只放请求即可。

    :return: (请求片段, 响应片段)；不含响应时响应为 ''
    """
    if not payload or not payload.strip():
        return '', ''

    lines = _split_lines(payload)
    while lines and not lines[-1].strip():
        lines.pop()

    for index in range(1, len(lines)):
        stripped = lines[index].strip()
        if not stripped or _HEADER_LINE_RE.match(lines[index]):
            continue
        if _is_status_line(stripped):
            return '\n'.join(lines[:index]), '\n'.join(lines[index:])
    return payload, ''


def _split_request_line(first: str) -> tuple:
    """把首行拆成 (method, path)，规整路径并转义不安全字符。"""
    match = _METHOD_PREFIX_RE.match(first)
    if match and match.group(1) in METHODS:
        method, target = match.group(1), match.group(2)
    else:
        # 只有路径（或干脆是别的内容）：按 GET 处理
        method, target = 'GET', first

    target = _VERSION_SUFFIX_RE.sub('', target).strip()
    if not target.startswith('/'):
        target = '/' + target
    return method, target.translate(PATH_UNSAFE_ENCODING)


def _split_headers_body(lines: list) -> tuple:
    """
    把首行之后的行拆成 (headers, body)。

    headers 是 (name, value) 列表——保留原始顺序与重复头（多个 Cookie 等
    在用 dict 时会被吞掉，报文就不忠实了）。首个空行或首个非头行开始算 body。
    """
    headers = []
    body_lines = []
    in_body = False
    for line in lines:
        if not in_body:
            if not line.strip():
                in_body = True
                continue
            # Content-Disposition: form-data 是表单分部头，不是请求头。
            # payload 里常直接写它（省掉 Content-Type 与分隔线），
            # 当成请求头就会被留在头区，multipart 补全识别不到分部。
            if _PART_DISPOSITION_RE.match(line):
                in_body = True
                body_lines.append(line)
                continue
            match = _HEADER_LINE_RE.match(line)
            if match:
                headers.append((match.group(1), (match.group(2) or '').strip()))
                continue
            in_body = True  # 非头行 → 从这里开始是主体
        body_lines.append(line)

    # 去掉尾部空行（多为复制时带入）
    while body_lines and not body_lines[-1].strip():
        body_lines.pop()
    return headers, '\r\n'.join(body_lines)


def _default_content_type(body: str, default: str) -> str:
    """
    有主体但没声明 Content-Type 时用的类型，按请求/响应各给一个固定值。

    不做内容推断（``{`` → application/json、``<`` → text/html 那套）。
    实测 Suricata 的 http.request_body 不看声明的类型，同一段正文换个
    Content-Type 命中结果完全一样，所以"猜得准"换不到任何额外命中；
    而猜错的代价是报文声明与实际不符，别处引用这份 PCAP 时要多解释一层。

    :param body: 请求或响应主体（当前不看，保留调用点一致性）
    :param default: 该方向的兜底类型
    """
    return default


def _new_part(attrs: dict, bare: bool = False) -> dict:
    """一个表单分部的解析中间态。"""
    return {
        'attrs': attrs,          # 有序 dict：name / filename
        'headers': [],           # 分部自己的头（Content-Type 等）
        'content': [],           # 分部内容行
        'in_content': False,     # 是否已越过分部头的空行
        'bare': bare,            # 由裸属性行建立的（可能还要并入下一个属性行）
    }


def _is_part_start(line: str) -> bool:
    """这一行能开一个新分部吗：完整 Content-Disposition 或裸 name/filename。"""
    return bool(_PART_DISPOSITION_RE.match(line) or _BARE_PART_RE.match(line))


def _parse_parts(lines: list, declared_boundary: str = ''):
    """
    把请求体切成表单分部。

    认作分部起点的两种写法（payload 里都常见）：
    - ``Content-Disposition: form-data; name="f"; filename="1.php"``
    - 裸属性行 ``name="f"`` / ``filename="1.php"``

    连续的裸属性行合并成一个分部：``name="Filedata"`` 下一行 ``filename="1.aspx"``
    是同一个字段的两个属性，不是两个字段。

    第一个分部起点之前的非空行收进 ``preamble``：它们在 RFC 2046 里是合法的
    前言区，原样保留在首条分隔线之前，一个字不丢。早先的实现把这些行直接
    丢弃，于是 ``field1=value1`` 写在 ``filename="1.php"`` 前面时会静默消失。

    ``--xxx`` 行的判定分两种情形，因为单看长相分不清分隔线与内容：

    - 报文头声明了 boundary：只认 ``--<boundary>``，其余 ``--xxx`` 一律当内容。
      这是唯一精确的判据。
    - 未声明 boundary：要求该行**紧跟一个分部起点**、且当前分部已有内容。
      "当前分部已有内容"是为了区分这两种字面完全相同的输入：
      ``name="a"`` 后空行接 ``--flag`` 再接 ``name="b"``（--flag 是 a 的内容）
      与 ``name="a"`` 后 ``aaa`` 接 ``--sep`` 再接 ``name="b"``（--sep 是分隔线）。

    :param lines: 请求体按 CRLF 切开的行
    :param declared_boundary: 报文头 Content-Type 里声明的 boundary，没有则空串
    :return: (preamble 行列表, 分部列表, 确认过的分隔线或 None)
    """
    preamble = []
    parts = []
    current = None
    seen_boundary = None

    def flush():
        if current:
            parts.append(current)

    for index, line in enumerate(lines):
        boundary_match = _BOUNDARY_LINE_RE.match(line)
        if boundary_match:
            name = boundary_match.group(1).rstrip('-')
            if declared_boundary:
                # 声明了 boundary：只有它才算分隔线，其余 -- 行是内容
                if name == declared_boundary:
                    seen_boundary = declared_boundary
                    continue
            else:
                follows = next(
                    (nxt for nxt in lines[index + 1:] if nxt.strip()), '',
                )
                has_content = current is not None and current['content']
                if _is_part_start(follows) and has_content:
                    seen_boundary = name
                    continue

        disposition = _PART_DISPOSITION_RE.match(line)
        bare = _BARE_PART_RE.match(line)

        if disposition:
            flush()
            attrs = {key.lower(): value for key, value
                     in _PART_ATTR_RE.findall(disposition.group(1))}
            current = _new_part(attrs)
            continue

        if bare:
            key, value = bare.group(1).lower(), bare.group(2)
            inline = (bare.group(3) or '').strip()
            if key == 'filename' and 'name' not in (current or {}).get('attrs', {}):
                # 只给 filename 时字段名无从得知
                attrs = {'name': DEFAULT_FIELD_NAME, 'filename': value}
            else:
                attrs = {key: value}
            # 上一条裸属性行还没进内容区、且没占这个属性 → 同一分部
            if current and current['bare'] and not current['in_content'] \
                    and not current['headers'] \
                    and not (set(attrs) & set(current['attrs'])):
                current['attrs'].update(attrs)
            else:
                flush()
                current = _new_part(attrs, bare=True)
            if inline:
                current['in_content'] = True
                current['content'].append(inline)
            continue

        if current is None:
            # 第一个分部起点之前：收进前言区，不丢
            if line.strip():
                preamble.append(line)
            continue

        if not current['in_content']:
            if not line.strip():
                current['in_content'] = True
                continue
            if _PART_HEADER_RE.match(line):
                current['headers'].append(line)
                continue
            current['in_content'] = True
        current['content'].append(line)

    flush()
    return preamble, parts, seen_boundary


def _render_part(part: dict, boundary: str) -> str:
    """渲染一个分部：分隔线 + Content-Disposition + 分部头 + 空行 + 内容。"""
    attrs = part['attrs']
    disposition = f'Content-Disposition: form-data; name="{attrs.get("name", DEFAULT_FIELD_NAME)}"'
    if 'filename' in attrs:
        disposition += f'; filename="{attrs["filename"]}"'
    # 尾部的空行是分部头与内容的固定分隔，内容为空时它也照样保留
    lines = [f'--{boundary}', disposition] + part['headers'] + ['']
    if not part['content']:
        return '\r\n'.join(lines)
    return '\r\n'.join(lines) + '\r\n' + '\r\n'.join(part['content'])


def _declared_boundary(headers: list) -> str:
    """报文头 Content-Type 里声明的 boundary；没声明时返回空串。

    不能用 _multipart_boundary 代替：它没有声明时返回 DEFAULT_BOUNDARY，
    与"用户恰好声明了 DEFAULT_BOUNDARY"分不开，而这两种情况在 _parse_parts
    里要走的判定路径不同。
    """
    for name, value in headers:
        if name.lower() == 'content-type':
            declared = _BOUNDARY_RE.search(value)
            if declared:
                return declared.group(1)
            break
    return ''


def _multipart_boundary(headers: list, seen_boundary: str) -> str:
    """
    定分隔串：报文声明的 > 正文里确认过的分隔线 > 固定默认值。

    只认已确认的分隔线（见 _parse_parts）——拿正文里长得像 ``--xxx`` 的行
    当依据，会让文件内容反过来决定报文的分隔线。
    """
    return _declared_boundary(headers) or seen_boundary or DEFAULT_BOUNDARY


def _expand_multipart(headers: list, body: str) -> tuple:
    """
    请求体是表单分部时补成完整 multipart/form-data 报文。

    payload 里常只写 ``filename="1.php"`` 或 ``Content-Disposition: form-data``
    这一截——直接当请求体发出去是个畸形报文，WAF 与 Suricata 都解析不出文件
    上传语义。这里把分隔线、分部头、以及头部 Content-Type 补齐。

    分部内容的字节一律不动，只补结构。第一个分部之前的内容（若用户写了）
    作为前言区原样留在首条分隔线之前——RFC 2046 允许，且丢掉就是改内容。

    :return: (headers, body)，不是表单分部时原样返回
    """
    if not body:
        return headers, body
    preamble, parts, seen_boundary = _parse_parts(
        body.split('\r\n'), _declared_boundary(headers),
    )
    if not parts:
        return headers, body

    boundary = _multipart_boundary(headers, seen_boundary)
    rendered_parts = '\r\n'.join(_render_part(part, boundary) for part in parts)
    preamble_block = '\r\n'.join(preamble)
    if preamble_block:
        # 前言区与首条分隔线之间要用空行隔开，否则会被并进同一个逻辑行
        rebuilt = f'{preamble_block}\r\n\r\n{rendered_parts}\r\n--{boundary}--'
    else:
        rebuilt = f'{rendered_parts}\r\n--{boundary}--'

    # 已有 Content-Type 就地改成 multipart（含用户声明的 boundary），
    # 没有则在 Host 之后插入。位置稳定，重复补全不会改动头部顺序。
    mimetype = f'multipart/form-data; boundary={boundary}'
    result = []
    replaced = False
    for name, value in headers:
        if name.lower() == 'content-type':
            if not replaced:
                result.append((name, mimetype))
                replaced = True
            continue
        result.append((name, value))
    if not replaced:
        insert_at = 1 if result and result[0][0].lower() == 'host' else 0
        result.insert(insert_at, ('Content-Type', mimetype))
    return result, rebuilt


def _ensure_message_headers(
    headers: list, body: str, add_host: bool = True,
    default_type: str = DEFAULT_REQUEST_CONTENT_TYPE,
) -> list:
    """
    补齐 Host / Content-Type / Content-Length，其余头部原样保留原位。

    已有的头部就地改值、缺的才追加——「删掉再追加」会把 Content-Type 挪到
    末尾，"补全一次"与"补全两次"产出不同的头部顺序，扩展就不幂等了。
    """
    length_value = str(len(body.encode('utf-8'))) if body else ''
    result = []
    host_seen = type_seen = length_seen = False
    for name, value in headers:
        lowered = name.lower()
        if lowered == 'content-length':
            length_seen = True
            if length_value:
                result.append((name, length_value))
            continue  # 无主体时丢掉 Content-Length，免得声明了不存在的字节
        if lowered == 'content-type':
            type_seen = True
        elif lowered == 'host':
            host_seen = True
            if add_host and not value.strip():
                # 空的 Host（payload 里只有一行 "Host:"）在 HTTP/1.1 下非法
                value = DEFAULT_HOST
        result.append((name, value))

    if add_host and not host_seen:
        result.insert(0, ('Host', DEFAULT_HOST))
    if body:
        if not type_seen:
            result.append(('Content-Type', _default_content_type(body, default_type)))
        if not length_seen:
            result.append(('Content-Length', length_value))
    return result


def _render(start_line: str, headers: list, body: str) -> str:
    """按 HTTP 报文格式拼接：起始行 + 头部 + 空行 + 主体，行尾统一 CRLF。"""
    lines = [start_line] + [f'{name}: {value}' for name, value in headers]
    return '\r\n'.join(lines) + '\r\n\r\n' + body


def expand_request(payload: str) -> str:
    """
    把简要 payload 扩展为完整 HTTP/1.1 请求报文。

    :param payload: 首行（请求行或路径）+ 可选头部 + 可选主体的片段
    :return: 完整请求报文（CRLF 行尾）；输入为空时返回空串
    """
    if not payload or not payload.strip():
        return ''

    lines = _split_lines(payload)
    while lines and not lines[-1].strip():
        lines.pop()

    method, path = _split_request_line(lines[0].strip())
    headers, body = _split_headers_body(lines[1:])
    # 先补 multipart 结构再补 Content-Length：分隔线与分部头都会改变字节数
    headers, body = _expand_multipart(headers, body)
    headers = _ensure_message_headers(headers, body)
    return _render(f'{method} {path} HTTP/1.1', headers, body)


def expand_response(payload: str) -> str:
    """
    把简要响应片段补成完整 HTTP 响应报文。

    :param payload: 状态行（HTTP/1.1 200 OK 或裸 200）、头部与主体，或纯主体
    :return: 完整响应报文（CRLF 行尾）；输入为空时返回空串
    """
    if not payload or not payload.strip():
        return ''

    lines = _split_lines(payload)
    while lines and not lines[-1].strip():
        lines.pop()

    first = lines[0].strip()
    if _RESPONSE_LINE_RE.match(first):
        status_line, rest = first, lines[1:]
    elif _STATUS_CODE_RE.match(first):
        match = _STATUS_CODE_RE.match(first)
        code = match.group(1)
        reason = (match.group(2) or STATUS_REASONS.get(code, '')).strip()
        status_line = f'HTTP/1.1 {code} {reason}'.rstrip()
        rest = lines[1:]
    else:
        # 纯主体：整体当作 200 响应内容
        status_line, rest = 'HTTP/1.1 200 OK', lines

    headers, body = _split_headers_body(rest)
    headers = _ensure_message_headers(
        headers, body, add_host=False, default_type=DEFAULT_RESPONSE_CONTENT_TYPE,
    )
    if not any(name.lower() == 'connection' for name, _ in headers):
        headers.append(('Connection', 'close'))
    return _render(status_line, headers, body)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    demo = '''POST /admin/import/export.php HTTP/1.1
errorReportPath=../../../../inc/td_config.php'''
    logger.info(expand_request(demo))
    logger.info('---')
    logger.info(expand_response('404'))
