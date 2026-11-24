# -*- coding: utf-8 -*-
"""web_apps 回归自测：验证 2026-09-30 修复的四个缺陷。

覆盖：
1. 模板解析保留原始字节（hex/base64 不再被 Latin-1→UTF-8 变形）
2. HTTP Content-Length / TCP ACK 按字节长度计算（中文报文）
3. creat_http_pcap 输出路径落在 utils.PCAP_DIR（下载不再 404）
4. run2 Detect 流程：不删除 sdbCrypt 本体、输出走 huoyan.sdb、
   子进程用 cwd= 不改本进程工作目录

用法（On Demand，tests/test_web_apps_regression.py 以子进程调用）：
    uv run python suricata_tools/web_apps/regression_selftest.py
退出码 0 = 全部通过。

注意：web_apps 模块平铺导入（`from utils import ...`），与仓库根 `utils/` 包同名，
只能在以 web_apps 为 cwd 的独立进程里导入，不能并入 pytest 同进程。
"""

import os
import sys
import tempfile
from pathlib import Path

FAILURES = []


def check(name, cond, detail=""):
    """记录单项断言结果。"""
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(f"{name}: {detail}")


def test_parse_templates():
    """模板解析返回 bytes，原始字节不变形。"""
    from utils import parse_templates

    check("hex 模板保留原始字节", parse_templates("{{hex(ff)}}") == b"\xff",
          f"实际值 {parse_templates('{{hex(ff)}}')!r}，期望 b'\\xff'")
    check("hex 模板替换全部同串出现",
          parse_templates("AB{{hex(ff)}}CD{{hex(ff)}}") == b"AB\xffCD\xff")
    check("base64 模板保留原始字节", parse_templates("{{base64(aGk=)}}") == b"hi")
    check("无模板文本按 UTF-8 编码", parse_templates("中文") == "中文".encode("utf-8"))
    check("非法模板原样返回",
          parse_templates("{{hex(zz)}}") == "{{hex(zz)}}".encode("utf-8"))
    # 中文与模板混排：文本段 UTF-8、模板段原样
    mixed = parse_templates("中文{{hex(80)}}")
    check("混排内容各段编码正确", mixed == "中文".encode("utf-8") + b"\x80",
          f"实际值 {mixed!r}")


def test_content_length_bytes():
    """Content-Length 按 UTF-8 字节数计算。"""
    from pcaps_create import fix_content_length, fix_response_content_length

    req = fix_content_length("POST /a HTTP/1.1\r\nContent-Length: 2\r\n\r\n中文")
    resp = fix_response_content_length("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n中文")
    check("fix 函数输出类型为 bytes", isinstance(req, bytes) and isinstance(resp, bytes),
          f"req={type(req).__name__}, resp={type(resp).__name__}")

    # 旧实现返回 str，统一转 bytes 后再定位头部
    req_b = req if isinstance(req, bytes) else req.encode("utf-8")
    resp_b = resp if isinstance(resp, bytes) else resp.encode("utf-8")
    check("请求 Content-Length 修正为字节数", b"Content-Length: 6" in req_b,
          f"实际输出 {req_b!r}")
    check("响应 Content-Length 修正为字节数", b"Content-Length: 6" in resp_b,
          f"实际输出 {resp_b!r}")


def test_creat_http_pcap():
    """生成路径正确、载荷字节原样、TCP 序列号按字节长度推进。"""
    from scapy.layers.inet import TCP
    from scapy.utils import rdpcap

    from pcaps_create import creat_http_pcap, fix_content_length
    from utils import PCAP_DIR, parse_templates

    req = fix_content_length(parse_templates("POST /a HTTP/1.1\r\nContent-Length: 2\r\n\r\n中文"))
    resp = parse_templates("HTTP/1.1 200 OK\r\n\r\n{{hex(ff)}}")
    # 旧实现可能返回 str，统一成 bytes 送入生成器
    req = req if isinstance(req, bytes) else req.encode("utf-8")
    resp = resp if isinstance(resp, bytes) else resp.encode("utf-8")

    path = creat_http_pcap(request_str=req, response_str=resp, pcapname="regself")

    expected = os.path.join(PCAP_DIR, "regself.pcap")
    check("PCAP 写入 PCAP_DIR（下载可见）", path == expected and os.path.isfile(path),
          f"返回 {path}，期望 {expected}")

    pkts = rdpcap(path)
    # 包序：SYN, SYN-ACK, ACK, 请求, 请求ACK, 响应, FIN, ...
    req_pkt, req_ack, resp_pkt, fin_pkt = pkts[3], pkts[4], pkts[5], pkts[6]
    check("请求载荷字节原样（含中文 UTF-8）", bytes(req_pkt[TCP].payload) == req,
          f"实际 {bytes(req_pkt[TCP].payload)!r}")
    check("请求 ACK 按字节长度推进", req_ack[TCP].ack == req_pkt[TCP].seq + len(req),
          f"ack={req_ack[TCP].ack}, seq+len={req_pkt[TCP].seq + len(req)}")
    check("响应载荷保留模板原始字节 \\xff", bytes(resp_pkt[TCP].payload) == resp,
          f"实际 {bytes(resp_pkt[TCP].payload)!r}")
    check("FIN 对响应的 ACK 按字节长度推进", fin_pkt[TCP].ack == resp_pkt[TCP].seq + len(resp),
          f"ack={fin_pkt[TCP].ack}, seq+len={resp_pkt[TCP].seq + len(resp)}")

    # pcapname 自带 .pcap 时不再重复追加扩展名
    path_with_ext = creat_http_pcap(request_str=req, response_str=resp, pcapname="regself.pcap")
    check("pcapname 已带 .pcap 时不产生双重扩展名", path_with_ext == expected,
          f"返回 {path_with_ext}，期望 {expected}")


def test_empty_response_fallback():
    """响应体为空/纯空白时，用 DEFAULT_RESPONSE_BODY 生成可解析的 PCAP。"""
    import re
    from urllib.parse import unquote

    from scapy.layers.inet import TCP
    from scapy.utils import rdpcap

    import generate_pcap
    from app import app
    from generate_pcap import DEFAULT_RESPONSE_BODY
    from utils import PCAP_DIR

    client = app.test_client()
    default_body = DEFAULT_RESPONSE_BODY.rsplit("\r\n\r\n", 1)[1].encode("utf-8")

    def generate_pcap_file(response_value):
        """提交生成表单，返回 (响应对象, 落盘路径, 响应包 payload, 文件名)。"""
        r = client.post('/generate_pcap', data={
            'generate': '1',
            'request_body': 'GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n',
            'response_body': response_value,
            'file_name': '',
        })
        if r.status_code != 302:
            return r, None, b'', ''
        filename = unquote(r.headers.get('Location', '').rsplit('/', 1)[-1])
        path = os.path.join(PCAP_DIR, filename)
        if not os.path.isfile(path):
            return r, path, b'', filename
        # 包序：SYN, SYN-ACK, ACK, 请求, 请求ACK, 响应, FIN, ...
        payload = bytes(rdpcap(path)[5][TCP].payload)
        return r, path, payload, filename

    # inc_gen_count 会写仓库内的 gen_count.json，测试期间替换为无副作用实现
    original_inc = generate_pcap.inc_gen_count
    generate_pcap.inc_gen_count = lambda name: 0
    try:
        for label, response_value in (("空响应", ""), ("纯空白响应", " \r\n\t\n")):
            r, path, payload, filename = generate_pcap_file(response_value)
            check(f"{label}时生成成功并跳转下载", r.status_code == 302 and path and os.path.isfile(path),
                  f"status={r.status_code}, path={path}")
            check(f"{label}时文件名只有单一 .pcap 扩展名",
                  filename.endswith(".pcap") and not filename.endswith(".pcap.pcap"),
                  f"实际文件名 {filename}")
            check(f"{label}时响应为合法 HTTP 报文", payload.startswith(b"HTTP/1.1 200 OK"),
                  f"实际 payload 前 32 字节 {payload[:32]!r}")
            check(f"{label}时响应体为 DEFAULT_RESPONSE_BODY", payload.endswith(default_body),
                  f"实际 payload {payload!r}")
            header, _, body = payload.partition(b"\r\n\r\n")
            match = re.search(rb"Content-Length: (\d+)", header)
            check(f"{label}时 Content-Length 与默认响应体字节数一致",
                  match is not None and int(match.group(1)) == len(body),
                  f"header={header!r}, body_len={len(body)}")

        # 非空响应仍按用户输入生成，回退不覆盖
        _, _, payload, _ = generate_pcap_file("HTTP/1.1 404 Not Found\r\n\r\ncustom-body")
        check("非空响应不被默认值覆盖",
              payload.startswith(b"HTTP/1.1 404 Not Found") and payload.endswith(b"custom-body"),
              f"实际 payload {payload!r}")
    finally:
        generate_pcap.inc_gen_count = original_inc


def test_expand_endpoint():
    """/generate_pcap/expand：简要 payload 就地补成完整报文。"""
    import generate_pcap
    from app import app
    from generate_pcap import DEFAULT_RESPONSE_BODY

    client = app.test_client()

    # 请求侧：只给请求行 + 表单体，Host/Content-Type/Content-Length 全补
    r = client.post('/generate_pcap/expand', data={
        'kind': 'request',
        'payload': 'POST /admin/export.php HTTP/1.1\nerrorReportPath=../../etc/passwd',
    })
    data = r.get_json() or {}
    content = data.get('content', '')
    check('请求片段被补全', r.status_code == 200 and data.get('changed') is True,
          f"status={r.status_code}, data={data}")
    check('请求补全后含 Host', 'Host: yixuan.com' in content, f"实际 {content!r}")
    expected_len = len('errorReportPath=../../etc/passwd')
    check('请求补全后含正确 Content-Length',
          f'Content-Length: {expected_len}' in content, f"实际 {content!r}")

    # 已是完整请求行的不改写
    complete = 'GET /a HTTP/1.1\r\nHost: h\r\n\r\n'
    r = client.post('/generate_pcap/expand', data={'kind': 'request', 'payload': complete})
    data = r.get_json() or {}
    check('完整请求不重复补全',
          data.get('changed') is False and data.get('content') == complete,
          f"data={data}")

    # 响应侧：只给状态码
    r = client.post('/generate_pcap/expand', data={'kind': 'response', 'payload': '404'})
    data = r.get_json() or {}
    check('响应状态码补成状态行',
          data.get('content', '').startswith('HTTP/1.1 404 Not Found\r\n'),
          f"实际 {data.get('content')!r}")
    check('响应补全后不含 Host',
          'Host:' not in data.get('content', ''), f"实际 {data.get('content')!r}")

    # 纯响应体补成 200
    r = client.post('/generate_pcap/expand', data={'kind': 'response', 'payload': '<p>hi</p>'})
    data = r.get_json() or {}
    check('纯响应体补成 200',
          data.get('content', '').startswith('HTTP/1.1 200 OK\r\n'),
          f"实际 {data.get('content')!r}")

    # 参数校验
    check('空内容被拒', client.post('/generate_pcap/expand',
                                data={'kind': 'request', 'payload': '  '}).status_code == 400)
    check('非法 kind 被拒', client.post('/generate_pcap/expand',
                                    data={'kind': 'x', 'payload': 'a'}).status_code == 400)

    # 请求框里粘着"请求 + 响应"连体：拆开，响应走 split_response
    r = client.post('/generate_pcap/expand', data={
        'kind': 'request',
        'payload': 'GET /index?p=1 HTTP/1.1\n\n200\n11111111',
    })
    data = r.get_json() or {}
    split_request = data.get('content', '')
    split_response = data.get('split_response', '')
    check('连体 payload 的请求只剩请求',
          split_request.startswith('GET /index?p=1 HTTP/1.1\r\n')
          and 'Host: yixuan.com' in split_request
          and '200' not in split_request.split('\r\n\r\n', 1)[1],
          f"实际 {split_request!r}")
    check('连体 payload 的响应被拆出并补状态行',
          split_response.startswith('HTTP/1.1 200 OK\r\n'),
          f"实际 {split_response!r}")
    check('拆出的响应体保留原内容',
          split_response.endswith('\r\n\r\n11111111'), f"实际 {split_response!r}")
    check('拆出的响应 Content-Length 与响应体字节数一致',
          'Content-Length: 8' in split_response.split('\r\n\r\n', 1)[0],
          f"实际 {split_response!r}")
    check('无响应片段时 split_response 为空',
          (client.post('/generate_pcap/expand', data={
              'kind': 'request', 'payload': 'POST /x\nx=1',
          }).get_json() or {}).get('split_response') == '')

    # 表单分部标记补成完整 multipart/form-data
    r = client.post('/generate_pcap/expand', data={
        'kind': 'request',
        'payload': 'POST /index?p=1 HTTP/1.1\nfilename="1.php"',
    })
    multipart_req = (r.get_json() or {}).get('content', '')
    import re as _re

    mp_head, _, mp_body = multipart_req.partition('\r\n\r\n')
    boundary_match = _re.search(r'boundary=(\S+)', mp_head)
    boundary = boundary_match.group(1) if boundary_match else ''
    check('裸 filename 补成 multipart Content-Type',
          bool(boundary), f"实际 {mp_head!r}")
    check('补出的边界与正文分隔线一致',
          bool(boundary) and mp_body.startswith(f'--{boundary}')
          and mp_body.rstrip().endswith(f'--{boundary}--'),
          f"boundary={boundary!r}, body={mp_body!r}")
    check('补出 Content-Disposition 且带 filename',
          'Content-Disposition: form-data; name="file"; filename="1.php"' in mp_body,
          f"实际 {mp_body!r}")
    check('multipart 补全幂等',
          (client.post('/generate_pcap/expand', data={
              'kind': 'request', 'payload': multipart_req,
          }).get_json() or {}).get('changed') is False, "二次补全又改动了")

    # 响应框已有内容时不拆：拆出来无处安放，硬拆等于删掉请求框里那段
    kept = client.post('/generate_pcap/expand', data={
        'kind': 'request',
        'payload': 'GET /index?p=1 HTTP/1.1\n\n200\n11111111',
        'response_filled': '1',
    }).get_json() or {}
    check('响应框已填时不拆分内容也不丢',
          kept.get('skipped_split') is True
          and kept.get('content') == 'GET /index?p=1 HTTP/1.1\n\n200\n11111111',
          f"实际 {kept}")

    # 生成链路：请求框里的响应片段顶替空响应框
    _orig_inc = generate_pcap.inc_gen_count
    generate_pcap.inc_gen_count = lambda name: 0
    try:
        r = client.post('/generate_pcap', data={
            'generate': '1',
            'request_body': 'GET /index?p=1 HTTP/1.1\n\n200\n11111111',
            'response_body': '',
            'file_name': 'split_payload_check.pcap',
        })
    finally:
        generate_pcap.inc_gen_count = _orig_inc
    from scapy.layers.inet import TCP as _TCP
    from scapy.utils import rdpcap as _rdpcap

    from utils import PCAP_DIR as _PCAP_DIR
    split_path = os.path.join(_PCAP_DIR, 'split_payload_check.pcap')
    if os.path.isfile(split_path):
        split_pkts = _rdpcap(split_path)
        req_bytes = bytes(split_pkts[3][_TCP].payload)
        resp_bytes = bytes(split_pkts[5][_TCP].payload)
        check('请求包里不含响应片段',
              b'Host: yixuan.com' in req_bytes and b'200 OK' not in req_bytes,
              f"实际 {req_bytes!r}")
        check('请求框拆出的响应进入了响应包',
              resp_bytes.startswith(b'HTTP/1.1 200 OK') and resp_bytes.endswith(b'11111111'),
              f"实际 {resp_bytes!r}")
        check('拆出的响应用了补全后的报文而非默认响应',
              b'11111111' in resp_bytes, f"实际 {resp_bytes!r}")
    else:
        check('连体 payload 能生成 PCAP', False, f"未落盘 {split_path}")

    # 补全结果能走完整生成链路（含默认响应回退）
    original_inc = generate_pcap.inc_gen_count
    generate_pcap.inc_gen_count = lambda name: 0
    try:
        r = client.post('/generate_pcap', data={
            'generate': '1',
            'request_body': content,
            'response_body': '',
            'file_name': '',
        })
        check('补全结果可直接生成 PCAP', r.status_code == 302, f"status={r.status_code}")

        # 生成时服务端自己也补全——兜住"补全请求在途时用户就点了生成"的竞态
        from scapy.layers.inet import TCP
        from scapy.utils import rdpcap

        from utils import PCAP_DIR
        r = client.post('/generate_pcap', data={
            'generate': '1',
            'request_body': 'POST /race.php HTTP/1.1\nx=1',   # 未补全的片段
            'response_body': '',
            'file_name': 'race_check.pcap',
        })
        race_path = os.path.join(PCAP_DIR, 'race_check.pcap')
        payload = bytes(rdpcap(race_path)[3][TCP].payload) if os.path.isfile(race_path) else b''
        check('生成时自动补全未补全的请求片段',
              r.status_code == 302 and b'Host: yixuan.com' in payload
              and b'Content-Length: 3' in payload,
              f"status={r.status_code}, payload={payload!r}")
    finally:
        generate_pcap.inc_gen_count = original_inc
    check('默认响应常量非空', bool(DEFAULT_RESPONSE_BODY.strip()))


def test_run2_flow():
    """Detect 流程：不删加密工具本体、输出走 huoyan.sdb、cwd= 隔离、串行锁。"""
    import run2
    import surui_de

    tmp = Path(tempfile.mkdtemp(prefix="regself_detect_"))
    bin_dir = tmp / "detectbin"
    (bin_dir / "log").mkdir(parents=True)
    (bin_dir / "pcap").mkdir()
    # 伪造 Detect 安装目录：工具本体 + 打包素材 + 上次运行的残留
    (bin_dir / "sdbCrypt").write_bytes(b"FAKE-BIN")
    (bin_dir / "Detect").write_bytes(b"FAKE-BIN")
    (bin_dir / "classification.sdb").write_bytes(b"cls")
    (bin_dir / "reference.sdb").write_bytes(b"ref")
    (bin_dir / "stale.rules").write_text("old")
    (bin_dir / "huoyan.sdb").write_bytes(b"stale-output")
    (bin_dir / "log" / "old.json").write_text("old")
    rules_file = tmp / "r.rules"
    rules_file.write_text('alert tcp any any -> any any (msg:"t"; sid:1;)')
    pcaps_file = tmp / "p.pcap"
    pcaps_file.write_bytes(b"fake")

    surui_de.detect_path = {"bin_": str(bin_dir)}

    calls = []

    def fake_run(cmd, timeout=None, cwd=None, **kwargs):
        """记录调用参数；模拟 Detect 写出 eve.json。"""
        calls.append((list(cmd), cwd))
        if str(cmd[0]).endswith("Detect"):
            (bin_dir / "log" / "eve.json").write_text('{"alerts": []}', encoding="utf-8")

        class _Result:
            returncode = 0

        return _Result()

    original_run = run2.subprocess.run
    run2.subprocess.run = fake_run
    cwd_before = os.getcwd()
    # H-1 修复后 run2 强制 rules_file 必须在 _RULES_DIR 下、pcaps_file 必须在
    # _PCAP_DIR 下。test 用了独立临时目录（不在 main() 设置的 PCAP_DIR/RULES_DIR
    # 下），所以把 run2 的安全基线指到 test 自己的 tmp，再在 try/finally 还原。
    # 重要：必须用 realpath——macOS 上 /var/folders/.../ 是 /private/var/.../ 的
    # 符号链接，run2._is_path_within 不调 realpath，传 raw tmp 会前缀失败。
    original_rules_dir = run2._RULES_DIR
    original_pcap_dir = run2._PCAP_DIR
    run2._RULES_DIR = os.path.realpath(str(tmp))
    run2._PCAP_DIR = os.path.realpath(str(tmp))
    try:
        success, result = run2.main(rules_file=str(rules_file), pcaps_file=str(pcaps_file))
    finally:
        run2.subprocess.run = original_run
        run2._RULES_DIR = original_rules_dir
        run2._PCAP_DIR = original_pcap_dir

    check("run2 不修改本进程工作目录", os.getcwd() == cwd_before,
          f"cwd 由 {cwd_before} 变为 {os.getcwd()}")
    check("所有子进程以 cwd=Detect 目录运行", all(cwd == str(bin_dir) for _, cwd in calls),
          f"实际 cwd 列表 {[c for _, c in calls]}")
    encrypt_cmd = calls[0][0] if calls else []
    check("加密输出指向 huoyan.sdb 而非工具本体",
          encrypt_cmd[-1] == run2.OUTPUT_SDB and encrypt_cmd[0] == "./sdbCrypt",
          f"实际命令 {encrypt_cmd}")
    tar_cmd = next((c for c, _ in calls if c[0] == "tar"), [])
    check("tar 打包包含 huoyan.sdb",
          run2.OUTPUT_SDB in tar_cmd and "./sdbCrypt" not in tar_cmd,
          f"实际命令 {tar_cmd}")
    check("sdbCrypt 工具本体在流程后仍存在", (bin_dir / "sdbCrypt").exists())
    check("陈旧 .rules 残留被清理", not (bin_dir / "stale.rules").exists())
    check("检测成功且返回 eve.json 内容", success and result == '{"alerts": []}',
          f"success={success}, result={result!r}")
    # rules_file 传给子进程前已转为绝对路径（cwd= 切换后仍可寻址）
    check("规则文件以绝对路径传给子进程", calls and os.path.isabs(encrypt_cmd[encrypt_cmd.index("-i") + 1]),
          f"实际命令 {encrypt_cmd}")


def test_suricata_check_page():
    """/suricata_check 页面：状态显示、按钮禁用、悬停提示、POST 服务端拦截。"""
    from app import app
    import suricata_check

    client = app.test_client()

    # 1) 真实环境探测（开发机通常无 Suricata，走缺失分支）
    r = client.get('/suricata_check')
    check('GET /suricata_check 返回 200', r.status_code == 200, f'status={r.status_code}')
    html = r.get_data(as_text=True)

    original_status = suricata_check.get_suricata_status
    try:
        # 2) 强制"未安装"：提示条 + 按钮禁用 + 悬停提示语
        suricata_check.get_suricata_status = lambda: {
            'available': False, 'bin': '/fake/suricata', 'version': ''}
        r = client.get('/suricata_check')
        html = r.get_data(as_text=True)
        check('未安装时页面显示提示条', '未检测到本地 Suricata' in html,
              f'页面片段: {html[:200]!r}')
        btn_html = html.split('id="execute_btn"', 1)[-1][:300]
        check('未安装时 execute 按钮 disabled', 'disabled' in btn_html, f'按钮片段: {btn_html!r}')
        check('按钮携带悬停提示语', '先安装 Suricata' in btn_html, f'按钮片段: {btn_html!r}')

        # 3) disabled 可被绕过（直接 POST）——服务端必须再挡一道
        popen_called = []

        def fail_popen(*args, **kwargs):
            popen_called.append(args)
            raise AssertionError('Suricata 不可用时不应启动子进程')

        original_popen = suricata_check.subprocess.Popen
        suricata_check.subprocess.Popen = fail_popen
        try:
            r = client.post('/suricata_check', data={'execute': '1'})
        finally:
            suricata_check.subprocess.Popen = original_popen
        html = r.get_data(as_text=True)
        check('POST execute 被服务端拦截且不启动子进程',
              not popen_called and '未检测到本地 Suricata' in html,
              f'popen_called={popen_called}')

        # 4) 强制"已安装"：按钮可用、无提示条、显示版本
        suricata_check.get_suricata_status = lambda: {
            'available': True, 'bin': '/usr/bin/suricata', 'version': 'Suricata 7.0.5'}
        r = client.get('/suricata_check')
        html = r.get_data(as_text=True)
        check('已安装时显示版本信息', 'Suricata 7.0.5' in html)
        check('已安装时无未安装提示条', '未检测到本地 Suricata' not in html)
        btn_html = html.split('id="execute_btn"', 1)[-1][:300]
        check('已安装时 execute 按钮可点击', 'disabled' not in btn_html, f'按钮片段: {btn_html!r}')
    finally:
        suricata_check.get_suricata_status = original_status


def test_detect_entry():
    """Detect 入口：未配置时按钮隐藏 + run_detect 不崩溃；配置后按钮显示。"""
    import stat
    from app import app
    import surui_de

    client = app.test_client()

    # 造一个"已安装"的假 Detect 可执行文件
    tmp = Path(tempfile.mkdtemp(prefix="regself_detect_bin_"))
    fake_detect = tmp / "DetectTool"
    fake_detect.write_bytes(b"FAKE")
    fake_detect.chmod(fake_detect.stat().st_mode | stat.S_IXUSR)

    original_bin = surui_de.detect_path.get('bin_', '')
    try:
        # 1) 未配置（bin_ 为空）——两个页面的 Detect 按钮都不渲染
        surui_de.detect_path['bin_'] = ''
        html = client.get('/suricata_check').get_data(as_text=True)
        check('未配置时 suricata 页隐藏 Detect 按钮', '运行 Detect 检查' not in html)
        html = client.get('/detect_check').get_data(as_text=True)
        check('未配置时 detect_check 页隐藏 Detect 按钮', '执行 Detect 检查' not in html)

        # 2) run_detect 直接访问不再 AttributeError 500
        #    H-1 修复后路径必须在 PCAP_DIR/RULES_DIR 下；用 main() 在 tmp
        #    下建的合法目录里的虚拟文件名（不需要真存在——run_detect 在
        #    拒绝 Detect 路径之前先走未配置分支）。
        from utils import RULES_DIR, PCAP_DIR
        r = client.get('/run_detect',
                       query_string={'rule_path': f'{RULES_DIR}/x.rules',
                                     'pcap_path': f'{PCAP_DIR}/y.pcap'})
        body = r.get_data(as_text=True)
        check('run_detect 未配置时不返回 500',
              r.status_code == 200 and '未配置' in body,
              f'status={r.status_code}, body={body[:200]!r}')

        # 3) 绕过前端直接 POST detect 被拦截，不进入 intermediate 跳转
        r = client.post('/suricata_check', data={'detect': '1'})
        body = r.get_data(as_text=True)
        check('suricata POST detect 未配置时被拦截',
              '即将运行 Detect' not in body and '未配置' in body,
              f'body={body[:200]!r}')
        r = client.post('/detect_check', data={'detect': '1', 'file_select': 'a.rules',
                                               'pcap_select': 'b.pcap'})
        body = r.get_data(as_text=True)
        check('detect_check POST 未配置时被拦截',
              '即将运行 Detect' not in body and '未配置' in body,
              f'body={body[:200]!r}')

        # 4) 配置为存在的可执行文件——按钮恢复显示
        surui_de.detect_path['bin_'] = str(fake_detect)
        html = client.get('/suricata_check').get_data(as_text=True)
        check('已配置时 suricata 页显示 Detect 按钮', '运行 Detect 检查' in html)
        html = client.get('/detect_check').get_data(as_text=True)
        check('已配置时 detect_check 页显示 Detect 按钮', '执行 Detect 检查' in html)

        # 5) 配置了路径但文件不存在——同样视为未配置
        surui_de.detect_path['bin_'] = str(tmp / 'not_exist')
        html = client.get('/detect_check').get_data(as_text=True)
        check('bin 路径无效时隐藏 Detect 按钮', '执行 Detect 检查' not in html)
    finally:
        surui_de.detect_path['bin_'] = original_bin


def test_duplicate_sid_handling():
    """重复 sid：原样保存不拦截；本地验证用去重副本，提示带给页面。

    背景：sid 唯一是 Suricata 单机限制。Detect 侧同 sid 全部生效
    （rulelib 实测 5 条 sid 全为 98：ok(5) fail(0)，各自命中）。所以
    不能拿下游引擎的限制去拦上游输入，否则既拒了合法规则集，又让
    "5 条里只测了 1 条"看起来像"其余规则不匹配"。
    """
    import suricata_check

    same_sid = '\n'.join(
        f'alert tcp any any -> any any (msg:"r{i}"; content:"A{i}"; sid:98;)'
        for i in range(5)
    )

    # 1) 组装不拦：5 条原样保留，sid 一个都不改
    content, err = suricata_check._assemble_rules(same_sid)
    check('重复 sid 的规则不被拒绝', err == '', f'err={err!r}')
    check('重复 sid 原样保留不被改号',
          content.count('sid:98;') == 5, f'内容: {content[:200]!r}')

    # 2) 能识别出重复组（用于提示）
    groups = suricata_check._duplicate_sid_groups(content)
    check('重复 sid 组被正确识别',
          groups == {98: [1, 2, 3, 4, 5]}, f'groups={groups!r}')

    # 3) 本地验证副本：sid 全部唯一，其余逐字不动
    rules_dir = os.environ['WEB_APPS_RULES_DIR']
    os.makedirs(rules_dir, exist_ok=True)
    src = os.path.join(rules_dir, 'regself_dup.rules')
    with open(src, 'w', encoding='utf-8') as f:
        f.write(content + '\n')

    path, remap, cleanup = suricata_check._rules_for_local_verify(src)
    try:
        check('本地验证用独立临时副本', path != src, f'path={path!r}')
        with open(src, encoding='utf-8') as f:
            check('原规则文件保持不变', f.read() == content + '\n')
        with open(path, encoding='utf-8') as f:
            rewritten = f.read()
        sids = suricata_check._SID_RE.findall(rewritten)
        check('临时副本里 sid 全部唯一',
              len(sids) == 5 and len(set(sids)) == 5, f'sids={sids}')
        check('临时副本只改 sid，内容不动',
              all(f'content:"A{i}"' in rewritten for i in range(5)),
              f'内容: {rewritten[:200]!r}')
        check('改号记录指向后 4 行',
              [n for n, _o, _x in remap] == [2, 3, 4, 5], f'remap={remap!r}')
        # 4) 临时文件不能出现在用户的下拉列表里
        listed = suricata_check.get_sorted_files(rules_dir, '.rules')
        check('临时副本不在规则列表里',
              not any(n.startswith('.verify-') for n in listed), f'listed={listed}')
    finally:
        for p in (cleanup, src):
            if p and os.path.exists(p):
                os.remove(p)
    check('临时副本已清理', not (cleanup and os.path.exists(cleanup)), f'cleanup={cleanup!r}')

    # 5) 自动分配的 sid 必须互不相同（这几条是不同检测意图，撞号会互相顶掉）
    frags = '\n'.join(f'content:"x{i}"; metadata:service tcp;' for i in range(5))
    auto, _err = suricata_check._assemble_rules(frags)
    auto_sids = suricata_check._SID_RE.findall(auto)
    check('自动分配的 sid 互不相同',
          len(auto_sids) == 5 and len(set(auto_sids)) == 5, f'sids={auto_sids}')


def main():
    # utils 在导入时固化目录配置，环境变量必须先就位
    tmp = tempfile.mkdtemp(prefix="regself_pcap_")
    os.environ["WEB_APPS_PCAP_DIR"] = os.path.join(tmp, "pcapss")
    os.environ["WEB_APPS_RULES_DIR"] = os.path.join(tmp, "ruless")

    for test_fn in (test_parse_templates, test_content_length_bytes,
                    test_creat_http_pcap, test_empty_response_fallback,
                    test_expand_endpoint, test_run2_flow,
                    test_suricata_check_page, test_detect_entry,
                    test_duplicate_sid_handling):
        try:
            test_fn()
        except Exception as exc:  # noqa: BLE001 — 旧代码跑红时不中断整轮
            print(f"[FAIL] {test_fn.__name__} 异常: {exc!r}")
            FAILURES.append(f"{test_fn.__name__} 异常: {exc!r}")

    # 各生成器模块可正常导入（编码链改动未破坏导入期）
    import generate_tcp  # noqa: F401
    import generate_smtp  # noqa: F401

    if FAILURES:
        print(f"\n回归自测失败：{len(FAILURES)} 项")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("\n回归自测全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
