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
    try:
        success, result = run2.main(rules_file=str(rules_file), pcaps_file=str(pcaps_file))
    finally:
        run2.subprocess.run = original_run

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
        r = client.get('/run_detect',
                       query_string={'rule_path': '/tmp/x.rules', 'pcap_path': '/tmp/y.pcap'})
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


def main():
    # utils 在导入时固化目录配置，环境变量必须先就位
    tmp = tempfile.mkdtemp(prefix="regself_pcap_")
    os.environ["WEB_APPS_PCAP_DIR"] = os.path.join(tmp, "pcapss")
    os.environ["WEB_APPS_RULES_DIR"] = os.path.join(tmp, "ruless")

    for test_fn in (test_parse_templates, test_content_length_bytes,
                    test_creat_http_pcap, test_run2_flow,
                    test_suricata_check_page, test_detect_entry):
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
