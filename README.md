# pcapcreate

基于 Flask + Scapy 的 PCAP 流量生成与 Suricata 规则验证工具。在网页上选择模板、填写字段，即可生成自定义 PCAP 文件，并用 Suricata 在线验证检测规则是否命中。

## 功能

### 流量生成

- **HTTP**：内置"标准 GET / 普通 POST / FORM 提交"等请求模板，自定义源 / 目的地址与端口、Host、URI、载荷等字段
- **TCP**：完整的 TCP 会话流量（三次握手、数据传输、四次挥手）
- **UDP**：自定义载荷的单向 / 双向 UDP 流量
- **ICMP**：自定义类型与载荷的 ICMP 报文
- **SMTP**：完整的 SMTP 会话流量（EHLO / MAIL / RCPT / DATA / QUIT）

生成完成后直接通过网页下载 PCAP 文件。

### 检测验证

- **Suricata 校验**：上传或选择 PCAP 与 `.rules` 规则文件，后台调用 Suricata 执行检测，展示告警结果，用于验证规则能否命中目标流量
- **Detect 校验**：对已生成的规则和 PCAP 文件执行 Detect 检测流程并查看结果

### 其他

- 生成的 PCAP 与规则文件每 16 小时自动清理，避免磁盘堆积
- 环境变量配置：`FLASK_HOST`（默认 `0.0.0.0`）、`FLASK_PORT`（默认 `9900`）、`FLASK_DEBUG`（默认 `false`）、`WEB_APPS_BASE_DIR`（文件目录，默认当前目录）
- `/health` 健康检查端点

## 快速开始

```bash
pip install -r requirements.txt
python app.py
```

浏览器访问 `http://localhost:9900`。

依赖：Python 3.x、Flask、Scapy、APScheduler、pytz。Suricata 校验功能需要本机已安装 Suricata。

## Docker 部署

当前 `Dockerfile` 采用间接打包方式：先基于 `python:3.11` 容器安装 Suricata 并部署代码，`docker commit` 为基础镜像（如 `mypcapcreate:v3`），再以该镜像为 `FROM` 构建。

完整步骤见 `Dockerfile` 内注释。镜像就绪后：

```bash
docker build -t topsec/pcapcreate:v2.4 .
docker run -d -p 9900:9900 --name pcapcreate_instance topsec/pcapcreate:v2.4
```

访问 `http://localhost:9900`。

## 贡献

欢迎提交 Issue 和 Pull Request。

## 许可

本项目采用 Apache 2.0 许可证，详情见 [LICENSE](LICENSE)。
