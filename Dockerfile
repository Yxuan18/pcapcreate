# syntax=docker/dockerfile:1
# web_apps 单阶段镜像 —— 一条 `docker build` 直接出可用镜像
#
# 设计要点：
# 1. 单阶段构建，不再需要「手工 run 容器 → apt install → docker cp →
#    docker commit → 改 FROM」的间接打包流程。
# 2. 必须 Suricata 8.x。应用的规则加载摘要解析要求三段格式
#    `N rules successfully loaded, M rules failed, K rules skipped`；
#    Suricata 7 只输出前两段（实测 Debian trixie 的 7.0.10 截断为
#    `0 rules failed, 0`），`_RULE_LOAD_PATTERN` 匹配不上，
#    `parse_rule_load()` 返回 (None, None)，判定链把每次检测都判成故障态。
#    OISF 官方 PPA 提供 8.0.8，amd64 与 arm64 都有。
# 3. 国内加速：apt 与 pip 均走阿里云。
# 4. 基础镜像固定 ubuntu:24.04（noble），与 OISF PPA 的 noble 仓对应。
#
# 构建：
#     docker build -t topsec/pcapcreate:v2.5 .
# 运行：
#     docker run -d -p 9900:9900 --name pcapcreate topsec/pcapcreate:v2.5
#
# 跨架构构建（例如在 arm64 Mac 上出 amd64 镜像）：
#     docker buildx build --platform linux/amd64 -t topsec/pcapcreate:v2.5 --load .

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ \
    PIP_TRUSTED_HOST=mirrors.aliyun.com

# ── apt：换阿里云源 + 装 Suricata 8（OISF PPA）──
#
# 三个必须按顺序处理的坑，都是实测出来的：
#
# ① 镜像源路径按架构分叉。阿里云的 amd64 归档在 /ubuntu/，arm64 在
#    /ubuntu-ports/。统一换成 /ubuntu/ 会让 arm64 上 apt 索引为空，
#    所有包报 "no installation candidate"。
# ② 基础镜像不含 CA 证书。首次 apt update 走 https 会全部失败于
#    "No system certificates available"。所以先换 http，装好
#    ca-certificates 之后再切回 https。
# ③ add-apt-repository 依赖 software-properties-common；装完 suricata
#    后卸掉，减少镜像体积。
ARG TARGETARCH
RUN set -eux; \
    if [ "$TARGETARCH" = "arm64" ]; then MIRROR_PATH=ubuntu-ports; else MIRROR_PATH=ubuntu; fi; \
    sed -i -E "s#https?://(archive\.ubuntu\.com|security\.ubuntu\.com|ports\.ubuntu\.com)/ubuntu(-ports)?/?#http://mirrors.aliyun.com/${MIRROR_PATH}/#g" \
        /etc/apt/sources.list.d/ubuntu.sources; \
    apt-get -o Acquire::Retries=5 update; \
    apt-get install -y --no-install-recommends \
        ca-certificates gnupg software-properties-common python3 python3-pip; \
    sed -i -E "s#http://mirrors\.aliyun\.com#https://mirrors.aliyun.com#g" \
        /etc/apt/sources.list.d/ubuntu.sources; \
    add-apt-repository -y ppa:oisf/suricata-stable; \
    apt-get -o Acquire::Retries=5 update; \
    apt-get install -y --no-install-recommends suricata; \
    suricata -V; \
    apt-get purge -y software-properties-common; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

# ── Python 依赖 ──
# 版本下限与仓库根 pyproject.toml 一致。--break-system-packages 是因为
# Ubuntu 24.04 的 pip 默认拒绝装进系统环境（PEP 668）。
RUN pip3 install --no-cache-dir --break-system-packages \
        "flask>=3.1.3" "scapy>=2.7.0" "apscheduler>=3.11.2" \
        "werkzeug>=3.1.8" "pytz>=2026.2"

WORKDIR /var/www/web_apps
COPY . /var/www/web_apps/

# pcapss/ruless 在 .dockerignore 里排除，这里建空目录占位
RUN mkdir -p /var/www/web_apps/pcapss /var/www/web_apps/ruless

EXPOSE 9900
# 记得用 app.py 的绝对路径：镜像的 CMD 不保证 cwd 稳定。
# 清理任务默认开启（16h 阈值，WEB_APPS_CLEANUP_HOURS 可调，
# WEB_APPS_CLEANUP_ENABLED=false 可关）。注意它在模块顶层启动，
# 任何 `import app` 都会触发一次——调试时先设 false。
CMD ["python3", "/var/www/web_apps/app.py"]
