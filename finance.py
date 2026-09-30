import datetime as dt
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from flask import Blueprint, jsonify, render_template, request

logger = logging.getLogger(__name__)

finance_bp = Blueprint("finance", __name__)

# -------------------------------------------------------------------
# 行情配置
# -------------------------------------------------------------------
# 港股：Yahoo Finance 港股代码需要带 .HK
# 注意：与 finanical_clash.py 保持同步，优先从那里导入
HK_TICKERS: dict[str, str] = {
    "2818.HK": "潘渡比特币ETF",
    "3085.HK": "潘渡以太币ETF",
    "3056.HK": "潘渡招商创新ETF",
    "3112.HK": "潘渡招商区块链ETF",
    "0700.HK": "腾讯控股",
    "9988.HK": "阿里巴巴",
    "3690.HK": "美团",
}

# 美股
US_TICKERS: dict[str, str] = {
    "AAPL": "苹果公司",
    "TSLA": "特斯拉",
    "NVDA": "英伟达",
    "MSFT": "微软",
    "AMZN": "亚马逊",
    "META": "Meta",
    "MSTR": "MicroStrategy",
    "CRCL": "Circle",
}

# finanical_clash.py 所在目录：当前 finance.py 通常在 web_apps/blueprints 下，doc 在 ../../doc
DOC_DIR = str(Path(__file__).resolve().parents[2] / "doc")

# 页面实时刷新不要每次都穿透请求外部接口，否则又慢又容易被限流
# 环境变量解析加 try/except，避免非整数值导致启动失败
try:
    CACHE_TTL_SECONDS = int(os.getenv("FINANCE_CACHE_TTL_SECONDS", "20"))
except (ValueError, TypeError):
    CACHE_TTL_SECONDS = 20

try:
    MAX_WORKERS = int(os.getenv("FINANCE_MAX_WORKERS", "8"))
except (ValueError, TypeError):
    MAX_WORKERS = 8

# 代理配置：从环境变量读取，默认走本地代理
_PROXY_HTTP = os.getenv("FINANCE_PROXY_HTTP", "socks5://127.0.0.1:7890")
_PROXY_HTTPS = os.getenv("FINANCE_PROXY_HTTPS", "socks5://127.0.0.1:7890")
PROXIES: dict[str, str] = {"http": _PROXY_HTTP, "https": _PROXY_HTTPS}

_CACHE: dict[str, Any] = {
    "data": None,
    "expires_at": 0.0,
}
_CACHE_LOCK = Lock()


# -------------------------------------------------------------------
# 通用工具
# -------------------------------------------------------------------
def _ensure_doc_path() -> None:
    """把 doc 目录加入 sys.path，保证可以导入 finanical_clash.py。"""
    if DOC_DIR not in sys.path:
        sys.path.append(DOC_DIR)


def _now_iso() -> str:
    """返回本地时间字符串，给前端展示更新时间。"""
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _get_beijing_hour() -> int:
    """获取当前北京时间的小时数 (0-23)。"""
    beijing_tz = dt.timezone(dt.timedelta(hours=8))
    return dt.datetime.now(beijing_tz).hour


def _get_priority_market() -> str:
    """
    根据北京时间返回优先显示的市场。

    - 06:00-17:59 → 港股优先
    - 18:00-05:59 → 美股优先
    """
    hour = _get_beijing_hour()
    return "hk" if 6 <= hour < 18 else "us"


def _to_float(value: Any) -> float | None:
    """安全转 float；失败返回 None，不用 0 冒充真实价格。"""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _round_or_none(value: Any, digits: int = 4) -> float | None:
    """安全转 float 并四舍五入。"""
    number = _to_float(value)
    return round(number, digits) if number is not None else None


def _call(name: str, func: Callable[[], Any], errors: list[dict[str, str]]) -> Any:
    """统一捕获外部接口异常，避免 Flask 接口直接 500。"""
    try:
        return func()
    except Exception as exc:  # noqa: BLE001
        logger.exception("%s 获取失败: %s", name, exc)
        errors.append({"target": name, "message": str(exc)})
        return None


def _normalize_stock_item(ticker: str, display_name: str, raw: Any) -> dict[str, Any]:
    """
    将 finanical_clash.fetch_from_yahoo_ / get_stock_prices 返回值整理成稳定结构。

    返回结构固定，前端不用猜字段：
    {
      ticker, name, price, change, pct, source, ok
    }
    """
    raw = raw or {}
    price = _round_or_none(raw.get("price"), 4)
    change = _round_or_none(raw.get("change"), 4)
    pct = _round_or_none(raw.get("pct"), 6)

    return {
        "ticker": ticker,
        "name": raw.get("name") or display_name,
        "price": price,
        "change": change,
        "pct": pct,
        "source": "Yahoo Finance",
        "ok": price is not None,
    }


# -------------------------------------------------------------------
# 具体取数逻辑
# -------------------------------------------------------------------
def fetch_stocks(tickers: dict[str, str]) -> dict[str, dict[str, Any]]:
    """
    并发获取股票/ETF行情。

    这里优先复用 finanical_clash.py 里的 fetch_from_yahoo_，
    但不用它的 get_stock_prices，因为原方法每个 ticker 之间 sleep 1~2.5 秒，
    放在网页接口里会明显拖慢。
    """
    _ensure_doc_path()
    from finanical_clash import fetch_from_yahoo_  # type: ignore

    result: dict[str, dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(1, len(tickers)))) as executor:
        future_map = {
            executor.submit(fetch_from_yahoo_, ticker, name): (ticker, name)
            for ticker, name in tickers.items()
        }

        for future in as_completed(future_map):
            ticker, name = future_map[future]
            try:
                raw = future.result()
                result[ticker] = _normalize_stock_item(ticker, name, raw)
            except Exception as exc:  # noqa: BLE001
                logger.exception("股票 %s 获取失败: %s", ticker, exc)
                result[ticker] = {
                    "ticker": ticker,
                    "name": name,
                    "price": None,
                    "change": None,
                    "pct": None,
                    "source": "Yahoo Finance",
                    "ok": False,
                    "error": str(exc),
                }

    # 按配置顺序返回，避免前端每次顺序乱跳
    return {ticker: result[ticker] for ticker in tickers.keys() if ticker in result}


def fetch_btc() -> dict[str, Any]:
    """获取 BTC 美元价格。"""
    _ensure_doc_path()
    from finanical_clash import get_btc_price  # type: ignore

    price = _round_or_none(get_btc_price(), 2)
    return {
        "symbol": "BTC",
        "name": "Bitcoin",
        "price": price,
        "currency": "USD",
        "source": "CoinGecko / BOX fallback",
        "ok": price is not None,
    }


def fetch_box() -> dict[str, Any]:
    """获取 BOX 单份净值。"""
    _ensure_doc_path()
    from finanical_clash import get_box_price_placeholder  # type: ignore

    price = _round_or_none(get_box_price_placeholder(), 4)
    return {
        "symbol": "BOX",
        "name": "BOX",
        "price": price,
        "currency": "USD",
        "source": "b.watch safe-api",
        "ok": price is not None,
    }


def fetch_fx() -> dict[str, dict[str, Any]]:
    """获取汇率。"""
    _ensure_doc_path()
    from finanical_clash import get_fx_rates  # type: ignore

    raw = get_fx_rates() or {}

    # 兼容两种 key 风格：USD_CNY / USDCNY
    pairs = {
        "USD_CNY": raw.get("USD_CNY", raw.get("USDCNY")),
        "USD_HKD": raw.get("USD_HKD", raw.get("USDHKD")),
        "HKD_CNY": raw.get("HKD_CNY", raw.get("HKDCNY")),
    }

    return {
        pair: {
            "pair": pair.replace("_", "/"),
            "rate": _round_or_none(rate, 4),
            "source": "v2.xxapi.cn",
            "ok": _to_float(rate) is not None,
        }
        for pair, rate in pairs.items()
    }


def build_finance_payload() -> dict[str, Any]:
    """
    构建完整行情 payload。

    注意：失败就返回 None + errors，不再用 0 / 固定汇率伪装成真实数据。
    """
    start = time.perf_counter()
    errors: list[dict[str, str]] = []

    hk_stocks = _call("港股", lambda: fetch_stocks(HK_TICKERS), errors) or {}
    us_stocks = _call("美股", lambda: fetch_stocks(US_TICKERS), errors) or {}
    btc = _call("BTC", fetch_btc, errors) or {
        "symbol": "BTC",
        "price": None,
        "currency": "USD",
        "ok": False,
    }
    box = _call("BOX", fetch_box, errors) or {
        "symbol": "BOX",
        "price": None,
        "currency": "USD",
        "ok": False,
    }
    fx = _call("汇率", fetch_fx, errors) or {}

    stock_values = list(hk_stocks.values()) + list(us_stocks.values())
    stock_failed = [
        item["ticker"]
        for item in stock_values
        if not item.get("ok")
    ]

    if stock_failed:
        errors.append({
            "target": "stocks",
            "message": "以下标的未获取到有效价格: " + ", ".join(stock_failed),
        })

    # 根据北京时间确定优先显示的市场
    priority_market = _get_priority_market()

    # 构建排序后的 all 股票列表
    # 优先市场放在前面，非优先市场放在后面
    if priority_market == "hk":
        ordered_tickers = list(HK_TICKERS.keys()) + list(US_TICKERS.keys())
    else:
        ordered_tickers = list(US_TICKERS.keys()) + list(HK_TICKERS.keys())

    # 按排序后的 ticker 顺序构建 all 字典
    all_stocks_ordered: dict[str, Any] = {}
    for ticker in ordered_tickers:
        if ticker in hk_stocks:
            all_stocks_ordered[ticker] = hk_stocks[ticker]
        elif ticker in us_stocks:
            all_stocks_ordered[ticker] = us_stocks[ticker]

    payload = {
        "success": len(errors) == 0,
        "updated_at": _now_iso(),
        "elapsed_ms": round((time.perf_counter() - start) * 1000, 2),
        "cache_ttl_seconds": CACHE_TTL_SECONDS,
        # 时间相关的优先级信息，供前端参考
        "priority_market": priority_market,
        "beijing_hour": _get_beijing_hour(),
        "stocks": {
            "hk": hk_stocks,
            "us": us_stocks,
            # 使用排序后的字典
            "all": all_stocks_ordered,
        },
        "crypto": {
            "btc": btc,
            "box": box,
        },
        # 兼容旧前端字段
        "btc": btc.get("price"),
        "box": box.get("price"),
        "fx": fx,
        "errors": errors,
    }
    return payload


def get_finance_payload(force_refresh: bool = False) -> dict[str, Any]:
    """带 TTL 缓存的行情获取入口。"""
    now = time.time()

    # 锁内只做缓存读取，避免所有请求串行化
    with _CACHE_LOCK:
        cached_data = _CACHE.get("data")
        if (
            not force_refresh
            and cached_data is not None
            and now < float(_CACHE.get("expires_at", 0))
        ):
            payload = dict(cached_data)
            payload["from_cache"] = True
            return payload

    # 外部请求在锁外执行，真正实现并发
    fresh_data = build_finance_payload()
    fresh_data["from_cache"] = False

    with _CACHE_LOCK:
        _CACHE["data"] = fresh_data
        _CACHE["expires_at"] = time.time() + CACHE_TTL_SECONDS

    return fresh_data


# -------------------------------------------------------------------
# Flask routes
# -------------------------------------------------------------------
@finance_bp.route("/finance")
def finance_home():
    """金融资产监控主页。"""
    return render_template("finance.html", title="金融与资产实时监控")


@finance_bp.route("/api/finance/data")
def finance_data():
    """
    获取所有资产最新行情。

    支持：
    - /api/finance/data          走缓存，适合页面轮询
    - /api/finance/data?force=1  强制刷新，适合手动刷新按钮
    """
    force_refresh = request.args.get("force") in {"1", "true", "yes"}
    status_code = 200

    try:
        payload = get_finance_payload(force_refresh=force_refresh)
    except Exception as exc:  # noqa: BLE001
        logger.exception("行情接口整体失败: %s", exc)
        status_code = 500
        payload = {
            "success": False,
            "updated_at": _now_iso(),
            "from_cache": False,
            "stocks": {"hk": {}, "us": {}, "all": {}},
            "crypto": {
                "btc": {"symbol": "BTC", "price": None, "currency": "USD", "ok": False},
                "box": {"symbol": "BOX", "price": None, "currency": "USD", "ok": False},
            },
            "btc": None,
            "box": None,
            "fx": {},
            "errors": [{"target": "finance_data", "message": str(exc)}],
        }

    return jsonify(payload), status_code
