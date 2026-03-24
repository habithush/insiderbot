"""
InsiderScope Bot — 3-Layer Suspicious Activity Scanner
Monitors: Polymarket | CME Futures | Options Flow
Alerts via: Telegram
"""

import os
import time
import logging
import threading
import requests
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import json

# ─────────────────────────────────────────────
# CONFIG — fill these in your Railway env vars
# ─────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID",   "YOUR_CHAT_ID")
POLYGON_API_KEY    = os.getenv("POLYGON_API_KEY",    "YOUR_POLYGON_KEY")   # free tier ok
UW_API_KEY         = os.getenv("UW_API_KEY",         "")                   # optional, Unusual Whales

# ─────────────────────────────────────────────
# THRESHOLDS
# ─────────────────────────────────────────────
POLYMARKET_SCAN_INTERVAL   = 300   # seconds (5 min)
FUTURES_SCAN_INTERVAL      = 60    # seconds (1 min)
OPTIONS_SCAN_INTERVAL      = 300   # seconds (5 min)
CORRELATION_WINDOW_HOURS   = 6     # hours to look for cross-layer matches

POLY_MIN_BET_USDC          = 5_000
POLY_WALLET_AGE_DAYS       = 7
POLY_VOLUME_SPIKE_MULTIPLIER = 8.0
POLY_PROB_JUMP_THRESHOLD   = 0.10  # 10% odds move

FUTURES_VOLUME_MULTIPLIER  = 5.0   # 5x rolling average = alert
FUTURES_PREMARKET_START    = 4     # 4 AM ET
FUTURES_PREMARKET_END      = 9     # 9:30 AM ET

OPTIONS_VOL_OI_RATIO       = 3.0
OPTIONS_MIN_PREMIUM        = 500_000   # $500k notional
OPTIONS_MAX_EXPIRY_DAYS    = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("InsiderScope")

# ─────────────────────────────────────────────
# SHARED STATE — cross-layer correlation engine
# ─────────────────────────────────────────────
alert_log = []          # list of dicts: {layer, ticker/market, signal, ts, score}
sent_alerts = set()     # dedupe key → don't re-alert same event
lock = threading.Lock()

# ─────────────────────────────────────────────
# TELEGRAM
# ─────────────────────────────────────────────
def send_telegram(message: str):
    if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN":
        log.info(f"[TELEGRAM MOCK] {message[:120]}...")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()
    except Exception as e:
        log.error(f"Telegram send failed: {e}")


def build_alert(layer: str, title: str, signals: list[str], score: int,
                extra: str = "", mega: bool = False) -> str:
    icon = "🚨🚨🚨" if mega else ("🚨" if score >= 7 else "⚠️")
    sig_lines = "\n".join(f"  ▸ {s}" for s in signals)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S ET")
    return (
        f"{icon} <b>INSIDERSCOPE ALERT</b> {icon}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"<b>Layer:</b> {layer}\n"
        f"<b>Event:</b> {title}\n"
        f"<b>Score:</b> {score}/10\n"
        f"<b>Signals triggered:</b>\n{sig_lines}\n"
        + (f"<b>Detail:</b> {extra}\n" if extra else "")
        + f"<b>Time:</b> {ts}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 Watch for news within 24-48 hrs"
    )


# ─────────────────────────────────────────────
# LAYER 1 — POLYMARKET SCANNER
# ─────────────────────────────────────────────

GEOPOLITICAL_TAGS = ["politics", "geopolitics", "war", "middle-east", "elections", "trump"]
POLY_GAMMA   = "https://gamma-api.polymarket.com"
POLY_DATA    = "https://data-api.polymarket.com"
POLY_CLOB    = "https://clob.polymarket.com"

def poly_get(path: str, base: str = POLY_GAMMA, params: dict = None) -> dict | list | None:
    try:
        r = requests.get(f"{base}{path}", params=params, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning(f"Polymarket GET {path} failed: {e}")
        return None


def get_geopolitical_markets(limit: int = 50) -> list[dict]:
    """Fetch active geopolitical/politics markets."""
    markets = []
    for tag in ["politics", "geopolitics"]:
        data = poly_get("/markets", params={"tag": tag, "closed": "false", "limit": limit})
        if data:
            if isinstance(data, list):
                markets.extend(data)
            elif isinstance(data, dict) and "markets" in data:
                markets.extend(data["markets"])
    seen = set()
    unique = []
    for m in markets:
        mid = m.get("id") or m.get("conditionId") or m.get("condition_id")
        if mid and mid not in seen:
            seen.add(mid)
            unique.append(m)
    return unique


def get_market_trades(condition_id: str, limit: int = 50) -> list[dict]:
    """Get recent trades for a market."""
    data = poly_get(f"/trades", base=POLY_DATA,
                    params={"market": condition_id, "limit": limit})
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("data", data.get("trades", []))
    return []


def get_wallet_history(address: str) -> list[dict]:
    """Get all trades by a wallet."""
    data = poly_get(f"/activity", base=POLY_DATA,
                    params={"user": address, "limit": 100})
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("data", data.get("activity", []))
    return []


def score_wallet(trade: dict, market: dict) -> tuple[int, list[str]]:
    """Score a wallet trade for insider signals. Returns (score, signals_list)."""
    score = 0
    signals = []

    # Signal 1 — Bet size
    size_usd = float(trade.get("usdcSize", trade.get("size", 0)) or 0)
    if size_usd >= POLY_MIN_BET_USDC:
        score += 2
        signals.append(f"Large bet: ${size_usd:,.0f} USDC")

    # Signal 2 — Wallet age (check via transaction count as proxy)
    maker = trade.get("maker") or trade.get("trader") or trade.get("transactorAddress", "")
    if maker:
        history = get_wallet_history(maker)
        tx_count = len(history)
        if tx_count < 10:
            score += 3
            signals.append(f"Fresh wallet: only {tx_count} lifetime trades")
        elif tx_count < 25:
            score += 1
            signals.append(f"New-ish wallet: {tx_count} trades")

        # Signal 3 — Market concentration (betting in <3 markets)
        market_ids = set()
        for h in history:
            m = h.get("market") or h.get("conditionId") or h.get("condition_id")
            if m:
                market_ids.add(m)
        if len(market_ids) <= 3:
            score += 2
            signals.append(f"Concentrated: only {len(market_ids)} markets ever")

    # Signal 4 — OTM buy (buying YES when probability is very low)
    price = float(trade.get("price", 0) or 0)
    side = trade.get("side", trade.get("outcomeIndex", ""))
    if price > 0 and price < 0.20 and str(side) in ["0", "YES", "yes"]:
        score += 2
        signals.append(f"Low-prob YES bet at {price:.0%} odds (conviction play)")

    # Signal 5 — Market volume spike
    volume_24h = float(market.get("volume24hr", market.get("volume", 0)) or 0)
    if volume_24h > 50_000 and size_usd / volume_24h > 0.05:
        score += 1
        signals.append(f"Trade is {size_usd/volume_24h:.1%} of 24h volume")

    return score, signals


def run_polymarket_scanner():
    log.info("🔵 Polymarket scanner started")
    seen_trades = set()

    while True:
        try:
            markets = get_geopolitical_markets()
            log.info(f"[Polymarket] Scanning {len(markets)} geopolitical markets")

            for market in markets:
                mid = market.get("conditionId") or market.get("condition_id") or market.get("id")
                title = market.get("question") or market.get("title") or "Unknown market"
                if not mid:
                    continue

                # Check probability jump
                prob = None
                prices = market.get("outcomePrices")
                if prices:
                    try:
                        p_list = json.loads(prices) if isinstance(prices, str) else prices
                        prob = float(p_list[0]) if p_list else None
                    except Exception:
                        pass

                trades = get_market_trades(mid, limit=20)
                for trade in trades:
                    trade_id = trade.get("id") or trade.get("transactionHash", "")
                    if trade_id in seen_trades:
                        continue
                    seen_trades.add(trade_id)

                    score, signals = score_wallet(trade, market)
                    if score >= 5:
                        alert_key = f"poly_{trade_id}"
                        with lock:
                            if alert_key not in sent_alerts:
                                sent_alerts.add(alert_key)
                                maker = trade.get("maker") or trade.get("trader", "Unknown")
                                msg = build_alert(
                                    layer="🔮 Polymarket (Prediction Markets)",
                                    title=title,
                                    signals=signals,
                                    score=score,
                                    extra=f"Wallet: {maker[:10]}...{maker[-6:] if len(maker) > 16 else ''}"
                                )
                                send_telegram(msg)
                                log.info(f"[Polymarket] ALERT sent: {title[:60]} score={score}")
                                alert_log.append({
                                    "layer": "polymarket",
                                    "market": title,
                                    "score": score,
                                    "ts": datetime.now(timezone.utc).isoformat()
                                })

        except Exception as e:
            log.error(f"[Polymarket] Scanner error: {e}")

        time.sleep(POLYMARKET_SCAN_INTERVAL)


# ─────────────────────────────────────────────
# LAYER 2 — FUTURES VOLUME SPIKE DETECTOR
# ─────────────────────────────────────────────

FUTURES_TICKERS = {
    "ES": {"name": "S&P 500 eMini", "direction": "LONG = risk-on / ceasefire"},
    "CL": {"name": "WTI Crude Oil",  "direction": "SHORT = ceasefire / peace"},
    "NQ": {"name": "Nasdaq eMini",  "direction": "LONG = risk-on"},
    "GC": {"name": "Gold",          "direction": "SHORT = risk-on"},
}
POLY_BASE = "https://api.polygon.io"


def poly_futures_get(path: str, params: dict = None) -> dict | None:
    if POLYGON_API_KEY == "YOUR_POLYGON_KEY":
        return None
    p = {"apiKey": POLYGON_API_KEY, **(params or {})}
    try:
        r = requests.get(f"{POLY_BASE}{path}", params=p, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning(f"[Polygon] {path} failed: {e}")
        return None


def get_futures_minute_bars(ticker: str, from_dt: datetime, to_dt: datetime) -> list[dict]:
    """Get 1-minute OHLCV bars for a futures ticker."""
    fmt = "%Y-%m-%d"
    data = poly_futures_get(
        f"/v2/aggs/ticker/{ticker}/range/1/minute/{from_dt.strftime(fmt)}/{to_dt.strftime(fmt)}",
        params={"adjusted": "true", "sort": "asc", "limit": 1000}
    )
    if data and "results" in data:
        return data["results"]
    return []


def compute_rolling_avg_volume(bars: list[dict], lookback_bars: int = 5) -> float:
    """Average volume of the last N bars as baseline."""
    if len(bars) < 2:
        return 0
    recent = bars[-lookback_bars-1:-1]  # exclude the last bar (current)
    vols = [b.get("v", 0) for b in recent]
    return sum(vols) / len(vols) if vols else 0


def run_futures_scanner():
    log.info("🟡 Futures scanner started")
    spike_buffer = {}  # ticker -> last spike time

    while True:
        try:
            now_utc = datetime.now(timezone.utc)
            # Convert to ET (UTC-4 during EDT, UTC-5 during EST)
            et_offset = -4  # EDT (March = summer)
            now_et = now_utc + timedelta(hours=et_offset)
            hour_et = now_et.hour

            # Only scan in pre-market window (4 AM - 9:30 AM ET)
            in_premarket = FUTURES_PREMARKET_START <= hour_et < FUTURES_PREMARKET_END

            if not in_premarket:
                log.debug(f"[Futures] Outside pre-market window ({hour_et}:00 ET), skipping")
                time.sleep(FUTURES_SCAN_INTERVAL)
                continue

            if POLYGON_API_KEY == "YOUR_POLYGON_KEY":
                log.info("[Futures] No Polygon key — running in simulation mode")
                time.sleep(FUTURES_SCAN_INTERVAL)
                continue

            spike_detected = {}
            today = now_utc.date()
            from_dt = datetime(today.year, today.month, today.day, tzinfo=timezone.utc)

            for ticker_root, meta in FUTURES_TICKERS.items():
                # Polygon futures format: e.g., /v2/aggs/ticker/C:CLAK25 for crude
                # For stocks/ETFs we use SPY/QQQ as proxies on free tier
                proxy_map = {"ES": "SPY", "CL": "USO", "NQ": "QQQ", "GC": "GLD"}
                ticker = proxy_map.get(ticker_root, ticker_root)

                bars = get_futures_minute_bars(ticker, from_dt, now_utc)
                if len(bars) < 3:
                    continue

                current_vol = bars[-1].get("v", 0)
                avg_vol = compute_rolling_avg_volume(bars, lookback_bars=10)
                if avg_vol == 0:
                    continue

                ratio = current_vol / avg_vol
                log.debug(f"[Futures] {ticker_root}: vol={current_vol} avg={avg_vol:.0f} ratio={ratio:.2f}x")

                if ratio >= FUTURES_VOLUME_MULTIPLIER:
                    spike_detected[ticker_root] = {
                        "ratio": ratio,
                        "volume": current_vol,
                        "avg": avg_vol,
                        "meta": meta,
                        "ticker": ticker
                    }
                    log.info(f"[Futures] SPIKE: {ticker_root} at {ratio:.1f}x avg volume")

            # Check for cross-asset correlation (ES + CL spiking together)
            if len(spike_detected) >= 2:
                tickers_hit = list(spike_detected.keys())
                alert_key = f"futures_{'_'.join(sorted(tickers_hit))}_{now_et.strftime('%Y%m%d%H%M')}"

                with lock:
                    if alert_key not in sent_alerts:
                        sent_alerts.add(alert_key)

                        signals = []
                        for t, info in spike_detected.items():
                            signals.append(
                                f"{info['meta']['name']}: {info['ratio']:.1f}x avg volume "
                                f"({info['volume']:,} vs avg {info['avg']:,.0f})"
                            )
                            signals.append(f"  Direction: {info['meta']['direction']}")

                        # Determine scenario
                        scenario = ""
                        if "ES" in spike_detected and "CL" in spike_detected:
                            scenario = "📈 ES UP + 🛢️ CL DOWN pattern = Likely PEACE/CEASEFIRE bet"
                        elif "ES" in spike_detected and "GC" in spike_detected:
                            scenario = "📈 ES + 🥇 GLD spiking = Risk-on / sanctions relief bet"

                        score = min(10, 5 + len(spike_detected))
                        msg = build_alert(
                            layer="📊 Futures (CME Pre-Market)",
                            title=f"Cross-asset volume spike — {', '.join(tickers_hit)}",
                            signals=signals,
                            score=score,
                            extra=scenario
                        )
                        send_telegram(msg)
                        log.info(f"[Futures] MULTI-SPIKE alert sent: {tickers_hit}")
                        alert_log.append({
                            "layer": "futures",
                            "tickers": tickers_hit,
                            "score": score,
                            "ts": datetime.now(timezone.utc).isoformat()
                        })

            elif len(spike_detected) == 1:
                t, info = list(spike_detected.items())[0]
                alert_key = f"futures_{t}_{now_et.strftime('%Y%m%d%H%M')}"
                with lock:
                    if alert_key not in sent_alerts:
                        sent_alerts.add(alert_key)
                        score = 5
                        msg = build_alert(
                            layer="📊 Futures (CME Pre-Market)",
                            title=f"Single-asset spike — {info['meta']['name']}",
                            signals=[
                                f"Volume {info['ratio']:.1f}x above 10-bar average",
                                f"Current: {info['volume']:,} vs avg {info['avg']:,.0f}",
                                info['meta']['direction']
                            ],
                            score=score,
                        )
                        send_telegram(msg)
                        alert_log.append({
                            "layer": "futures",
                            "tickers": [t],
                            "score": score,
                            "ts": datetime.now(timezone.utc).isoformat()
                        })

        except Exception as e:
            log.error(f"[Futures] Scanner error: {e}")

        time.sleep(FUTURES_SCAN_INTERVAL)


# ─────────────────────────────────────────────
# LAYER 3 — OPTIONS FLOW SCANNER
# ─────────────────────────────────────────────

UW_BASE = "https://api.unusualwhales.com/api"
WATCHLIST = ["SPY", "SPX", "QQQ", "USO", "XLE", "XOP", "GLD"]


def uw_get(path: str, params: dict = None) -> dict | list | None:
    headers = {}
    if UW_API_KEY:
        headers["Authorization"] = f"Bearer {UW_API_KEY}"
    try:
        r = requests.get(f"{UW_BASE}{path}", params=params, headers=headers, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning(f"[UW] GET {path} failed: {e}")
        return None


def get_option_flow(ticker: str, limit: int = 50) -> list[dict]:
    """Fetch recent options flow for a ticker."""
    data = uw_get(f"/stock/{ticker}/option-trades", params={"limit": limit})
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("data", data.get("trades", []))
    return []


def score_option_trade(trade: dict) -> tuple[int, list[str]]:
    """Score an options trade for insider signals."""
    score = 0
    signals = []

    # Signal 1 — Vol/OI ratio
    volume = float(trade.get("volume", 0) or 0)
    oi = float(trade.get("open_interest", trade.get("openInterest", 1)) or 1)
    vol_oi = volume / oi if oi > 0 else 0
    if vol_oi >= OPTIONS_VOL_OI_RATIO:
        score += 3
        signals.append(f"Vol/OI ratio: {vol_oi:.1f}x (new position, not hedge)")

    # Signal 2 — Order type (sweep = urgency)
    order_type = str(trade.get("type", trade.get("saleCondition", ""))).lower()
    if "sweep" in order_type:
        score += 2
        signals.append("Sweep order — executed urgently across multiple exchanges")
    elif "block" in order_type:
        score += 1
        signals.append("Block order — large privately negotiated trade")

    # Signal 3 — Short expiry
    expiry_str = trade.get("expiry", trade.get("expiration_date", ""))
    if expiry_str:
        try:
            expiry = datetime.strptime(expiry_str[:10], "%Y-%m-%d")
            days_to_expiry = (expiry - datetime.now()).days
            if 0 <= days_to_expiry <= OPTIONS_MAX_EXPIRY_DAYS:
                score += 2
                signals.append(f"Expiry in {days_to_expiry}d — short-dated, high conviction")
            elif days_to_expiry == 0:
                score += 3
                signals.append("0DTE — same-day expiry, extreme conviction")
        except Exception:
            pass

    # Signal 4 — Premium size
    premium = float(trade.get("premium", trade.get("totalPremium", 0)) or 0)
    if premium >= OPTIONS_MIN_PREMIUM:
        score += 2
        signals.append(f"Premium: ${premium:,.0f} notional")

    # Signal 5 — OTM call/put
    strike = float(trade.get("strike_price", trade.get("strike", 0)) or 0)
    underlying = float(trade.get("underlying_price", trade.get("spot", 0)) or 0)
    option_type = str(trade.get("put_call", trade.get("type", ""))).upper()
    if strike > 0 and underlying > 0:
        otm_pct = abs(strike - underlying) / underlying
        if otm_pct >= 0.05:
            score += 1
            signals.append(
                f"OTM {option_type}: strike ${strike:.0f} vs spot ${underlying:.0f} "
                f"({otm_pct:.1%} OTM)"
            )

    return score, signals


def get_barchart_flow(ticker: str) -> list[dict]:
    """
    Fallback: scrape Barchart unusual options activity (public page).
    Returns simplified trade dicts when UW is not available.
    """
    try:
        url = f"https://www.barchart.com/options/unusual-activity/{ticker}"
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=15)
        # Barchart blocks scraping — this is a placeholder
        # In production, use their paid API or Unusual Whales
        return []
    except Exception:
        return []


def run_options_scanner():
    log.info("🟢 Options flow scanner started")
    seen_trades = set()

    while True:
        try:
            if not UW_API_KEY:
                log.info("[Options] No UW API key — running in monitor-only mode. Add UW_API_KEY to enable.")
                time.sleep(OPTIONS_SCAN_INTERVAL)
                continue

            for ticker in WATCHLIST:
                trades = get_option_flow(ticker, limit=30)
                log.debug(f"[Options] {ticker}: {len(trades)} trades fetched")

                for trade in trades:
                    trade_id = (
                        trade.get("id") or
                        trade.get("tradeId") or
                        f"{ticker}_{trade.get('expiry','')}_{trade.get('strike','')}_{trade.get('premium','')}"
                    )
                    if trade_id in seen_trades:
                        continue
                    seen_trades.add(trade_id)

                    score, signals = score_option_trade(trade)
                    if score >= 5:
                        alert_key = f"options_{trade_id}"
                        with lock:
                            if alert_key not in sent_alerts:
                                sent_alerts.add(alert_key)
                                msg = build_alert(
                                    layer=f"📈 Options Flow ({ticker})",
                                    title=f"Unusual {trade.get('put_call','?')} activity on {ticker}",
                                    signals=signals,
                                    score=score,
                                    extra=f"Strike: ${trade.get('strike_price', trade.get('strike', '?'))} | "
                                          f"Exp: {trade.get('expiry', trade.get('expiration_date', '?'))}"
                                )
                                send_telegram(msg)
                                log.info(f"[Options] ALERT sent: {ticker} score={score}")
                                alert_log.append({
                                    "layer": "options",
                                    "ticker": ticker,
                                    "score": score,
                                    "ts": datetime.now(timezone.utc).isoformat()
                                })

        except Exception as e:
            log.error(f"[Options] Scanner error: {e}")

        time.sleep(OPTIONS_SCAN_INTERVAL)


# ─────────────────────────────────────────────
# CORRELATION ENGINE — Cross-layer MEGA alert
# ─────────────────────────────────────────────

def run_correlation_engine():
    """
    If 2+ layers fire within CORRELATION_WINDOW_HOURS → MEGA ALERT.
    This is the smoking gun pattern.
    """
    log.info("🔴 Correlation engine started")

    while True:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=CORRELATION_WINDOW_HOURS)
            with lock:
                recent = [
                    a for a in alert_log
                    if datetime.fromisoformat(a["ts"]) > cutoff
                ]

            layers_hit = set(a["layer"] for a in recent)

            if len(layers_hit) >= 2:
                alert_key = f"mega_{'+'.join(sorted(layers_hit))}_{datetime.now().strftime('%Y%m%d%H')}"
                with lock:
                    if alert_key not in sent_alerts:
                        sent_alerts.add(alert_key)

                        layer_summary = []
                        for layer in layers_hit:
                            layer_alerts = [a for a in recent if a["layer"] == layer]
                            layer_summary.append(f"{layer.upper()}: {len(layer_alerts)} signal(s)")

                        msg = build_alert(
                            layer="🔴 CORRELATION ENGINE",
                            title="MULTI-LAYER INSIDER PATTERN DETECTED",
                            signals=layer_summary + [
                                f"All {len(layers_hit)} layers fired within {CORRELATION_WINDOW_HOURS}h",
                                "Historical precedent: Monday's Polymarket + Futures spike → Trump post 15 min later",
                            ],
                            score=10,
                            extra="⚡ HIGH CONFIDENCE — Watch for major announcement within 24-48 hours",
                            mega=True
                        )
                        send_telegram(msg)
                        log.info(f"🔴 MEGA ALERT sent: {layers_hit}")

        except Exception as e:
            log.error(f"[Correlation] Engine error: {e}")

        time.sleep(300)  # check every 5 min


# ─────────────────────────────────────────────
# MAIN — Start all threads
# ─────────────────────────────────────────────

def main():
    log.info("=" * 50)
    log.info("  InsiderScope Bot — Starting up")
    log.info("  Layers: Polymarket | Futures | Options")
    log.info("=" * 50)

    send_telegram(
        "🟢 <b>InsiderScope Bot is LIVE</b>\n\n"
        "Monitoring:\n"
        "  🔮 Polymarket — fresh wallets + geopolitical bets\n"
        "  📊 CME Futures — pre-market volume spikes\n"
        "  📈 Options — sweeps + OTM flows\n"
        "  🔴 Correlation engine — cross-layer MEGA alerts\n\n"
        "Will alert on suspicious activity across all 3 layers."
    )

    threads = [
        threading.Thread(target=run_polymarket_scanner, name="Polymarket", daemon=True),
        threading.Thread(target=run_futures_scanner,    name="Futures",    daemon=True),
        threading.Thread(target=run_options_scanner,    name="Options",    daemon=True),
        threading.Thread(target=run_correlation_engine, name="Correlation", daemon=True),
    ]

    for t in threads:
        t.start()
        log.info(f"Started thread: {t.name}")

    # Keep main thread alive
    try:
        while True:
            alive = [t.name for t in threads if t.is_alive()]
            log.info(f"[Health] Active threads: {alive}")
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("Shutting down InsiderScope Bot...")


if __name__ == "__main__":
    main()
