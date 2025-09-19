# service.py
# --------------------------------------------
# EyeGuard Enrichment Service
# FastAPI + Cache + Local DB + Range Alert + Decision + Alerts (Log/Webhook/SSE)
# --------------------------------------------

import os, time, json, threading, asyncio
from datetime import datetime
from pathlib import Path
from urllib.parse import quote_plus
from typing import Optional, List, Dict, Any

import requests
import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

# ----------------- Paths / Config
BASE_DIR = Path(".")
CACHE_DIRS = {
    "vt":   BASE_DIR / "data/raw/virustotal",
    "abuse":BASE_DIR / "data/raw/abuseipdb",
    "otx":  BASE_DIR / "data/raw/otx",
}
for p in CACHE_DIRS.values():
    p.mkdir(parents=True, exist_ok=True)

LOCAL_DATA_PATH  = BASE_DIR / "data/local/indicators.csv"
LOCAL_INDEX: Optional[Dict[str, Dict[str, Any]]] = None

# ---- Range alert
RANGE_BITS = int(os.getenv("RANGE_BITS", "24"))  # غيّرها بمتغير بيئة لو عايز
FLAGGED_IPS_PATH  = BASE_DIR / "data/local/flagged_ips.json"
LOCAL_RANGES_PATH = BASE_DIR / "data/local/risky_ranges.csv"

# ---- API Keys
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY  = os.getenv("ABUSEIPDB_KEY")
OTX_KEY    = os.getenv("OTX_KEY")

# ---- Rate limits (seconds)
RATE = {
    "vt":   float(os.getenv("VT_RATE_SECONDS", "15.5")),
    "abuse":float(os.getenv("ABUSE_RATE_SECONDS", "1.5")),
    "otx":  float(os.getenv("OTX_RATE_SECONDS", "1.5")),
}

# ---- Alerts sink
ALERTS_LOG_PATH = BASE_DIR / "data/local/alerts.jsonl"
DASHBOARD_WEBHOOK_URL = os.getenv("DASHBOARD_WEBHOOK_URL")  # اختياري
ALERT_BUFFER: List[dict] = []
ALERT_BUFFER_MAX = 500

# ----------------- FastAPI
app = FastAPI(title="EyeGuard Enrichment Service", version="0.3.0")

# ----------------- Schemas
class QueryRequest(BaseModel):
    type: str                      # "ip" | "file" | "domain"
    value: str
    providers: Optional[List[str]] = None     # ["vt","abuse","otx"]
    force_refresh: bool = False

class IngestFlow(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    metadata: Optional[dict] = None
    providers: Optional[List[str]] = None
    force_refresh: bool = False

# ----------------- Utils
def safe_name(s: str) -> str:
    return s.replace("/", "_").replace(":", "_")

def cache_path(provider: str, key: str) -> Path:
    return CACHE_DIRS[provider] / f"{safe_name(key)}.json"

def load_cached(provider: str, key: str) -> Optional[dict]:
    p = cache_path(provider, key)
    if p.exists():
        try:
            return json.load(open(p, "r", encoding="utf-8"))
        except Exception:
            return None
    return None

def save_cache(provider: str, key: str, data: dict):
    p = cache_path(provider, key)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def load_local_index():
    """Load local CSV once to memory: columns = indicator,type,label,score,notes,timestamp"""
    global LOCAL_INDEX
    if LOCAL_DATA_PATH.exists():
        df = pd.read_csv(LOCAL_DATA_PATH)
        idx: Dict[str, Dict[str, Any]] = {}
        for _, r in df.iterrows():
            key = str(r.get("indicator", "")).strip()
            if not key: continue
            idx[key] = {
                "type":      str(r.get("type","")),
                "label":     r.get("label"),
                "score":     r.get("score"),
                "notes":     r.get("notes"),
                "timestamp": r.get("timestamp"),
            }
        LOCAL_INDEX = idx
    else:
        LOCAL_INDEX = {}

def local_lookup(indicator: str) -> Optional[dict]:
    if LOCAL_INDEX is None:
        load_local_index()
    return LOCAL_INDEX.get(indicator)

def is_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4: return False
    try:
        return all(0 <= int(p) < 256 for p in parts)
    except Exception:
        return False

# ---- IP helpers for range alerts
def ip_to_int(ip: str) -> int:
    try:
        a,b,c,d = [int(x) for x in ip.split(".")]
        return (a<<24) | (b<<16) | (c<<8) | d
    except Exception:
        return -1

def same_subnet(ip1: str, ip2: str, bits: int = RANGE_BITS) -> bool:
    if not (is_ip(ip1) and is_ip(ip2)): return False
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return (ip_to_int(ip1) & mask) == (ip_to_int(ip2) & mask)

def cidr_contains(cidr: str, ip: str) -> bool:
    try:
        net, bits = cidr.split("/")
        bits = int(bits)
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        return (ip_to_int(ip) & mask) == (ip_to_int(net) & mask)
    except Exception:
        return False

def load_flagged_ips() -> list:
    if FLAGGED_IPS_PATH.exists():
        try:
            return json.load(open(FLAGGED_IPS_PATH, "r", encoding="utf-8"))
        except Exception:
            return []
    return []

def save_flagged_ip(ip: str, action: str, threat_score: float):
    lst = load_flagged_ips()
    lst.append({"ip": ip, "action": action, "threat_score": threat_score, "ts": time.time()})
    FLAGGED_IPS_PATH.parent.mkdir(parents=True, exist_ok=True)
    json.dump(lst[-5000:], open(FLAGGED_IPS_PATH, "w", encoding="utf-8"), indent=2)

def load_local_ranges() -> list:
    nets = []
    if LOCAL_RANGES_PATH.exists():
        try:
            df = pd.read_csv(LOCAL_RANGES_PATH)
            for cidr in df.get("cidr", []):
                if isinstance(cidr, str) and "/" in cidr:
                    nets.append(cidr.strip())
        except Exception:
            pass
    return nets

# ----------------- Providers
def vt_get(t: str, value: str, force_refresh: bool = False) -> Optional[dict]:
    if not VT_API_KEY:
        return None
    key = f"{t}_{value}"
    if not force_refresh:
        cached = load_cached("vt", key)
        if cached: return cached
    base = "https://www.virustotal.com/api/v3"
    if t == "file":
        endpoint = f"/files/{quote_plus(value)}"
    elif t == "ip":
        endpoint = f"/ip_addresses/{quote_plus(value)}"
    elif t == "domain":
        endpoint = f"/domains/{quote_plus(value)}"
    else:
        return None
    r = requests.get(base+endpoint, headers={"x-apikey": VT_API_KEY}, timeout=30)
    if r.status_code == 429:
        time.sleep(60)
        r = requests.get(base+endpoint, headers={"x-apikey": VT_API_KEY}, timeout=30)
    if r.status_code != 200: return None
    data = r.json()
    save_cache("vt", key, data)
    time.sleep(RATE["vt"])
    return data

def abuse_get_ip(ip: str, force_refresh: bool = False) -> Optional[dict]:
    if not ABUSE_KEY: return None
    key = f"ip_{ip}"
    if not force_refresh:
        cached = load_cached("abuse", key)
        if cached: return cached
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=headers, params=params, timeout=20)
    if r.status_code != 200: return None
    data = r.json()
    save_cache("abuse", key, data)
    time.sleep(RATE["abuse"])
    return data

def otx_get_ip(ip: str, force_refresh: bool = False) -> Optional[dict]:
    if not OTX_KEY: return None
    key = f"ip_{ip}"
    if not force_refresh:
        cached = load_cached("otx", key)
        if cached: return cached
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{quote_plus(ip)}/general"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    r = requests.get(url, headers=headers, timeout=20)
    if r.status_code != 200: return None
    data = r.json()
    save_cache("otx", key, data)
    time.sleep(RATE["otx"])
    return data

# ----------------- Summaries
def summarize_vt(j: dict) -> dict:
    if not j: return {}
    d = j.get("data", {})
    a = d.get("attributes", {})
    stats = a.get("last_analysis_stats", {}) or {}
    votes = a.get("total_votes", {}) or {}
    return {
        "id": d.get("id"),
        "type": d.get("type"),
        "reputation": a.get("reputation"),
        "first_submission_date": a.get("first_submission_date"),
        "last_analysis_stats": {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "timeout": int(stats.get("timeout", 0)),
        },
        "total_votes": {
            "harmless": int(votes.get("harmless", 0)),
            "malicious": int(votes.get("malicious", 0)),
        },
        "tags": a.get("tags", []),
    }

def summarize_abuse(j: dict) -> dict:
    if not j or "data" not in j: return {}
    d = j["data"]
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "abuse_total_reports": d.get("totalReports"),
        "abuse_country": d.get("countryCode"),
        "abuse_usage_type": d.get("usageType"),
        "abuse_isp": d.get("isp"),
    }

def summarize_otx(j: dict) -> dict:
    if not j: return {}
    return {
        "otx_reputation": j.get("reputation"),
        "otx_pulse_count": (j.get("pulse_info") or {}).get("count", 0),
    }

# ----------------- Threat score + Decision
def combined_threat_score(src: Dict[str, Any], local_hit: Optional[dict]) -> float:
    vt_mal = float((src.get("vt") or {}).get("last_analysis_stats", {}).get("malicious", 0))
    abuse_score = float((src.get("abuse") or {}).get("abuse_confidence_score") or 0)
    otx_pulses = float((src.get("otx") or {}).get("otx_pulse_count") or 0)
    local_bonus = 20.0 if (local_hit and str(local_hit.get("label","")).lower() == "malicious") else 0.0
    return (vt_mal * 2.0) + (abuse_score * 0.5) + (min(otx_pulses, 5) * 3.0) + local_bonus

def decide_action(result: Dict[str, Any]) -> Dict[str, str]:
    ts = float(result.get("threat_score", 0.0))
    local = result.get("local_hit")
    vt_mal = int((result.get("sources", {}).get("vt") or {}).get("last_analysis_stats", {}).get("malicious", 0))
    abuse_score = float((result.get("sources", {}).get("abuse") or {}).get("abuse_confidence_score") or 0)

    if local and str(local.get("label","")).lower() == "malicious":
        return {"action":"block", "notes":"Local DB flags as malicious"}
    if vt_mal >= 5:
        return {"action":"block", "notes":f"VT malicious count = {vt_mal}"}
    if abuse_score >= 75:
        return {"action":"alert", "notes":f"AbuseIPDB score = {abuse_score}"}
    if ts >= 15:
        return {"action":"alert", "notes":f"Composite threat_score = {ts}"}
    if ts >= 5:
        return {"action":"monitor", "notes":f"Composite threat_score = {ts}"}
    return {"action":"none", "notes":"No significant signals"}

# ----------------- Alerts sink helpers
def _append_alert_local(alert: dict):
    ALERTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERTS_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    ALERT_BUFFER.append(alert)
    if len(ALERT_BUFFER) > ALERT_BUFFER_MAX:
        del ALERT_BUFFER[0:len(ALERT_BUFFER)-ALERT_BUFFER_MAX]

def _post_webhook(alert: dict):
    if not DASHBOARD_WEBHOOK_URL:
        return
    def _send():
        try:
            requests.post(DASHBOARD_WEBHOOK_URL, json=alert, timeout=10)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()

def emit_alert_to_sinks(alert: dict):
    _append_alert_local(alert)
    _post_webhook(alert)

# ----------------- Core
def handle_query(t: str, value: str, providers: List[str], force_refresh: bool):
    result: Dict[str, Any] = {"local_hit": None, "sources": {}, "threat_score": 0.0}

    # 1) Local first
    local = local_lookup(value)
    if local: result["local_hit"] = local

    # 2) Providers
    if "vt" in providers:
        vt_json = vt_get(t, value, force_refresh=force_refresh)
        result["sources"]["vt"] = summarize_vt(vt_json)
    if t == "ip":
        if "abuse" in providers:
            abuse_json = abuse_get_ip(value, force_refresh=force_refresh)
            result["sources"]["abuse"] = summarize_abuse(abuse_json)
        if "otx" in providers:
            otx_json = otx_get_ip(value, force_refresh=force_refresh)
            result["sources"]["otx"] = summarize_otx(otx_json)

    # 3) Score + decision
    result["threat_score"] = combined_threat_score(result["sources"], result["local_hit"])
    decision = decide_action(result)
    result.update(decision)

    # 4) Range alerts (IP only)
    if t == "ip":
        ip_val = value
        range_hit_info = {}
        flagged = load_flagged_ips()
        for item in flagged[-2000:]:
            bad_ip = item.get("ip")
            if bad_ip and same_subnet(ip_val, bad_ip, RANGE_BITS):
                range_hit_info = {
                    "type": "same_subnet",
                    "bits": RANGE_BITS,
                    "matched_ip": bad_ip,
                    "matched_action": item.get("action"),
                    "matched_threat_score": item.get("threat_score"),
                }
                break
        if not range_hit_info:
            for cidr in load_local_ranges():
                if cidr_contains(cidr, ip_val):
                    range_hit_info = {"type": "cidr_list", "cidr": cidr}
                    break
        if range_hit_info:
            if result.get("action") in (None,"none","monitor") or not result.get("action"):
                result["action"] = "alert"
                base_note = ("Same subnet as flagged IP"
                             if range_hit_info.get("type")=="same_subnet"
                             else f"In risky CIDR {range_hit_info.get('cidr')}")
                prev = result.get("notes", "")
                extra = ""
                if range_hit_info.get("matched_ip"):
                    extra = f" (matched {range_hit_info['matched_ip']} action={range_hit_info.get('matched_action')})"
                result["notes"] = (prev + " | " if prev else "") + base_note + extra
            result["range_alert"] = range_hit_info

    # 5) Persist flagged IPs for future range alerts
    if t == "ip" and result.get("action") in ("block","alert"):
        save_flagged_ip(value, result["action"], float(result.get("threat_score", 0.0)))

    # 6) Emit alert to sinks (webhook + local log)
    if result.get("action") in ("alert", "block"):
        alert_payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": t,
            "indicator": value,
            "action": result.get("action"),
            "notes": result.get("notes"),
            "threat_score": result.get("threat_score"),
            "sources": result.get("sources", {}),
            "local_hit": result.get("local_hit"),
            "range_alert": result.get("range_alert", None)
        }
        emit_alert_to_sinks(alert_payload)

    return result

# ----------------- Endpoints
@app.get("/health")
def health():
    return {"ok": True}

@app.get("/keys")
def get_keys_status():
    status = {
        "vt_present": bool(VT_API_KEY),
        "abuseipdb_present": bool(ABUSE_KEY),
        "otx_present": bool(OTX_KEY),
    }
    return JSONResponse(content=status)

@app.get("/alerts")
def get_alerts(limit: int = 100):
    data = list(ALERT_BUFFER)[-limit:][::-1]
    if not data and ALERTS_LOG_PATH.exists():
        lines = []
        with open(ALERTS_LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    lines.append(json.loads(line))
                except Exception:
                    pass
        data = lines[-limit:][::-1]
    return {"ok": True, "count": len(data), "alerts": data}

@app.get("/alerts/stream")
async def alerts_stream(request: Request):
    async def event_generator():
        last_seen = len(ALERT_BUFFER)
        while True:
            if await request.is_disconnected():
                break
            if len(ALERT_BUFFER) > last_seen:
                for i in range(last_seen, len(ALERT_BUFFER)):
                    yield f"data: {json.dumps(ALERT_BUFFER[i], ensure_ascii=False)}\n\n"
                last_seen = len(ALERT_BUFFER)
            await asyncio.sleep(1)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/query")
def query_entity(q: QueryRequest):
    t = q.type.lower().strip()
    val = q.value.strip()
    if t not in {"ip","file","domain"}:
        raise HTTPException(400,"type must be one of: ip, file, domain")

    providers = q.providers or ["vt","abuse","otx"]
    providers = [
        p for p in providers
        if not ((p=="vt" and not VT_API_KEY) or (p=="abuse" and not ABUSE_KEY) or (p=="otx" and not OTX_KEY))
    ]
    try:
        res = handle_query(t, val, providers, q.force_refresh)
        return {"ok": True,"used_providers": providers, **res}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/ingest")
def ingest_flow(flow: IngestFlow):
    providers = flow.providers or ["vt","abuse","otx"]
    providers = [
        p for p in providers
        if not ((p=="vt" and not VT_API_KEY) or (p=="abuse" and not ABUSE_KEY) or (p=="otx" and not OTX_KEY))
    ]
    enriched: Dict[str, Any] = {}
    if flow.file_hash:
        enriched["file"] = handle_query("file", flow.file_hash, providers, flow.force_refresh)
    if flow.domain:
        enriched["domain"] = handle_query("domain", flow.domain, providers, flow.force_refresh)
    if flow.src_ip:
        enriched.setdefault("ips", {})["src_ip"] = handle_query("ip", flow.src_ip, providers, flow.force_refresh)
    if flow.dst_ip:
        enriched.setdefault("ips", {})["dst_ip"] = handle_query("ip", flow.dst_ip, providers, flow.force_refresh)
    return {"ok": True, "enriched": enriched}
