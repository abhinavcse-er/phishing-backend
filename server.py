from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, List
from urllib.parse import urlparse
from functools import lru_cache
import re
import math

# ==========================
# Initialize App
# ==========================
app = FastAPI(
    title="Phishing Detection API",
    version="5.0",
    description="Stable Render-safe Phishing Detection API"
)

# ==========================
# CORS
# ==========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# API KEY
# ==========================
API_KEYS = {"my-secret-key"}

async def validate_key(x_api_key: str):
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API Key")

# ==========================
# Request Models
# ==========================
class ScanRequest(BaseModel):
    url: str

class BatchScanRequest(BaseModel):
    urls: List[str]

# ==========================
# Constants
# ==========================
SUSPICIOUS_TLDS = {
    "zip","biz","top","country","gq","ml","cf","tk","work","men",
    "loan","click","link"
}

URL_SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","ow.ly","is.gd","cutt.ly","rb.gy"
}

IP_RE = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d?\d)(\.|$)){4}")
PUNY_PREFIX = "xn--"

# ==========================
# Helper Functions
# ==========================
def safe_parse(url: str):
    if not re.match(r"^\w+://", url):
        url = "http://" + url
    return urlparse(url)

def count_digits(s: str) -> int:
    return sum(ch.isdigit() for ch in s)

def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    probs = [n / len(s) for n in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

# ==========================
# Feature Extraction
# ==========================
@lru_cache(maxsize=1024)
def extract_features(url: str) -> Dict[str, Any]:

    parsed = safe_parse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path or "/"

    features = {
        "uses_https": parsed.scheme == "https",
        "url_length": len(url),
        "host_length": len(hostname),
        "num_dots": hostname.count("."),
        "has_at_symbol": "@" in url,
        "has_hyphen": "-" in hostname,
        "is_ip_host": bool(IP_RE.match(hostname)),
        "num_digits_host": count_digits(hostname),
        "suspicious_tld": hostname.split(".")[-1] in SUSPICIOUS_TLDS,
        "contains_punycode": PUNY_PREFIX in hostname,
        "uses_shortener": hostname in URL_SHORTENERS,
        "query_length": len(parsed.query),
        "path_entropy": round(entropy(path), 3),
    }

    return {
        "parsed_url": parsed.geturl(),
        "hostname": hostname,
        "features": features
    }

# ==========================
# Scoring (Stable Heuristic Only)
# ==========================
def score(details: Dict[str, Any]):

    f = details["features"]
    risk = 0

    if not f["uses_https"]:
        risk += 2

    if f["is_ip_host"]:
        risk += 4

    if f["suspicious_tld"]:
        risk += 3

    if f["uses_shortener"]:
        risk += 2

    if f["contains_punycode"]:
        risk += 2

    if f["has_at_symbol"]:
        risk += 3

    if f["num_digits_host"] > 5:
        risk += 2

    final_score = min(100, int((risk / 18) * 100))

    if final_score >= 60:
        label = "likely_phishing"
    elif final_score >= 30:
        label = "suspicious"
    else:
        label = "probably_safe"

    return {
        "risk_score": final_score,
        "label": label
    }

# ==========================
# Routes
# ==========================
@app.get("/")
async def health():
    return {"status": "Phishing Detection API running"}

@app.post("/api/scan")
async def scan(
    body: ScanRequest,
    x_api_key: str = Header(...)
):
    await validate_key(x_api_key)

    details = extract_features(body.url.strip())
    verdict = score(details)

    return {
        "ok": True,
        "details": details,
        "verdict": verdict
    }

@app.post("/api/batch_scan")
async def batch_scan(
    body: BatchScanRequest,
    x_api_key: str = Header(...)
):
    await validate_key(x_api_key)

    results = []

    for url in body.urls:
        details = extract_features(url.strip())
        verdict = score(details)
        results.append({
            "url": url,
            "verdict": verdict
        })

    return {
        "ok": True,
        "results": results
    }
