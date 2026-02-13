from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, List
from urllib.parse import urlparse
from datetime import datetime
from functools import lru_cache

import re
import socket
import ssl
import asyncio
import aiodns
import tldextract
import math
import joblib
import whois
import requests

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# ==========================
# Load ML Model
# ==========================
ml_model = joblib.load("phishing_model.pkl")

# ==========================
# Initialize App
# ==========================
app = FastAPI(
    title="Phishing Detection API",
    version="3.1",
    description="Industry-ready phishing detection API (Async + ML + Heuristic)"
)

# ==========================
# CORS
# ==========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# Rate Limiter Setup
# ==========================
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded"}
    )

# ==========================
# API Keys
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
SUSPICIOUS_TLDS = {"zip","biz","top","country","gq","ml","cf","tk","work","men",
                   "loan","click","link"}

BRAND_KEYWORDS = ["login","verify","update","secure","account","support",
                  "billing","unlock","reset","confirm","invoice","security",
                  "pay","wallet","password"]

TRUSTED_BRANDS = ["google","facebook","instagram","apple","microsoft",
                  "netflix","amazon","paypal","bank","yahoo","outlook"]

URL_SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","t.co","ow.ly",
                  "is.gd","cutt.ly","rb.gy","buff.ly"}

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

async def dns_resolves(hostname: str) -> bool:
    resolver = aiodns.DNSResolver()
    try:
        await resolver.gethostbyname(hostname.split(":")[0], socket.AF_INET)
        return True
    except:
        return False

def ssl_valid(hostname: str) -> bool:
    try:
        context = ssl.create_default_context()
        host = hostname.replace("https://","").split("/")[0]
        with socket.create_connection((host, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.getpeercert()
        return True
    except:
        return False

def get_domain_age(domain: str) -> int:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        if creation_date:
            return (datetime.now() - creation_date).days
        return -1
    except:
        return -1

def is_blacklisted(url: str) -> bool:
    # Disabled by default (needs API key)
    return False

# ==========================
# Feature Extraction
# ==========================
@lru_cache(maxsize=1024)
def extract_features_base(url: str) -> Dict[str, Any]:
    parsed = safe_parse(url)
    ext = tldextract.extract(parsed.netloc)

    hostname = parsed.netloc.lower()
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain = ext.subdomain or ""
    path = parsed.path or "/"

    return {
        "parsed_url": parsed.geturl(),
        "hostname": hostname,
        "domain": domain,
        "subdomain": subdomain,
        "path": path,
        "features": {
            "uses_https": parsed.scheme == "https",
            "url_length": len(url),
            "host_length": len(hostname),
            "num_dots": hostname.count("."),
            "has_at_symbol": "@" in url,
            "has_hyphen": "-" in ext.domain,
            "has_port": ":" in hostname,
            "is_ip_host": bool(IP_RE.match(hostname)),
            "num_digits_host": count_digits(hostname),
            "suspicious_tld": ext.suffix in SUSPICIOUS_TLDS,
            "contains_punycode": PUNY_PREFIX in hostname,
            "uses_shortener": hostname in URL_SHORTENERS,
            "subdomain_len": len(subdomain),
            "subdomain_entropy": round(entropy(subdomain), 3),
            "keyword_in_path": any(k in path.lower() for k in BRAND_KEYWORDS),
            "brand_mismatch": any(b in path.lower() for b in TRUSTED_BRANDS)
                              and not any(b in domain for b in TRUSTED_BRANDS),
            "query_len": len(parsed.query),
            "domain_age_days": get_domain_age(domain),
            "ssl_valid": ssl_valid(parsed.geturl()),
            "is_blacklisted": is_blacklisted(parsed.geturl())
        }
    }

async def extract_features(url: str):
    details = extract_features_base(url)
    details["features"]["dns_resolves"] = await dns_resolves(details["hostname"])
    return details

# ==========================
# Scoring
# ==========================
def score(details: Dict[str, Any]):
    f = details["features"]
    risk = 0

    if not f["uses_https"]: risk += 2
    if f["is_ip_host"]: risk += 4
    if f["suspicious_tld"]: risk += 3
    if f["uses_shortener"]: risk += 2
    if not f["dns_resolves"]: risk += 3
    if f["contains_punycode"]: risk += 2
    if f["domain_age_days"] >= 0 and f["domain_age_days"] < 30: risk += 2

    heuristic_score = min(100, int((risk / 20) * 100))

    feature_vector = [int(v) if isinstance(v,bool) else v
                      for v in f.values()
                      if isinstance(v,(int,float,bool))]

    ml_score = int(ml_model.predict_proba([feature_vector])[0][1] * 100)

    final_score = max(heuristic_score, ml_score)

    if final_score >= 60:
        label = "likely_phishing"
    elif final_score >= 30:
        label = "suspicious"
    else:
        label = "probably_safe"

    return {
        "risk_score": final_score,
        "heuristic_score": heuristic_score,
        "ml_score": ml_score,
        "label": label
    }

# ==========================
# API Endpoints
# ==========================
@app.get("/")
async def health():
    return {"status": "Phishing Detection API running"}

@app.post("/api/scan")
@limiter.limit("10/minute")
async def scan(request: Request, body: ScanRequest, x_api_key: str = Header(...)):
    await validate_key(x_api_key)
    details = await extract_features(body.url.strip())
    verdict = score(details)
    return {"ok": True, "input": body.url, "details": details, "verdict": verdict}

@app.post("/api/batch_scan")
@limiter.limit("5/minute")
async def batch_scan(request: Request, body: BatchScanRequest, x_api_key: str = Header(...)):
    await validate_key(x_api_key)

    results = []
    for url in body.urls:
        details = await extract_features(url.strip())
        verdict = score(details)
        results.append({"input": url, "verdict": verdict})

    return {"ok": True, "results": results}
