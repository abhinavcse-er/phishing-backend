from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, List
from urllib.parse import urlparse
from functools import lru_cache
import re
import math
import joblib
import os
import pandas as pd

# ==========================
# Initialize App
# ==========================
app = FastAPI(
    title="Phishing Detection API",
    version="6.0",
    description="ML + Heuristic Phishing Detection API"
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
# Load ML Model
# ==========================
MODEL_PATH = "phishing_model.pkl"

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = None
    print("⚠ ML model not found, running heuristic only")

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
        "uses_https": int(parsed.scheme == "https"),
        "url_length": len(url),
        "host_length": len(hostname),
        "num_dots": hostname.count("."),
        "has_at_symbol": int("@" in url),
        "has_hyphen": int("-" in hostname),
        "is_ip_host": int(bool(IP_RE.match(hostname))),
        "num_digits_host": count_digits(hostname),
        "suspicious_tld": int(hostname.split(".")[-1] in SUSPICIOUS_TLDS),
        "contains_punycode": int(PUNY_PREFIX in hostname),
        "uses_shortener": int(hostname in URL_SHORTENERS),
        "query_length": len(parsed.query),
        "path_entropy": round(entropy(path), 3),
    }

    return {
        "parsed_url": parsed.geturl(),
        "hostname": hostname,
        "features": features
    }

# ==========================
# ML Prediction
# ==========================
def ml_predict(features: Dict[str, Any]):

    if model is None:
        return None

    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    prob = model.predict_proba(df)[0][1]

    return {
        "ml_label": int(prediction),
        "ml_probability": round(float(prob), 3)
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
    ml_result = ml_predict(details["features"])

    return {
        "ok": True,
        "details": details,
        "ml_result": ml_result
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
        ml_result = ml_predict(details["features"])
        results.append({
            "url": url,
            "ml_result": ml_result
        })

    return {
        "ok": True,
        "results": results
    }
