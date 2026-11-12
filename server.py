from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Any
from urllib.parse import urlparse
from functools import lru_cache
import re
import math
import os
import joblib

try:
    import pandas as pd
except Exception:
    pd = None

app = FastAPI(
    title="Phishing Detection API",
    version="7.1",
    description="URL phishing detection using heuristic signals and optional ML model"
)

# Public browser frontend needs unauthenticated access. Restrict origins through
# ALLOWED_ORIGINS when deploying a private/custom frontend.
_origins = os.getenv("ALLOWED_ORIGINS", "*")
allowed_origins = ["*"] if _origins.strip() == "*" else [
    origin.strip() for origin in _origins.split(",") if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.getenv("MODEL_PATH", "phishing_model.pkl")
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("ML model loaded")
    except Exception as exc:
        print(f"ML model could not be loaded; heuristic mode enabled: {exc}")

class ScanRequest(BaseModel):
    url: str

class BatchScanRequest(BaseModel):
    urls: List[str]

SUSPICIOUS_TLDS = {
    "zip", "biz", "top", "country", "gq", "ml", "cf", "tk", "work",
    "men", "loan", "click", "link"
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "cutt.ly", "rb.gy"
}
IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
PUNY_PREFIX = "xn--"

def safe_parse(url: str):
    value = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Please enter a valid HTTP or HTTPS URL.")
    return parsed

def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())

@lru_cache(maxsize=2048)
def extract_features(url: str) -> Dict[str, Any]:
    parsed = safe_parse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    labels = [part for part in hostname.split(".") if part]
    common_tlds = {
        "com", "org", "net", "edu", "gov", "in", "co", "uk", "de",
        "io", "info", "biz", "app", "dev", "me", "ai"
    }
    tokens = [token for token in re.split(r"[^a-zA-Z0-9]+", url.lower()) if token]
    path_extension = path.rsplit("/", 1)[-1].rsplit(".", 1)
    suspicious_extensions = {
        "exe", "scr", "bat", "cmd", "com", "pif", "js", "vbs",
        "jar", "apk", "msi", "hta", "iso"
    }
    features = {
        # Exact feature names expected by the trained RandomForest model.
        "url_length": len(url),
        "has_ip_address": int(bool(IP_RE.match(hostname))),
        "dot_count": hostname.count("."),
        "https_flag": int(parsed.scheme == "https"),
        "url_entropy": round(entropy(url.lower()), 6),
        "token_count": len(tokens),
        "subdomain_count": max(0, len(labels) - 2),
        "query_param_count": len([part for part in parsed.query.split("&") if part]),
        "tld_length": len(tld),
        "path_length": len(path),
        "has_hyphen_in_domain": int("-" in hostname),
        "number_of_digits": sum(ch.isdigit() for ch in hostname),
        "tld_popularity": int(tld in common_tlds),
        "suspicious_file_extension": int(
            len(path_extension) == 2 and path_extension[-1].lower() in suspicious_extensions
        ),
        "domain_name_length": len(hostname),
        "percentage_numeric_chars": round(
            (sum(ch.isdigit() for ch in url) / max(1, len(url))) * 100, 4
        ),
        # Additional signals used by the transparent heuristic rules.
        "has_at_symbol": int("@" in url),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "contains_punycode": int(PUNY_PREFIX in hostname),
        "uses_shortener": int(hostname in URL_SHORTENERS),
    }
    return {"parsed_url": parsed.geturl(), "hostname": hostname, "features": features}

def assess_url(details: Dict[str, Any]) -> Dict[str, Any]:
    f = details["features"]
    reasons = []
    score = 0

    def flag(condition, points, reason):
        nonlocal score
        if condition:
            score += points
            reasons.append({"reason": reason, "points": points})

    flag(f["has_at_symbol"] == 1, 25, "URL contains an @ symbol, which can hide the actual destination.")
    flag(f["is_ip_host"] == 1, 25, "The website uses an IP address instead of a normal domain name.")
    flag(f["suspicious_tld"] == 1, 15, "The domain uses a TLD frequently associated with suspicious links.")
    flag(f["uses_shortener"] == 1, 15, "The URL uses a link-shortening service that hides the destination.")
    flag(f["contains_punycode"] == 1, 20, "The domain contains punycode, which can be used for look-alike domains.")
    flag(f["url_length"] > 100, 10, "The URL is unusually long.")
    flag(f["host_length"] > 50, 10, "The hostname is unusually long.")
    flag(f["num_digits_host"] >= 5, 10, "The hostname contains an unusually high number of digits.")
    flag(f["has_hyphen"] == 1 and f["num_dots"] >= 3, 10, "The hostname has multiple subdomains and hyphen usage.")
    flag(f["uses_https"] == 0, 5, "The URL does not use HTTPS.")

    score = min(score, 100)
    if score >= 50:
        label = "Phishing"
    elif score >= 25:
        label = "Suspicious"
    else:
        label = "Safe"

    ml_result = None
    ml_status = "model_not_loaded" if model is None else "pandas_unavailable"
    if model is not None and pd is not None:
        try:
            expected = list(getattr(model, "feature_names_in_", []))
            if expected:
                missing = [name for name in expected if name not in f]
                extra = [name for name in f if name not in expected]
                if missing or extra:
                    ml_status = "feature_schema_mismatch"
                    print(f"ML prediction skipped: feature schema mismatch; missing={missing}; extra={extra}")
                else:
                    frame = pd.DataFrame([{name: f[name] for name in expected}])
                    prediction = int(model.predict(frame)[0])
                    probability = None
                    if hasattr(model, "predict_proba"):
                        probabilities = model.predict_proba(frame)[0]
                        probability = round(float(max(probabilities)), 3)
                    ml_result = {"ml_label": prediction, "ml_probability": probability}
                    ml_status = "used"
            else:
                frame = pd.DataFrame([f])
                prediction = int(model.predict(frame)[0])
                probability = None
                if hasattr(model, "predict_proba"):
                    probabilities = model.predict_proba(frame)[0]
                    probability = round(float(max(probabilities)), 3)
                ml_result = {"ml_label": prediction, "ml_probability": probability}
                ml_status = "used"
        except Exception as exc:
            ml_status = "prediction_error"
            print(f"ML prediction skipped: {type(exc).__name__}: {exc}")

    return {
        "verdict": {"label": label, "risk_score": score, "reasons": reasons},
        "details": details,
        "ml_result": ml_result,
        "ml_status": ml_status
    }

@app.get("/diagnostics")
async def diagnostics():
    expected = list(getattr(model, "feature_names_in_", [])) if model is not None else []
    runtime_features = list(extract_features("https://example.com/")["features"].keys())
    missing = [name for name in expected if name not in runtime_features]
    extra = [name for name in runtime_features if expected and name not in expected]
    classes = [str(value) for value in getattr(model, "classes_", [])] if model is not None else []
    return {
        "api_version": "7.1",
        "model_loaded": model is not None,
        "pandas_available": pd is not None,
        "model_feature_count": len(expected) if expected else None,
        "runtime_feature_count": len(runtime_features),
        "model_features": expected or None,
        "feature_schema_compatible": (not missing) if expected else None,
        "missing_runtime_features": missing,
        "additional_runtime_features": extra,
        "model_classes": classes
    }

@app.get("/")
async def health():
    return {"status": "Phishing Detection API running", "version": "7.1"}

@app.get("/health")
async def health_check():
    return {"ok": True, "status": "healthy"}

@app.post("/api/scan")
async def scan(body: ScanRequest):
    url = body.url.strip()
    if not url or len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL must contain between 1 and 2048 characters.")
    details = extract_features(url)
    return {"ok": True, **assess_url(details)}

@app.post("/api/batch_scan")
async def batch_scan(body: BatchScanRequest):
    if len(body.urls) > 100:
        raise HTTPException(status_code=400, detail="A maximum of 100 URLs can be scanned at once.")
    results = []
    for raw_url in body.urls:
        url = raw_url.strip()
        if not url or len(url) > 2048:
            results.append({"url": raw_url, "ok": False, "error": "Invalid URL length."})
            continue
        try:
            details = extract_features(url)
            results.append({"url": url, "ok": True, **assess_url(details)})
        except HTTPException as exc:
            results.append({"url": raw_url, "ok": False, "error": exc.detail})
    return {"ok": True, "results": results}
