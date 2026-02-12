from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, List
from urllib.parse import urlparse
import re, socket, ssl, asyncio, aiodns, tldextract, math, joblib, whois, requests
from functools import lru_cache
from datetime import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address

# Load ML model
ml_model = joblib.load("phishing_model.pkl")

# ---------- Initialize App ----------
app = FastAPI(
    title="Phishing Detection API",
    version="3.0",
    description="Industry-ready phishing detection API (async, ML + heuristic)"
)

# ---------- CORS ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # replace with frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Rate Limiter ----------
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# ---------- API Key ----------
API_KEYS = {"my-secret-key"}  # replace with real keys

async def validate_key(x_api_key: str = Header(...)):
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API Key")

# ---------- Request Models ----------
class ScanRequest(BaseModel):
    url: str

class BatchScanRequest(BaseModel):
    urls: List[str]

# ---------- Constants ----------
SUSPICIOUS_TLDS = {"zip","biz","top","country","gq","ml","cf","tk","work","men",
                   "loan","click","link"}
BRAND_KEYWORDS = ["login","verify","update","secure","account","support","billing",
                  "unlock","reset","confirm","invoice","security","pay","wallet","password"]
TRUSTED_BRANDS = ["google","facebook","instagram","apple","microsoft","netflix",
                  "amazon","paypal","bank","yahoo","outlook"]
URL_SHORTENERS = {"bit.ly","tinyurl.com","goo.gl","t.co","ow.ly",
                  "is.gd","cutt.ly","rb.gy","buff.ly"}
IP_RE = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d?\d)(\.|$)){4}")
PUNY_PREFIX = "xn--"

# ---------- Helper Functions ----------
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
    if not hostname.startswith("https"):
        return False
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname.replace("https://","").split("/")[0], 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.getpeercert()
        return True
    except:
        return False

def get_domain_age(domain: str) -> int:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        return (datetime.now() - creation_date).days
    except:
        return -1

def is_blacklisted(url: str) -> bool:
    # Example with Google Safe Browsing API (replace API_KEY)
    API_KEY = "YOUR_GOOGLE_SAFEBROWSING_KEY"
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}",
            json={
                "client": {"clientId": "app", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }, timeout=3
        )
        return bool(response.json().get("matches"))
    except:
        return False

# ---------- Feature Extraction ----------
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

async def extract_features(url: str) -> Dict[str, Any]:
    details = extract_features_base(url)
    details["features"]["dns_resolves"] = await dns_resolves(details["hostname"])
    return details

# ---------- Scoring Function ----------
def score(details: Dict[str, Any]) -> Dict[str, Any]:
    f = details["features"]
    risk = 0
    reasons = []

    def add(points, reason, condition):
        nonlocal risk
        if condition:
            risk += points
            reasons.append({"points": points, "reason": reason})

    add(2, "Not using HTTPS", not f["uses_https"])
    add(4, "Host is an IP", f["is_ip_host"])
    add(3, "Suspicious TLD", f["suspicious_tld"])
    add(2, "URL shortener", f["uses_shortener"])
    add(2, "Contains '@'", f["has_at_symbol"])
    add(1, "Hyphenated domain", f["has_hyphen"])
    add(1, "Port specified", f["has_port"])
    add(2, "High subdomain entropy", f["subdomain_entropy"] >= 3.5)
    add(2, "Brand mismatch", f["brand_mismatch"])
    add(1, "Login/security keyword", f["keyword_in_path"])
    add(1, "Long URL", f["url_length"] > 80)
    add(1, "Many dots", f["num_dots"] >= 4)
    add(1, "Many digits", f["num_digits_host"] >= 4)
    add(3, "DNS does not resolve", not f.get("dns_resolves", True))
    add(2, "Punycode detected", f["contains_punycode"])
    add(1, "Long query string", f["query_len"] > 60)
    add(2, "Domain age < 30 days", f["domain_age_days"] >=0 and f["domain_age_days"] < 30)
    add(3, "Invalid SSL", not f["ssl_valid"])
    add(5, "URL is blacklisted", f["is_blacklisted"])

    heuristic_score = min(100, int((risk / 35) * 100))

    # ML Score
    feature_vector = [v for v in f.values() if isinstance(v, (int,float,bool))]
    ml_score = int(ml_model.predict_proba([feature_vector])[0][1]*100)

    # Hybrid Score
    final_score = max(heuristic_score, ml_score)
    if final_score >= 60:
        label, color = "likely_phishing", "red"
    elif final_score >= 30:
        label, color = "suspicious", "orange"
    else:
        label, color = "probably_safe", "green"

    return {
        "risk_score": final_score,
        "label": label,
        "color": color,
        "heuristic_score": heuristic_score,
        "ml_score": ml_score,
        "reasons": sorted(reasons, key=lambda x: -x["points"])
    }

# ---------- API Endpoints ----------
@app.get("/")
async def health():
    return {"status": "Phishing Detection API running"}

@app.post("/api/scan")
@limiter.limit("10/minute")
async def scan(body: ScanRequest, api_key: str = Header(...)):
    await validate_key(api_key)
    details = await extract_features(body.url.strip())
    verdict = score(details)
    return {"ok": True, "input": body.url, "details": details, "verdict": verdict}

@app.post("/api/batch_scan")
@limiter.limit("5/minute")
async def batch_scan(body: BatchScanRequest, api_key: str = Header(...)):
    await validate_key(api_key)
    results = []
    for url in body.urls:
        details = await extract_features(url.strip())
        verdict = score(details)
        results.append({"input": url, "details": details, "verdict": verdict})
    return {"ok": True, "results": results}
