from urllib.parse import urlparse
from detection.feature_extractor import normalize_url, extract_features
from model.ml_detector import ml_predict

TRUSTED_DOMAINS = [
    "google.com",
    "google.co.in",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "youtube.com",
    "gmail.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "azure.com",
    "cloudflare.com",
    "github.com",
    "githubusercontent.com",
    "amazon.com",
    "amazon.in",
    "linkedin.com",
    "apple.com",
    "whatsapp.com",
    "facebook.com",
    "instagram.com",
    "yahoo.com"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure",
    "account", "bank", "password", "confirm",
    "free", "bonus", "gift", "limited",
    "urgent", "redirect", "signin"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".loan",
    ".review", ".zip", ".country", ".stream"
]

def get_domain(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    return parsed.hostname or ""

def is_trusted_domain(domain):
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in TRUSTED_DOMAINS)

def rule_score(url, domain):
    score = 0
    full = url.lower()

    if "@" in full:
        score += 25

    if len(full) > 90:
        score += 15

    if domain.count(".") >= 4:
        score += 10

    if domain.count("-") >= 2:
        score += 10

    if any(word in full for word in SUSPICIOUS_KEYWORDS):
        score += 20

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 25

    if full.startswith("http://"):
        score += 10

    return min(score, 100)

def detect_url(url):
    url = normalize_url(url)
    domain = get_domain(url)

    if not domain:
        return {
            "url": url,
            "domain": "",
            "status": "SUSPICIOUS",
            "risk_score": 60
        }

    if is_trusted_domain(domain):
        return {
            "url": url,
            "domain": domain,
            "status": "SAFE",
            "risk_score": 5
        }

    rules = rule_score(url, domain)

    features = extract_features(url)
    ml_prediction, ml_risk = ml_predict(features)

    final_risk = int((rules * 0.45) + (ml_risk * 0.55))

    if final_risk >= 70:
        status = "PHISHING"
    elif final_risk >= 40:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    return {
        "url": url,
        "domain": domain,
        "status": status,
        "risk_score": final_risk
    }