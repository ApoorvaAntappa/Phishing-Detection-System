import re
from detection.url_detector import detect_url

URL_REGEX = re.compile(r"https?://[^\s]+")

SUSPICIOUS_EMAIL_WORDS = [
    "verify", "urgent", "password", "bank",
    "account", "limited", "click here",
    "update", "login", "security alert"
]

def detect_email(sender, subject, body):
    text = f"{sender} {subject} {body}".lower()

    score = 0

    for word in SUSPICIOUS_EMAIL_WORDS:
        if word in text:
            score += 12

    urls = URL_REGEX.findall(body)

    worst_url = ""
    worst_risk = 0

    for url in urls:
        result = detect_url(url)
        if result["risk_score"] > worst_risk:
            worst_risk = result["risk_score"]
            worst_url = url

    final_risk = min(score + worst_risk, 100)

    if final_risk >= 70:
        status = "PHISHING"
    elif final_risk >= 40:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    return status, final_risk, worst_url