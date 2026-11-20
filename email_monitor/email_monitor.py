import re
from detection.url_detector import detect_url

URL_REGEX = re.compile(r"https?://[^\s<>\"']+")

PHISHING_WORDS = [
    "verify", "account", "immediately", "urgent", "password",
    "login", "update", "confirm", "blocked", "suspended",
    "click here", "security alert", "bank", "payment"
]

def extract_links(text):
    return URL_REGEX.findall(text or "")

def detect_email(sender, subject, body):
    text = f"{sender} {subject} {body}".lower()

    email_score = 0

    for word in PHISHING_WORDS:
        if word in text:
            email_score += 12

    links = extract_links(body)

    worst_link = ""
    worst_url_risk = 0
    url_status = "SAFE"

    for link in links:
        result = detect_url(link)

        if result["risk_score"] > worst_url_risk:
            worst_url_risk = result["risk_score"]
            worst_link = link
            url_status = result["status"]

    final_risk = min(email_score + worst_url_risk, 100)

    # Force phishing if risky URL exists
    if url_status == "PHISHING" or final_risk >= 70:
        status = "PHISHING"
    elif url_status == "SUSPICIOUS" or final_risk >= 40:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    return status, final_risk, worst_link