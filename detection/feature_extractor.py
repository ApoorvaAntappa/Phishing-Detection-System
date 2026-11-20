from urllib.parse import urlparse

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def extract_features(url):
    url = normalize_url(url)
    parsed = urlparse(url)

    sensitive_words = [
        "login", "verify", "secure", "update",
        "bank", "account", "paypal"
    ]

    return [
        len(url),
        1 if parsed.scheme else 0,
        1 if "@" in url else 0,
        sum(word in url.lower() for word in sensitive_words),
        len(parsed.path),
        1 if parsed.scheme == "https" else 0,
        url.count("."),
        url.count("-"),
        url.count("&"),
        url.lower().count("or"),
        url.lower().count("www"),
        url.lower().count(".com"),
        url.count("_")
    ]