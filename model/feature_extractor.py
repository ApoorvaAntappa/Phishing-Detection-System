from urllib.parse import urlparse

def extract_features(url):
    parsed = urlparse(url)

    url_length = len(url)
    valid_url = 1 if parsed.scheme else 0
    at_symbol = 1 if "@" in url else 0

    sensitive_words = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "account",
        "paypal"
    ]

    sensitive_words_count = sum(
        word in url.lower()
        for word in sensitive_words
    )

    path_length = len(parsed.path)
    isHttps = 1 if parsed.scheme == "https" else 0
    nb_dots = url.count(".")
    nb_hyphens = url.count("-")
    nb_and = url.count("&")
    nb_or = url.lower().count("or")
    nb_www = url.lower().count("www")
    nb_com = url.lower().count(".com")
    nb_underscore = url.count("_")

    features = [
        url_length,
        valid_url,
        at_symbol,
        sensitive_words_count,
        path_length,
        isHttps,
        nb_dots,
        nb_hyphens,
        nb_and,
        nb_or,
        nb_www,
        nb_com,
        nb_underscore
    ]

    return features
