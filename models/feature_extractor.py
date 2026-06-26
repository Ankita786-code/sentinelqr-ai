import re
from urllib.parse import urlparse


def extract_features(url):
    """
    Extract numerical features from a URL
    for phishing/threat detection.
    """

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    path = parsed.path.lower()

    suspicious_words = [
        "login",
        "verify",
        "bank",
        "bonus",
        "free",
        "password",
        "otp",
        "secure",
        "update",
        "account",
        "confirm",
        "signin",
        "wallet"
    ]

    features = [

        # 1 URL length
        len(url),

        # 2 HTTPS
        1 if parsed.scheme == "https" else 0,

        # 3 Number of dots
        url.count("."),

        # 4 Number of slashes
        url.count("/"),

        # 5 Number of digits
        sum(c.isdigit() for c in url),

        # 6 Number of hyphens
        url.count("-"),

        # 7 Number of '@'
        url.count("@"),

        # 8 Number of '?'
        url.count("?"),

        # 9 Number of '='
        url.count("="),

        # 10 IP Address present
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", domain) else 0,

        # 11 Suspicious words count
        sum(word in url.lower() for word in suspicious_words),

        # 12 Domain length
        len(domain),

        # 13 Path length
        len(path),

        # 14 Subdomain count
        max(domain.count(".") - 1, 0),

        # 15 Uses HTTP only
        1 if parsed.scheme == "http" else 0
    ]

    return features