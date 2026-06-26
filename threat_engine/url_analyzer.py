import re
from urllib.parse import urlparse


def analyze_url(url):
    """
    Rule-based URL risk analyzer.
    Returns:
        risk_score (0-100)
        reasons (list)
    """

    risk_score = 0
    reasons = []

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # -------------------------
    # HTTPS
    # -------------------------

    if parsed.scheme != "https":
        risk_score += 20
        reasons.append("Website does not use HTTPS")

    # -------------------------
    # Long URL
    # -------------------------

    if len(url) > 75:
        risk_score += 15
        reasons.append("Long URL")

    # -------------------------
    # IP Address
    # -------------------------

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        risk_score += 20
        reasons.append("Uses IP address")

    # -------------------------
    # Too many dots
    # -------------------------

    if url.count(".") > 3:
        risk_score += 10
        reasons.append("Too many subdomains")

    # -------------------------
    # Hyphen
    # -------------------------

    if "-" in domain:
        risk_score += 10
        reasons.append("Hyphen in domain")

    # -------------------------
    # @ Symbol
    # -------------------------

    if "@" in url:
        risk_score += 15
        reasons.append("@ symbol detected")

    # -------------------------
    # Suspicious Keywords
    # -------------------------

    suspicious_words = [
        "login",
        "verify",
        "update",
        "bank",
        "free",
        "bonus",
        "password",
        "otp",
        "wallet",
        "secure",
        "signin",
        "account",
        "confirm"
    ]

    for word in suspicious_words:
        if word in url.lower():
            risk_score += 10
            reasons.append(f"Suspicious keyword: {word}")

    # -------------------------
    # Limit score
    # -------------------------

    risk_score = min(risk_score, 100)

    return risk_score, reasons