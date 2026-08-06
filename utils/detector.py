import re
from urllib.parse import urlparse
import tldextract


def analyze_url(url):

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    domain = extracted.domain
    subdomain = extracted.subdomain
    suffix = extracted.suffix

    score = 0
    reasons = []

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "bank",
        "signin",
        "update",
        "password",
        "account",
        "wallet",
        "paypal"
    ]

    # URL Length
    if len(url) > 75:
        score += 10
        reasons.append("Very long URL")

    # Hyphens
    if url.count("-") >= 2:
        score += 15
        reasons.append("Too many hyphens")

    # @ symbol
    if "@" in url:
        score += 20
        reasons.append("Contains @ symbol")

    # HTTPS
    if parsed.scheme != "https":
        score += 10
        reasons.append("Not using HTTPS")

    # IP Address
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 25
        reasons.append("Uses an IP address")

    # Suspicious TLDs
    bad_tlds = [
        "xyz",
        "top",
        "click",
        "gq",
        "tk",
        "cf",
        "ml"
    ]

    if suffix in bad_tlds:
        score += 20
        reasons.append(f"Suspicious TLD (.{suffix})")

    # Too many dots
    if url.count(".") >= 4:
        score += 10
        reasons.append("Too many subdomains")

    # Digits
    if sum(c.isdigit() for c in url) > 5:
        score += 10
        reasons.append("Contains many numbers")

    # Keywords
    lower = url.lower()

    for word in suspicious_keywords:
        if word in lower:
            score += 10
            reasons.append(f"Contains '{word}'")

    if score > 100:
        score = 100

    if score >= 70:
        status = "🔴 Likely Phishing"
    elif score >= 33:
        status = "🟡 Suspicious"
    else:
        status = "🟢 Safe"

    return {
        "score": score,
        "status": status,
        "reasons": reasons,
        "domain": domain,
        "subdomain": subdomain if subdomain else "None",
        "tld": suffix,
        "protocol": parsed.scheme.upper(),
        "path": parsed.path if parsed.path else "/"
    }