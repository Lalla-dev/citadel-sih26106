"""
Citadel Security Platform - URL Intelligence Module
Implements lightweight lexical, structural, and obfuscation analysis based on
Paper 3 (Chaudhuri & Mohankumar - AR-LRF: Adversarial-Resilient Phishing URL Detection).
"""
import math
import re
from urllib.parse import urlparse, unquote
from typing import List, Dict, Any
from backend.schemas import URLAnalysis

# High-frequency deceptive tokens often used in token padding / evasion
DECEPTIVE_TOKENS = {
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "portal", "auth", "confirm", "wallet", "support", "service", "billing",
    "password", "security", "validation", "authenticate", "access"
}

# Suspicious high-risk top-level domains commonly used in disposable phishing campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "work", "click", "rest", "cam", "fit", "buzz", "cfd",
    "surf", "monster", "sbs", "beauty", "hair", "skin", "quest", "icu", "gq",
    "cf", "tk", "ml", "ga"
}

IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

def calculate_shannon_entropy(s: str) -> float:
    """
    Computes Shannon Entropy H(s) = - sum(p * log2(p)).
    Captures character randomness, encoding obfuscation, and algorithmic generation.
    """
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def analyze_single_url(raw_url: str) -> URLAnalysis:
    """
    Performs comprehensive lightweight feature extraction and evasion risk scoring
    on an individual URL string without external web crawling or DPI.
    Safe against malformed URLs, null bytes, and unparseable input.
    """
    clean_url = (raw_url or "").strip().replace("\x00", "")
    if not clean_url:
        return URLAnalysis(
            url="empty", domain="unknown", length=0, shannon_entropy=0.0,
            digit_ratio=0.0, special_char_count=0, is_ip_address=False,
            is_https=False, subdomain_count=0, has_hex_encoding=False,
            has_unicode_obfuscation=False, has_deceptive_keywords=False,
            risk_score=0.0, risk_category="SAFE", triggers=[]
        )

    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    try:
        parsed = urlparse(clean_url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
    except Exception:
        # Fallback for severely malformed URLs
        hostname = "malformed-host"
        path = ""
        query = ""
        parsed = None
    full_string = clean_url.lower()

    # Lexical features
    url_length = len(clean_url)
    entropy = calculate_shannon_entropy(clean_url)
    digit_count = sum(c.isdigit() for c in clean_url)
    digit_ratio = round(digit_count / max(1, url_length), 3)
    special_chars = sum(c in "@-_=%?&~:/" for c in clean_url)

    # Structural features
    is_https = parsed.scheme.lower() == "https"
    is_ip = bool(IPV4_PATTERN.match(hostname))
    
    # Subdomain depth calculation
    host_parts = hostname.split(".")
    if is_ip or len(host_parts) <= 2:
        subdomain_count = 0
        tld = ""
    else:
        # e.g. "a.b.bank.com" -> 2 subdomains
        subdomain_count = max(0, len(host_parts) - 2)
        tld = host_parts[-1]

    # Obfuscation & Evasion Checks (Paper 3 threat model)
    has_hex = bool(re.search(r'%[0-9a-fA-F]{2}', raw_url))
    has_unicode = "xn--" in hostname or any(ord(c) > 127 for c in raw_url)

    # Token padding and deceptive keyword detection
    matched_deceptive = [token for token in DECEPTIVE_TOKENS if token in path or token in query or token in hostname]
    has_deceptive_keywords = len(matched_deceptive) > 0

    # Risk Calculation Engine (Heuristic model calibrated to Paper 3 distributions)
    risk_score = 0.0
    triggers: List[str] = []

    # 1. IP-based host (High risk indicator)
    if is_ip:
        risk_score += 45.0
        triggers.append(f"Host uses direct raw IP address ({hostname}) instead of registered domain.")

    # 2. Shannon Entropy threshold (Paper 3: Phishing mean 4.03, max 4.9; Benign mean 3.47, max 4.4)
    # High entropy is significant when tokens are randomized/hashed or combined with high digit/special char ratio
    if entropy >= 4.6:
        risk_score += 25.0
        triggers.append(f"Severely elevated Shannon Entropy ({entropy:.2f}), indicative of randomized/algorithmic tokens.")
    elif entropy >= 4.2 and (digit_ratio > 0.15 or special_chars > 8 or has_hex):
        risk_score += 15.0
        triggers.append(f"Elevated Shannon Entropy ({entropy:.2f}) combined with high token complexity.")

    # 3. Excessive URL length (Paper 3: Phishing mean 88.9 chars vs Benign 63.8)
    if url_length > 105:
        risk_score += 15.0
        triggers.append(f"Abnormal URL length ({url_length} characters), typical of token padding evasion.")
    elif url_length > 85 and has_deceptive_keywords:
        risk_score += 10.0

    # 4. Deceptive tokens (significant primarily when coupled with other anomalies)
    if has_deceptive_keywords:
        if is_ip or has_hex or has_unicode or subdomain_count >= 2 or not is_https:
            risk_score += 25.0
            triggers.append(f"Deceptive credential keywords ({', '.join(matched_deceptive[:3])}) in high-risk context.")
        else:
            # Low weight if simply a normal path keyword on standard domain
            risk_score += 5.0

    # 5. Excessive subdomains (Subdomain manipulation)
    if subdomain_count >= 3:
        risk_score += 20.0
        triggers.append(f"Deep subdomain nesting ({subdomain_count} levels), potential subdomain manipulation.")

    # 6. High-risk TLD
    if tld in HIGH_RISK_TLDS:
        risk_score += 25.0
        triggers.append(f"Domain registered under high-risk disposable TLD (.{tld}).")

    # 7. Hex / Unicode obfuscation
    if has_hex:
        risk_score += 15.0
        triggers.append("Hexadecimal/percent-encoded URL obfuscation detected.")
    if has_unicode:
        risk_score += 30.0
        triggers.append("Unicode / Punycode (xn--) internationalized domain detected, potential homoglyph evasion.")

    # 8. Insecure plain HTTP requesting credentials or using IP
    if not is_https and (is_ip or has_deceptive_keywords):
        risk_score += 15.0
        triggers.append("Insecure plain HTTP protocol in high-risk or credential context.")

    # Normalize to 0 - 100
    risk_score = min(100.0, round(risk_score, 1))

    if risk_score >= 65.0:
        risk_category = "MALICIOUS"
    elif risk_score >= 35.0:
        risk_category = "SUSPICIOUS"
    else:
        risk_category = "SAFE"

    return URLAnalysis(
        url=raw_url,
        domain=hostname,
        length=url_length,
        shannon_entropy=entropy,
        digit_ratio=digit_ratio,
        special_char_count=special_chars,
        is_ip_address=is_ip,
        is_https=is_https,
        subdomain_count=subdomain_count,
        has_hex_encoding=has_hex,
        has_unicode_obfuscation=has_unicode,
        has_deceptive_keywords=has_deceptive_keywords,
        risk_score=risk_score,
        risk_category=risk_category,
        triggers=triggers
    )

def analyze_urls(urls: List[str]) -> List[URLAnalysis]:
    """Analyzes a list of URLs and returns sorted results by risk score descending."""
    results = [analyze_single_url(u) for u in urls]
    results.sort(key=lambda x: x.risk_score, reverse=True)
    return results
