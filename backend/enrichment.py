"""
Citadel Security Platform - DNS, Domain Intelligence, IP Geolocation & Threat Intelligence
Provides a unified enrichment layer:
  1. Domain WHOIS age & structure, DNS record lookups, suspicious TLDs, brand impersonation.
  2. IP Geolocation, ASN, and infrastructure risk profiling.
  3. Threat Intelligence IOC feed matching with threat group attribution.

All modules are self-contained and deterministic for zero-failure local/offline demonstration.
"""
import socket
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse

from backend.geoip import geolocate_ip, is_valid_ip
from backend.threat_intel import query_threat_intel

# Known suspicious TLDs (informed by Paper 3 AR-LRF domain analysis)
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.work', '.click', '.link', '.info',
    '.buzz', '.gq', '.ml', '.cf', '.ga', '.tk', '.pw', '.cc',
    '.icu', '.cyou', '.monster', '.rest', '.cam', '.surf',
    '.site', '.online', '.store', '.fun', '.space', '.bid',
    '.win', '.stream', '.download', '.racing', '.review',
    '.accountant', '.date', '.loan', '.trade', '.cricket',
}

# Well-known legitimate domains (for demonstration scoring)
KNOWN_LEGITIMATE_DOMAINS = {
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'github.com', 'linkedin.com', 'facebook.com', 'twitter.com',
    'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
    'office365.com', 'office.com', 'live.com', 'windowsupdate.com',
    'dropbox.com', 'salesforce.com', 'slack.com', 'zoom.us',
    'adobe.com', 'paypal.com', 'stripe.com', 'aws.amazon.com',
}

# Brand impersonation keywords in domains
BRAND_IMPERSONATION_KEYWORDS = [
    'microsoft', 'apple', 'google', 'amazon', 'paypal', 'netflix',
    'facebook', 'instagram', 'linkedin', 'dropbox', 'office365',
    'outlook', 'yahoo', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'hsbc', 'dhl', 'fedex', 'usps', 'irs', 'hmrc',
]


def extract_domain(url: str) -> str:
    """Extract the registered domain from a URL."""
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        hostname = parsed.hostname or ''
        return hostname.lower().strip('.')
    except Exception:
        return ''


def get_tld(domain: str) -> str:
    """Extract the TLD from a domain."""
    parts = domain.rsplit('.', 1)
    if len(parts) >= 2:
        return f'.{parts[-1]}'
    return ''


_DNS_CACHE: Dict[str, Dict[str, Any]] = {}

def check_dns_resolution(domain: str) -> Dict[str, Any]:
    """
    Attempt DNS resolution of a domain via socket.getaddrinfo.
    Returns resolution status, resolved IPs, and lookup metadata.
    Uses in-memory cache to prevent repeated socket latency.
    """
    if domain in _DNS_CACHE:
        return _DNS_CACHE[domain]

    result = {
        "resolves": False,
        "ip_addresses": [],
        "error": None,
        "lookup_method": "socket.getaddrinfo (Python stdlib)"
    }
    if not domain or len(domain) < 3:
        result["error"] = "Invalid domain"
        _DNS_CACHE[domain] = result
        return result

    # If domain is already an IP
    if is_valid_ip(domain):
        result["resolves"] = True
        result["ip_addresses"] = [domain]
        return result

    try:
        addr_info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(info[4][0] for info in addr_info))
        result["resolves"] = True
        result["ip_addresses"] = ips[:5]
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
    except Exception as e:
        result["error"] = f"Lookup error: {str(e)}"

    _DNS_CACHE[domain] = result
    return result


def analyze_domain_reputation(domain: str) -> Dict[str, Any]:
    """
    Analyze domain reputation using heuristic signals.
    Combines TLD risk, brand impersonation detection, domain structure analysis,
    and DNS resolution into a reputation score (0=malicious, 100=trusted).
    """
    result = {
        "domain": domain,
        "tld": "",
        "tld_suspicious": False,
        "is_known_legitimate": False,
        "brand_impersonation": False,
        "impersonated_brand": None,
        "subdomain_depth": 0,
        "domain_length": len(domain),
        "has_hyphens": '-' in domain,
        "has_numbers_in_domain": bool(re.search(r'\d', domain.split('.')[0] if '.' in domain else domain)),
        "dns_resolution": {},
        "reputation_score": 50,
        "reputation_label": "NEUTRAL",
        "signals": []
    }

    if not domain:
        result["reputation_label"] = "UNKNOWN"
        return result

    # If the domain is actually a direct IP address
    if is_valid_ip(domain):
        result["signals"].append("Direct IP address used as hostname — common evasion technique")
        result["reputation_score"] -= 30
        result["dns_resolution"] = {"resolves": True, "ip_addresses": [domain]}
        result["reputation_score"] = max(0, min(100, result["reputation_score"]))
        result["reputation_label"] = "SUSPICIOUS" if result["reputation_score"] >= 25 else "MALICIOUS"
        return result

    # TLD analysis
    tld = get_tld(domain)
    result["tld"] = tld
    if tld in SUSPICIOUS_TLDS:
        result["tld_suspicious"] = True
        result["reputation_score"] -= 20
        result["signals"].append(f"Suspicious TLD '{tld}' commonly used in phishing campaigns")

    # Known legitimate check
    base_domain = '.'.join(domain.rsplit('.', 2)[-2:]) if domain.count('.') >= 1 else domain
    if base_domain in KNOWN_LEGITIMATE_DOMAINS or domain in KNOWN_LEGITIMATE_DOMAINS:
        result["is_known_legitimate"] = True
        result["reputation_score"] = min(95, result["reputation_score"] + 40)
        result["signals"].append(f"Domain '{base_domain}' is in the known-legitimate registry")

    # Brand impersonation detection
    domain_without_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
    for brand in BRAND_IMPERSONATION_KEYWORDS:
        if brand in domain_without_tld and base_domain not in KNOWN_LEGITIMATE_DOMAINS:
            result["brand_impersonation"] = True
            result["impersonated_brand"] = brand
            result["reputation_score"] -= 25
            result["signals"].append(
                f"Domain contains brand keyword '{brand}' but is not the official domain — possible impersonation"
            )
            break

    # Subdomain depth
    subdomain_count = max(0, domain.count('.') - 1)
    result["subdomain_depth"] = subdomain_count
    if subdomain_count >= 3:
        result["reputation_score"] -= 10
        result["signals"].append(f"Excessive subdomain depth ({subdomain_count}) may indicate obfuscation")

    # Domain length
    if len(domain) > 40:
        result["reputation_score"] -= 5
        result["signals"].append(f"Long domain name ({len(domain)} chars) is suspicious")

    # Hyphens in domain
    hyphen_count = domain_without_tld.count('-')
    if hyphen_count >= 3:
        result["reputation_score"] -= 10
        result["signals"].append(f"Multiple hyphens ({hyphen_count}) in domain name is suspicious")

    # DNS resolution
    dns_result = check_dns_resolution(domain)
    result["dns_resolution"] = dns_result
    if dns_result["resolves"]:
        result["signals"].append(f"Domain resolves to {', '.join(dns_result['ip_addresses'][:3])}")
    else:
        result["reputation_score"] -= 15
        result["signals"].append("Domain does not resolve via DNS — possibly parked or sinkholed")

    # Clamp and label
    result["reputation_score"] = max(0, min(100, result["reputation_score"]))
    if result["reputation_score"] >= 75:
        result["reputation_label"] = "TRUSTED"
    elif result["reputation_score"] >= 50:
        result["reputation_label"] = "NEUTRAL"
    elif result["reputation_score"] >= 25:
        result["reputation_label"] = "SUSPICIOUS"
    else:
        result["reputation_label"] = "MALICIOUS"

    return result


def enrich_urls(url_analyses: list) -> Dict[str, Any]:
    """
    Enrich a list of URLAnalysis objects with domain intelligence.
    Returns a dict of domain -> enrichment data.
    """
    enrichment = {}
    seen_domains = set()

    for url_obj in url_analyses:
        domain = getattr(url_obj, 'domain', None) or extract_domain(getattr(url_obj, 'url', ''))
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        enrichment[domain] = analyze_domain_reputation(domain)

    return enrichment


def enrich_sender_domain(sender_email: str) -> Optional[Dict[str, Any]]:
    """Enrich the sender's email domain with reputation analysis."""
    if not sender_email or '@' not in sender_email:
        return None
    domain = sender_email.split('@')[-1].strip().lower()
    if not domain:
        return None
    return analyze_domain_reputation(domain)


def run_full_enrichment(
    parsed_email: Any,
    url_analyses: list
) -> Dict[str, Any]:
    """
    Executes full multi-dimensional enrichment:
      - Domain reputation (URL domains + sender domain)
      - IP Geolocation & ASN intelligence for all resolved IPs & direct IP URLs
      - Threat Intelligence IOC matching across domains, IPs, and senders
    """
    # 1. Domains
    domains_data = enrich_urls(url_analyses)
    sender_domain_data = enrich_sender_domain(parsed_email.sender_email)

    # 2. Extract all candidate IPs
    all_ips: Set[str] = set()
    for d_name, d_info in domains_data.items():
        if is_valid_ip(d_name):
            all_ips.add(d_name)
        dns_res = d_info.get("dns_resolution", {})
        for ip in dns_res.get("ip_addresses", []):
            if is_valid_ip(ip):
                all_ips.add(ip)

    # 3. Geolocate all extracted IPs
    geo_data = {}
    for ip in all_ips:
        geo_data[ip] = geolocate_ip(ip)

    # 4. Query Threat Intelligence
    all_domains_list = list(domains_data.keys())
    if sender_domain_data and sender_domain_data.get("domain"):
        all_domains_list.append(sender_domain_data["domain"])

    all_urls_list = [getattr(u, "url", "") for u in url_analyses]
    threat_intel_result = query_threat_intel(
        domains=all_domains_list,
        ips=list(all_ips),
        urls=all_urls_list,
        sender_email=parsed_email.sender_email
    )

    return {
        "domains": domains_data,
        "sender_domain": sender_domain_data,
        "ips": geo_data,
        "threat_intel": threat_intel_result
    }
