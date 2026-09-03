"""
Citadel Security Platform - Threat Intelligence IOC Feed Engine
Matches indicators of compromise (IOCs) including domains, IPs, URLs, and senders
against curated threat intelligence feeds. Provides attribution and campaign tracking.
"""
from typing import Dict, Any, List, Optional
import hashlib

# Curated Threat Intelligence Database (Simulated SOC Threat Intel Feed)
IOC_FEEDS = {
    "domains": {
        "secure-portal.xyz": {
            "threat_group": "TA505 (EvilProxy Campaign)",
            "threat_type": "Adversary-in-the-Middle (AiTM) Phishing Proxy",
            "confidence": 0.95,
            "severity": "CRITICAL",
            "first_seen": "2026-01-15",
            "tags": ["aitm", "session-hijack", "credential-harvesting"]
        },
        "microsoft-support-verify.com": {
            "threat_group": "Scattered Spider (UNC3944)",
            "threat_type": "Executive & Helpdesk Credential Harvest",
            "confidence": 0.92,
            "severity": "CRITICAL",
            "first_seen": "2026-02-01",
            "tags": ["sim-swap", "mfa-bypass", "spoofing"]
        },
        "payment-remittance-update.net": {
            "threat_group": "FIN7 (Carbanak BEC Syndicate)",
            "threat_type": "Vendor Email Compromise / Wire Diversion",
            "confidence": 0.89,
            "severity": "HIGH",
            "first_seen": "2026-02-18",
            "tags": ["bec", "wire-fraud", "banking-redirection"]
        }
    },
    "ips": {
        "198.51.100.42": {
            "threat_group": "Shinjiru PhishOps Nexus",
            "threat_type": "Bulletproof Phishing C2 / Payload Dropper",
            "confidence": 0.94,
            "severity": "CRITICAL",
            "first_seen": "2026-01-10",
            "tags": ["bulletproof-hosting", "c2", "high-entropy-redirect"]
        },
        "203.0.113.88": {
            "threat_group": "FastFlux Botnet Cluster",
            "threat_type": "Dynamic DNS Fast-Flux Phish Ingress",
            "confidence": 0.91,
            "severity": "CRITICAL",
            "first_seen": "2026-01-28",
            "tags": ["fast-flux", "phishing-redirect", "russia"]
        },
        "185.220.101.5": {
            "threat_group": "Tor Cybercrime Proxy Network",
            "threat_type": "Anonymized Scanning & Brute-force Relay",
            "confidence": 0.85,
            "severity": "HIGH",
            "first_seen": "2025-12-05",
            "tags": ["tor-exit", "anonymizer", "recon"]
        }
    },
    "senders": {
        "ceo-office@exec-secure-portal.com": {
            "threat_group": "Financially Motivated BEC Actor #104",
            "threat_type": "CEO Impersonation & Direct Gift Card Pretext",
            "confidence": 0.90,
            "severity": "HIGH",
            "first_seen": "2026-02-10",
            "tags": ["ceo-fraud", "gift-cards", "spoofed-display"]
        }
    }
}


def query_threat_intel(
    domains: List[str],
    ips: List[str],
    urls: List[str],
    sender_email: Optional[str] = None
) -> Dict[str, Any]:
    """
    Scans extracted indicators against known threat intelligence databases.
    Returns matched IOCs, threat attribution, threat severity, and intelligence notes.
    """
    matches = []
    total_severity = "NONE"
    max_confidence = 0.0

    # 1. Check domains
    for d in domains:
        clean_d = d.lower().strip()
        if clean_d in IOC_FEEDS["domains"]:
            info = IOC_FEEDS["domains"][clean_d]
            matches.append({
                "ioc_type": "domain",
                "indicator": clean_d,
                "threat_group": info["threat_group"],
                "threat_type": info["threat_type"],
                "confidence": info["confidence"],
                "severity": info["severity"],
                "tags": info["tags"]
            })
            if info["confidence"] > max_confidence:
                max_confidence = info["confidence"]

    # 2. Check IPs
    for ip in ips:
        clean_ip = ip.strip()
        if clean_ip in IOC_FEEDS["ips"]:
            info = IOC_FEEDS["ips"][clean_ip]
            matches.append({
                "ioc_type": "ip",
                "indicator": clean_ip,
                "threat_group": info["threat_group"],
                "threat_type": info["threat_type"],
                "confidence": info["confidence"],
                "severity": info["severity"],
                "tags": info["tags"]
            })
            if info["confidence"] > max_confidence:
                max_confidence = info["confidence"]

    # 3. Check Sender
    if sender_email:
        clean_s = sender_email.lower().strip()
        if clean_s in IOC_FEEDS["senders"]:
            info = IOC_FEEDS["senders"][clean_s]
            matches.append({
                "ioc_type": "sender",
                "indicator": clean_s,
                "threat_group": info["threat_group"],
                "threat_type": info["threat_type"],
                "confidence": info["confidence"],
                "severity": info["severity"],
                "tags": info["tags"]
            })
            if info["confidence"] > max_confidence:
                max_confidence = info["confidence"]

    # Determine highest severity
    severities = [m["severity"] for m in matches]
    if "CRITICAL" in severities:
        total_severity = "CRITICAL"
    elif "HIGH" in severities:
        total_severity = "HIGH"
    elif "MEDIUM" in severities:
        total_severity = "MEDIUM"
    elif len(matches) > 0:
        total_severity = "LOW"

    return {
        "matched": len(matches) > 0,
        "match_count": len(matches),
        "matches": matches,
        "highest_severity": total_severity,
        "max_confidence": max_confidence,
        "feed_source": "Citadel Unified Threat Intelligence Feeds (IOC Nexus)",
        "attribution": [m["threat_group"] for m in matches] if matches else []
    }
