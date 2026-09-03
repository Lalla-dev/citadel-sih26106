"""
Citadel Security Platform - Email Header & Authentication Analyzer
Parses RFC 5322 authentication headers (SPF, DKIM, DMARC), detects display name spoofing,
and checks for Envelope-From/Reply-To divergence.
"""
import re
from typing import List, Tuple, Optional
from urllib.parse import urlparse
from backend.parser import ParsedEmail
from backend.schemas import AuthenticationAnalysis, AuthResultDetail

# High-risk executive titles and sensitive role terms for impersonation checks
VIP_ROLE_PATTERNS = [
    r'\bceo\b', r'\bcfo\b', r'\bcoo\b', r'\bcto\b', r'\bchief\s+executive\b',
    r'\bchief\s+financial\b', r'\bpresident\b', r'\bdirector\b',
    r'\bpayroll\b', r'\bhuman\s+resources\b', r'\baccounting\b',
    r'\bit\s+support\b', r'\bhelpdesk\b', r'\bsystem\s+admin\b',
    r'\bboard\s+of\s+directors\b', r'\bmanaging\s+director\b'
]

# Free webmail and generic consumer domains frequently abused in spoofing
FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "proton.me", "mail.com", "zoho.com", "yandex.com",
    "icloud.com", "gmx.com", "tutanota.com"
}

def extract_domain(email_addr: str) -> str:
    """Extract lowercase domain portion of an email address."""
    if not email_addr or "@" not in email_addr:
        return ""
    return email_addr.split("@")[-1].strip().lower()

def parse_auth_header(auth_results_str: str, mech: str) -> AuthResultDetail:
    """
    Parses SPF, DKIM, or DMARC status tokens from an Authentication-Results header.
    mech can be 'spf', 'dkim', or 'dmarc'.
    """
    detail = AuthResultDetail(status="none")
    if not auth_results_str:
        return detail

    detail.raw_header = auth_results_str.strip()
    
    # Matches e.g. "spf=pass", "dkim=fail (bad sig)", "dmarc=pass"
    pattern = rf'\b{mech}\s*=\s*([a-zA-Z0-9_\-]+)'
    match = re.search(pattern, auth_results_str, re.IGNORECASE)
    if match:
        status_token = match.group(1).lower()
        detail.status = status_token

    # Extract header.d=domain or smtp.mailfrom=domain
    if mech == "dkim":
        d_match = re.search(r'header\.d\s*=\s*([a-zA-Z0-9.\-]+)', auth_results_str, re.IGNORECASE)
        if d_match:
            detail.domain = d_match.group(1).lower()
    elif mech == "spf":
        from_match = re.search(r'smtp\.mailfrom\s*=\s*([a-zA-Z0-9.\-@]+)', auth_results_str, re.IGNORECASE)
        if from_match:
            detail.domain = extract_domain(from_match.group(1))

    return detail

def analyze_headers(parsed_email: ParsedEmail) -> AuthenticationAnalysis:
    """
    Analyzes authentication mechanisms, display name spoofing, and sender mismatches.
    Explicitly tags results as static parsed headers (not live DNS verified).
    """
    auth = AuthenticationAnalysis()
    auth.live_verified = False  # Explicitly documented
    auth.verification_method = "Header Parsing (Static RFC 5322)"

    # 1. Parse Authentication-Results or Received-SPF headers
    auth_results_header = parsed_email.headers.get("authentication-results", "")
    received_spf_header = parsed_email.headers.get("received-spf", "")

    if auth_results_header:
        auth.spf = parse_auth_header(auth_results_header, "spf")
        auth.dkim = parse_auth_header(auth_results_header, "dkim")
        auth.dmarc = parse_auth_header(auth_results_header, "dmarc")

    # Fallback to Received-SPF header if SPF was not captured above
    if auth.spf.status == "none" and received_spf_header:
        auth.spf.raw_header = received_spf_header
        spf_token_match = re.match(r'^\s*([a-zA-Z0-9_\-]+)', received_spf_header)
        if spf_token_match:
            auth.spf.status = spf_token_match.group(1).lower()

    # 2. Sender Alignment & Envelope Checks
    from_domain = extract_domain(parsed_email.sender_email)
    return_path_domain = extract_domain(parsed_email.return_path)
    reply_to_domain = extract_domain(parsed_email.reply_to_email)

    # Envelope-From vs Header-From check
    if return_path_domain and from_domain and return_path_domain != from_domain:
        auth.envelope_from_mismatch = True
        auth.sender_alignment_pass = False
        auth.spoof_details.append(
            f"Envelope From domain mismatch: Header From is '{from_domain}', but Return-Path is '{return_path_domain}'."
        )

    # From vs Reply-To divergence check (very common in BEC redirect attacks)
    if parsed_email.reply_to_email and parsed_email.sender_email:
        if parsed_email.reply_to_email != parsed_email.sender_email:
            if reply_to_domain and from_domain and reply_to_domain != from_domain:
                # High-risk cross-domain diversion
                auth.reply_to_mismatch = True
                auth.sender_alignment_pass = False
                auth.spoof_details.append(
                    f"Reply-To cross-domain diversion: Responses redirected to external domain '{reply_to_domain}' ({parsed_email.reply_to_email}) instead of sender domain '{from_domain}'."
                )
            else:
                # Same domain department routing (e.g. newsletter@company.com -> support@company.com)
                auth.spoof_details.append(
                    f"Notice: Reply-To points to internal department alias '{parsed_email.reply_to_email}' within same domain."
                )

    # 3. Display Name Spoofing & Impersonation Checks
    display_name = parsed_email.sender_display_name
    if display_name:
        # Check A: Display name embeds a fake email address (e.g. "it-admin@company.com" <attacker@evil.com>)
        embedded_email = re.search(r'([a-zA-Z0-9.\-_+]+@[a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,})', display_name)
        if embedded_email:
            embedded_addr = embedded_email.group(1).lower()
            if embedded_addr != parsed_email.sender_email:
                auth.display_name_spoofed = True
                auth.spoof_details.append(
                    f"Deceptive Display Name: Display name contains address '{embedded_addr}' which conflicts with actual sender '{parsed_email.sender_email}'."
                )

        # Check B: High-privilege role/executive title used from free public webmail
        disp_lower = display_name.lower()
        for role_pat in VIP_ROLE_PATTERNS:
            if re.search(role_pat, disp_lower):
                if from_domain in FREE_WEBMAIL_DOMAINS:
                    auth.display_name_spoofed = True
                    auth.spoof_details.append(
                        f"Executive/Role Impersonation: Display name references role '{display_name}' but sender domain '{from_domain}' is a free public webmail provider."
                    )
                    break

    return auth
