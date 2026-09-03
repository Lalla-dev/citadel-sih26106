"""
Citadel Security Platform - Email Parser Module
Parses RFC 5322 .eml messages, extracts headers, body content, and embedded URLs.
"""
import re
import email
from email import policy
from email.header import decode_header, make_header
from email.utils import parseaddr
from typing import Dict, List, Tuple, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Regular expression to catch URLs in raw text
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[a-zA-Z0-9.\-_~:/?#[\]@!$&\'()*+,;=%]+',
    re.IGNORECASE
)

def decode_mime_header(header_value: Optional[str]) -> str:
    """Safely decode RFC 2047 encoded headers (e.g. UTF-8 or Base64 encoded subjects)."""
    if not header_value:
        return ""
    try:
        decoded_segments = decode_header(header_value)
        return str(make_header(decoded_segments))
    except Exception:
        return str(header_value)

class ParsedEmail:
    """Holds parsed components of an RFC 5322 email message."""
    def __init__(self):
        self.headers: Dict[str, str] = {}
        self.raw_headers: List[Tuple[str, str]] = []
        self.subject: str = ""
        self.sender_display_name: str = ""
        self.sender_email: str = ""
        self.recipient: str = ""
        self.reply_to_display_name: str = ""
        self.reply_to_email: str = ""
        self.return_path: str = ""
        self.date: str = ""
        self.message_id: str = ""
        self.plain_body: str = ""
        self.html_body: str = ""
        self.normalized_body: str = ""
        self.urls: List[str] = []
        self.raw_eml_bytes: bytes = b""

def parse_eml(eml_bytes_or_str: Any) -> ParsedEmail:
    """
    Parses raw .eml bytes or string into a structured ParsedEmail object.
    Preserves exact original raw bytes for cryptographic evidence hashing.
    """
    if isinstance(eml_bytes_or_str, str):
        raw_bytes = eml_bytes_or_str.encode("utf-8", errors="replace")
        msg = email.message_from_string(eml_bytes_or_str, policy=policy.default)
    else:
        raw_bytes = bytes(eml_bytes_or_str)
        msg = email.message_from_bytes(eml_bytes_or_str, policy=policy.default)

    parsed = ParsedEmail()
    parsed.raw_eml_bytes = raw_bytes

    # 1. Extract and normalize headers
    for k, v in msg.items():
        parsed.raw_headers.append((k, str(v)))
        parsed.headers[k.lower()] = str(v)

    parsed.subject = decode_mime_header(msg.get("Subject", ""))
    
    # Sender details
    raw_from = msg.get("From", "")
    from_disp, from_addr = parseaddr(raw_from)
    parsed.sender_display_name = decode_mime_header(from_disp).strip()
    parsed.sender_email = from_addr.strip().lower()

    # Recipient
    parsed.recipient = decode_mime_header(msg.get("To", "")).strip()

    # Reply-To details
    raw_reply_to = msg.get("Reply-To", "")
    reply_disp, reply_addr = parseaddr(raw_reply_to)
    parsed.reply_to_display_name = decode_mime_header(reply_disp).strip()
    parsed.reply_to_email = reply_addr.strip().lower()

    # Return-Path / Envelope-From
    raw_return_path = msg.get("Return-Path", "")
    _, return_addr = parseaddr(raw_return_path)
    parsed.return_path = return_addr.strip().lower()

    parsed.date = str(msg.get("Date", ""))
    parsed.message_id = str(msg.get("Message-ID", "")).strip()

    # 2. Extract Body Parts (walking the MIME tree)
    plain_parts: List[str] = []
    html_parts: List[str] = []
    extracted_urls: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Skip attachment files
            if "attachment" in content_disposition.lower():
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset()
                    text = None
                    if charset:
                        try:
                            text = payload.decode(charset, errors="replace")
                        except (LookupError, ValueError):
                            text = None
                    if text is None:
                        # Safe fallback to utf-8 then latin-1 with character replacement
                        try:
                            text = payload.decode("utf-8", errors="replace")
                        except Exception:
                            text = payload.decode("latin-1", errors="replace")

                    if content_type == "text/plain":
                        plain_parts.append(text)
                    elif content_type == "text/html":
                        html_parts.append(text)
            except Exception:
                continue
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset()
                text = None
                if charset:
                    try:
                        text = payload.decode(charset, errors="replace")
                    except (LookupError, ValueError):
                        text = None
                if text is None:
                    try:
                        text = payload.decode("utf-8", errors="replace")
                    except Exception:
                        text = payload.decode("latin-1", errors="replace")

                if content_type == "text/html":
                    html_parts.append(text)
                else:
                    plain_parts.append(text)
        except Exception:
            pass

    parsed.plain_body = "\n".join(plain_parts).strip()
    parsed.html_body = "\n".join(html_parts).strip()

    # 3. Derive clean normalized text and extract URLs
    if parsed.html_body:
        try:
            soup = BeautifulSoup(parsed.html_body, "html.parser")
            # Extract links from href attributes
            for a_tag in soup.find_all("a", href=True):
                href = str(a_tag["href"]).strip()
                if href and href.lower().startswith(("http://", "https://", "www.")):
                    extracted_urls.append(href)
            
            # Extract text from HTML
            html_text = soup.get_text(separator=" ", strip=True)
            if not parsed.plain_body:
                parsed.normalized_body = html_text
            else:
                parsed.normalized_body = parsed.plain_body
        except Exception:
            parsed.normalized_body = parsed.plain_body
    else:
        parsed.normalized_body = parsed.plain_body

    # Extract any URLs present in plain text body
    if parsed.normalized_body:
        try:
            text_urls = URL_REGEX.findall(parsed.normalized_body)
            extracted_urls.extend(text_urls)
        except Exception:
            pass

    # Clean & Deduplicate URLs while preserving order
    seen = set()
    cleaned_urls = []
    for u in extracted_urls:
        if not u or not isinstance(u, str):
            continue
        u_clean = u.rstrip(".,;)>'\" \r\n\t")
        if u_clean and u_clean not in seen:
            seen.add(u_clean)
            cleaned_urls.append(u_clean)
    parsed.urls = cleaned_urls

    return parsed
