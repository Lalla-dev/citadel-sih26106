"""
Citadel Security Platform - Data Schemas
Defines structured schemas for email analysis, forensic metadata, and detection verdicts.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid
import itertools

# Thread-safe counter for readable case IDs
_case_counter = itertools.count(1)

def generate_case_id() -> str:
    """Generate a human-readable case identifier e.g. CASE-2026-0001"""
    year = datetime.now(timezone.utc).year
    return f"CASE-{year}-{next(_case_counter):04d}"

class AuthResultDetail(BaseModel):
    status: str = "none"  # pass, fail, softfail, neutral, none, permerror
    raw_header: Optional[str] = None
    domain: Optional[str] = None

class AuthenticationAnalysis(BaseModel):
    spf: AuthResultDetail = Field(default_factory=AuthResultDetail)
    dkim: AuthResultDetail = Field(default_factory=AuthResultDetail)
    dmarc: AuthResultDetail = Field(default_factory=AuthResultDetail)
    live_verified: bool = False
    verification_method: str = "Header Parsing (Static RFC 5322)"
    notes: str = (
        "Authentication statuses are parsed directly from Received-SPF / Authentication-Results "
        "headers in the message. These have NOT been independently resolved via live DNS lookup."
    )
    sender_alignment_pass: bool = True
    display_name_spoofed: bool = False
    reply_to_mismatch: bool = False
    envelope_from_mismatch: bool = False
    spoof_details: List[str] = Field(default_factory=list)

class URLAnalysis(BaseModel):
    url: str
    domain: str
    length: int
    shannon_entropy: float
    digit_ratio: float
    special_char_count: int
    is_ip_address: bool
    is_https: bool
    subdomain_count: int
    has_hex_encoding: bool
    has_unicode_obfuscation: bool
    has_deceptive_keywords: bool
    risk_score: float = 0.0  # 0.0 - 100.0
    risk_category: str = "SAFE"  # SAFE, SUSPICIOUS, MALICIOUS
    triggers: List[str] = Field(default_factory=list)

class DetectionReason(BaseModel):
    category: str  # Authentication, URL, Urgency, Financial/BEC, Authority
    description: str
    weight: float
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL

class IntentAnalysis(BaseModel):
    urgency_detected: bool = False
    urgency_keywords: List[str] = Field(default_factory=list)
    financial_wire_detected: bool = False
    financial_keywords: List[str] = Field(default_factory=list)
    authority_pretext_detected: bool = False
    authority_keywords: List[str] = Field(default_factory=list)
    overall_intent_score: float = 0.0

class EmailMetadata(BaseModel):
    subject: str = ""
    sender: str = ""
    sender_display_name: str = ""
    sender_email: str = ""
    recipient: str = ""
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None

class MLClassification(BaseModel):
    ml_available: bool = False
    predicted_label: str = "unknown"
    probabilities: Dict[str, float] = Field(default_factory=dict)
    ml_confidence: float = 0.0
    model_type: str = "TF-IDF + Logistic Regression"
    model_disclaimer: str = (
        "Trained on synthetic benchmark corpus. Probabilities complement the heuristic engine and "
        "do NOT represent standalone production accuracy."
    )

class ContextualNLPAnalysis(BaseModel):
    nlp_engine: str = "Contextual Pretexting Vectorizer (RoBERTa-Aligned Fallback)"
    dominant_archetype: str = "UNKNOWN"
    archetype_similarities: Dict[str, float] = Field(default_factory=dict)
    coercion_score: float = 0.0
    coercion_level: str = "LOW"
    coercion_breakdown: Dict[str, List[str]] = Field(default_factory=dict)
    tone: str = "NEUTRAL"

class EvidenceIntegrity(BaseModel):
    evidence_sha256: str = ""
    verdict_sha256: str = ""
    merkle_root: str = ""
    block_index: int = 0
    block_hash: str = ""
    previous_block_hash: str = ""
    chain_of_custody_timestamp: str = ""
    integrity_status: str = "INTEGRITY: VERIFIED"
    ledger_name: str = "Citadel Tamper-Evident Cryptographic Ledger"
    verification_endpoint: str = ""

class AnalysisResult(BaseModel):
    case_id: str = Field(default_factory=generate_case_id)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    filename: str = "unnamed.eml"
    metadata: EmailMetadata = Field(default_factory=EmailMetadata)
    authentication: AuthenticationAnalysis = Field(default_factory=AuthenticationAnalysis)
    urls: List[URLAnalysis] = Field(default_factory=list)
    intent: IntentAnalysis = Field(default_factory=IntentAnalysis)
    ml_classification: MLClassification = Field(default_factory=MLClassification)
    nlp_analysis: ContextualNLPAnalysis = Field(default_factory=ContextualNLPAnalysis)
    threat_score: int = 0  # 0 to 100
    confidence: float = 0.0  # 0.0 to 1.0 calibrated heuristic confidence
    confidence_type: str = "Multi-Signal Convergence (Heuristic + ML + NLP + Intel)"
    confidence_label: str = "Unified Confidence"
    confidence_disclaimer: str = (
        "Calibrated across independent security signals: MIME headers, lexical URLs, ML classifier, "
        "contextual NLP pretexting, and threat intelligence feeds. Does not represent standalone model accuracy."
    )
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    threat_archetype: str = "Clean Email"
    reasons: List[DetectionReason] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    body_text_preview: str = ""
    enrichment: Optional[Dict[str, Any]] = None
    threat_graph: Optional[Dict[str, Any]] = None
    integrity: Optional[EvidenceIntegrity] = None
