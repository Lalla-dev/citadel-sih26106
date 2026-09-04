"""
Citadel Security Platform - Forensic Incident Reporting & Dossier Export (Phase 8)
Generates comprehensive forensic incident dossiers based on real AnalysisResult data:
  1. Printable HTML Forensic Dossier (Executive overview, header forensics, URL IOCs,
     ML/NLP analysis, curated threat intelligence, graph summary, evidence integrity, and playbook).
  2. SIEM/SOAR-Ready Structured JSON Export.
"""
import os
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.schemas import AnalysisResult

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(['html', 'xml'])
)

# Centralized In-Memory Case Store for Analyzed Results
_CASE_RESULTS_STORE: Dict[str, AnalysisResult] = {}


def store_case_result(result: AnalysisResult) -> None:
    """Stores the complete AnalysisResult indexed by case_id."""
    if result and result.case_id:
        _CASE_RESULTS_STORE[result.case_id] = result


def get_case_result(case_id: str) -> Optional[AnalysisResult]:
    """
    Retrieves an AnalysisResult by case_id.
    Checks memory cache first, then rehydrates from persistent relational database
    so forensic reports work seamlessly across application restarts.
    """
    if case_id in _CASE_RESULTS_STORE:
        return _CASE_RESULTS_STORE[case_id]

    try:
        from backend.cases import get_case_repository
        ticket = get_case_repository().get_case(case_id)
        if ticket and ticket.analysis_result:
            _CASE_RESULTS_STORE[case_id] = ticket.analysis_result
            return ticket.analysis_result
    except Exception:
        pass

    return None


def generate_executive_summary(result: AnalysisResult) -> str:
    """
    Generates a concise, analyst-readable executive summary directly from real detection data.
    """
    if result.threat_score >= 80:
        severity_desc = f"CRITICAL incident (Threat Score: {result.threat_score}/100) classified as '{result.threat_archetype}'"
    elif result.threat_score >= 50:
        severity_desc = f"ELEVATED RISK incident (Threat Score: {result.threat_score}/100) classified as '{result.threat_archetype}'"
    else:
        severity_desc = f"LOW RISK message (Threat Score: {result.threat_score}/100) classified as '{result.threat_archetype}'"

    # Top risk reasons
    if result.reasons:
        reasons_summary = "; ".join([r.description for r in result.reasons[:3]])
        why_suspicious = f"Key contributing risk factors include: {reasons_summary}."
    else:
        why_suspicious = "No significant risk anomalies or policy violations were detected."

    # Top recommended action
    if result.recommended_actions:
        action_summary = f"Priority SOC Action: {result.recommended_actions[0]}"
    else:
        action_summary = "Priority SOC Action: No intervention required; message appears standard."

    # ML/NLP highlight
    ml_label = getattr(result.ml_classification, "predicted_label", "unknown")
    coercion = getattr(result.nlp_analysis, "coercion_score", 0.0)
    if coercion >= 0.5:
        nlp_highlight = f"Contextual NLP detected severe psychological coercion (Coercion Index: {coercion:.2f})."
    else:
        nlp_highlight = f"Machine learning classifier indicated label '{ml_label}'."

    return f"Citadel detected a {severity_desc}. {why_suspicious} {nlp_highlight} {action_summary}."


def generate_html_report(result: AnalysisResult) -> str:
    """
    Renders the printable HTML forensic incident dossier using Jinja2.
    """
    template = jinja_env.get_template("forensic_report.html")
    exec_summary = generate_executive_summary(result)
    return template.render(
        result=result,
        executive_summary=exec_summary,
        generated_at=datetime.now(timezone.utc).isoformat()
    )


def generate_json_report(result: AnalysisResult) -> Dict[str, Any]:
    """
    Produces a comprehensive, SIEM/SOAR-ready structured JSON forensic export.
    """
    exec_summary = generate_executive_summary(result)
    raw_dict = result.model_dump()

    # Structure into standardized SOC forensic export schema
    return {
        "format_version": "Citadel-Forensic-Dossier-v1.0",
        "export_type": "SIEM_SOAR_STRUCTURED_FORENSIC_EXPORT",
        "export_timestamp": datetime.now(timezone.utc).isoformat(),
        "case_identification": {
            "case_id": result.case_id,
            "timestamp": result.timestamp,
            "filename": result.filename,
            "risk_level": result.risk_level,
            "threat_score": result.threat_score,
            "threat_archetype": result.threat_archetype,
            "confidence": result.confidence,
            "confidence_type": result.confidence_type,
            "confidence_disclaimer": result.confidence_disclaimer
        },
        "executive_summary": exec_summary,
        "email_forensics": {
            "metadata": raw_dict.get("metadata", {}),
            "body_preview": result.body_text_preview
        },
        "authentication_analysis": {
            "disclaimer": getattr(result.authentication, "notes", "SPF/DKIM/DMARC results are extracted via static header parsing."),
            "verification_method": getattr(result.authentication, "verification_method", "Header Parsing (Static RFC 5322)"),
            "spf_status": getattr(result.authentication.spf, "status", "none") if hasattr(result.authentication, "spf") else "none",
            "dkim_status": getattr(result.authentication.dkim, "status", "none") if hasattr(result.authentication, "dkim") else "none",
            "dmarc_status": getattr(result.authentication.dmarc, "status", "none") if hasattr(result.authentication, "dmarc") else "none",
            "reply_to_mismatch": getattr(result.authentication, "reply_to_mismatch", False),
            "display_name_spoofed": getattr(result.authentication, "display_name_spoofed", False),
            "envelope_from_mismatch": getattr(result.authentication, "envelope_from_mismatch", False),
            "spoof_details": getattr(result.authentication, "spoof_details", [])
        },
        "url_ioc_analysis": {
            "url_count": len(result.urls),
            "urls": [u.model_dump() for u in result.urls]
        },
        "ml_nlp_analysis": {
            "ml_classification": raw_dict.get("ml_classification") or {},
            "contextual_nlp_pretexting": raw_dict.get("nlp_analysis") or {},
            "heuristic_intent": raw_dict.get("intent") or {}
        },
        "threat_intelligence_enrichment": {
            "notice": "Enrichment data and threat actor attribution originate from Citadel Curated Threat Intelligence and offline ASN databases.",
            "enrichment": raw_dict.get("enrichment") or {}
        },
        "correlation_graph_summary": {
            "node_count": len((raw_dict.get("threat_graph") or {}).get("nodes") or []),
            "edge_count": len((raw_dict.get("threat_graph") or {}).get("edges") or []),
            "nodes": (raw_dict.get("threat_graph") or {}).get("nodes") or [],
            "edges": (raw_dict.get("threat_graph") or {}).get("edges") or []
        },
        "evidence_integrity": raw_dict.get("integrity") or {},
        "detection_reasoning": [r.model_dump() for r in result.reasons],
        "recommended_soc_actions": result.recommended_actions
    }
