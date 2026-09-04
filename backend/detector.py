"""
Citadel Security Platform - Threat Detection & BEC Scoring Engine
Provides a modular heuristic & rule-based detection foundation for Phase 1.
Architecture designed for seamless plug-in of ML (TF-IDF/LR) and Transformer models in subsequent phases.
"""
import re
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Any, Optional
from backend.parser import ParsedEmail
from backend.schemas import (
    AuthenticationAnalysis, URLAnalysis, DetectionReason,
    IntentAnalysis, AnalysisResult, EmailMetadata, generate_case_id
)

# Core Intent Dictionaries (Informed by Paper 2 BEC Taxonomy and Paper 4 Phishing Triggers)
URGENCY_PATTERNS = [
    r'\burgent\b', r'\bimmediate(?:ly)?\b', r'\baction\s+required\b',
    r'\bwithin\s+(?:24|12|48)\s*hours?\b', r'\basap\b', r'\bpromptly\b',
    r'\bfinal\s+notice\b', r'\baccount\s+suspended\b', r'\bdeadline\b',
    r'\btime\s+sensitive\b', r'\bcritical\s+update\b', r'\bexpire(?:s|d)?\b'
]

FINANCIAL_PATTERNS = [
    r'\bwire\s+transfer\b', r'\bbank\s+(?:account|details)\b',
    r'\brouting\s+number\b', r'\bnew\s+banking\s+instructions?\b',
    r'\bchanged?\s+(?:our\s+)?bank\b', r'\binvoice\b', r'\bremittance\b',
    r'\bswift(?:\s+code)?\b', r'\bpayment\s+(?:due|request|details)\b',
    r'\bgift\s+cards?\b', r'\bpayroll\b', r'\bdirect\s+deposit\b',
    r'\bach\b', r'\bunauthorized\s+transaction\b', r'\bfunds?\s+transfer\b'
]

AUTHORITY_PATTERNS = [
    r'\bstrictly\s+confidential\b', r'\bdo\s+not\s+(?:call|discuss|mention)\b',
    r'\bi(?:\'?m|\s+am)\s+in\s+a\s+meeting\b', r'\bexecutive\s+approval\b',
    r'\bboard\s+of\s+directors\b', r'\bhandling\s+this\s+personally\b',
    r'\bacquisition\b', r'\bauthorized\s+by\s+the\s+ceo\b',
    r'\bprivileged\s+and\s+confidential\b', r'\bkeep\s+this\s+quiet\b'
]

class BaseDetector(ABC):
    """Abstract interface to enable modular extension with ML and Transformer engines."""
    @abstractmethod
    def evaluate(
        self,
        parsed_email: ParsedEmail,
        auth: AuthenticationAnalysis,
        urls: List[URLAnalysis]
    ) -> Tuple[int, float, str, str, IntentAnalysis, List[DetectionReason], List[str]]:
        """
        Returns:
            (threat_score, confidence, risk_level, threat_archetype, intent, reasons, actions)
        """
        pass

class HeuristicRuleDetector(BaseDetector):
    """
    Phase 1 Heuristic & Rule-Based Detection Engine.
    Combines header spoofing detection, URL risk intelligence, and BEC social engineering intent analysis.
    """
    def __init__(self):
        self.urgency_regex = [re.compile(p, re.IGNORECASE) for p in URGENCY_PATTERNS]
        self.financial_regex = [re.compile(p, re.IGNORECASE) for p in FINANCIAL_PATTERNS]
        self.authority_regex = [re.compile(p, re.IGNORECASE) for p in AUTHORITY_PATTERNS]

    def _extract_intent(self, text: str) -> IntentAnalysis:
        intent = IntentAnalysis()
        if not text:
            return intent

        for rx in self.urgency_regex:
            m = rx.search(text)
            if m:
                intent.urgency_detected = True
                intent.urgency_keywords.append(m.group(0).lower())

        for rx in self.financial_regex:
            m = rx.search(text)
            if m:
                intent.financial_wire_detected = True
                intent.financial_keywords.append(m.group(0).lower())

        for rx in self.authority_regex:
            m = rx.search(text)
            if m:
                intent.authority_pretext_detected = True
                intent.authority_keywords.append(m.group(0).lower())

        # Deduplicate matched keywords
        intent.urgency_keywords = sorted(list(set(intent.urgency_keywords)))
        intent.financial_keywords = sorted(list(set(intent.financial_keywords)))
        intent.authority_keywords = sorted(list(set(intent.authority_keywords)))

        score = 0.0
        if intent.urgency_detected:
            score += 25.0 * min(3, len(intent.urgency_keywords)) / 3.0
        if intent.financial_wire_detected:
            score += 35.0 * min(3, len(intent.financial_keywords)) / 3.0
        if intent.authority_pretext_detected:
            score += 25.0 * min(3, len(intent.authority_keywords)) / 3.0

        intent.overall_intent_score = min(100.0, round(score, 1))
        return intent

    def evaluate(
        self,
        parsed_email: ParsedEmail,
        auth: AuthenticationAnalysis,
        urls: List[URLAnalysis]
    ) -> Tuple[int, float, str, str, IntentAnalysis, List[DetectionReason], List[str]]:
        
        reasons: List[DetectionReason] = []
        actions: List[str] = []
        raw_score = 0.0
        
        # Combined full text for intent scanning
        full_text = f"{parsed_email.subject}\n{parsed_email.normalized_body}"
        intent = self._extract_intent(full_text)

        # -------------------------------------------------------------
        # 1. Header & Identity Spoofing Evaluation (Paper 2)
        # -------------------------------------------------------------
        if auth.display_name_spoofed:
            raw_score += 40.0
            for d in auth.spoof_details:
                if "Display Name" in d or "Impersonation" in d:
                    reasons.append(DetectionReason(
                        category="Identity & Header",
                        description=d,
                        weight=40.0,
                        severity="CRITICAL"
                    ))

        if auth.reply_to_mismatch:
            raw_score += 30.0
            reasons.append(DetectionReason(
                category="Identity & Header",
                description=f"Reply-To diversion: Replies redirect to '{parsed_email.reply_to_email}' rather than sender.",
                weight=30.0,
                severity="HIGH"
            ))

        if auth.envelope_from_mismatch:
            raw_score += 15.0
            reasons.append(DetectionReason(
                category="Identity & Header",
                description=f"Envelope sender (Return-Path: {parsed_email.return_path}) does not align with From header.",
                weight=15.0,
                severity="MEDIUM"
            ))

        # Check parsed authentication statuses (Header values only)
        if auth.spf.status in ("fail", "softfail"):
            raw_score += 20.0
            reasons.append(DetectionReason(
                category="Authentication",
                description=f"Parsed SPF header indicates validation failure ({auth.spf.status.upper()}).",
                weight=20.0,
                severity="HIGH"
            ))
        elif auth.spf.status == "none" and not auth.display_name_spoofed:
            reasons.append(DetectionReason(
                category="Authentication",
                description="SPF record missing or unverified in parsed headers.",
                weight=5.0,
                severity="INFO"
            ))

        if auth.dkim.status in ("fail", "permerror"):
            raw_score += 20.0
            reasons.append(DetectionReason(
                category="Authentication",
                description=f"Parsed DKIM signature validation failed ({auth.dkim.status.upper()}).",
                weight=20.0,
                severity="HIGH"
            ))

        if auth.dmarc.status == "fail":
            raw_score += 25.0
            reasons.append(DetectionReason(
                category="Authentication",
                description="Parsed DMARC policy check failed.",
                weight=25.0,
                severity="CRITICAL"
            ))

        # -------------------------------------------------------------
        # 2. URL & Domain Intelligence Evaluation (Paper 3)
        # -------------------------------------------------------------
        max_url_score = 0.0
        malicious_urls = [u for u in urls if u.risk_category == "MALICIOUS"]
        suspicious_urls = [u for u in urls if u.risk_category == "SUSPICIOUS"]

        if urls:
            max_url_score = max(u.risk_score for u in urls)
            
            if malicious_urls:
                raw_score += 45.0
                for mu in malicious_urls[:3]:
                    reasons.append(DetectionReason(
                        category="URL Threat",
                        description=f"Malicious link detected ({mu.domain}): {'; '.join(mu.triggers[:2])}",
                        weight=45.0,
                        severity="CRITICAL"
                    ))
            elif suspicious_urls:
                raw_score += 25.0
                for su in suspicious_urls[:2]:
                    reasons.append(DetectionReason(
                        category="URL Threat",
                        description=f"Suspicious link detected ({su.domain}): {'; '.join(su.triggers[:2])}",
                        weight=25.0,
                        severity="MEDIUM"
                    ))

        # -------------------------------------------------------------
        # 3. BEC & Pretexting Intent Evaluation (Paper 2)
        # -------------------------------------------------------------
        if intent.financial_wire_detected and intent.urgency_detected:
            raw_score += 35.0
            reasons.append(DetectionReason(
                category="BEC & Intent",
                description=f"Coercive financial urgency pattern detected: ({', '.join(intent.financial_keywords[:3])}) with ({', '.join(intent.urgency_keywords[:2])}).",
                weight=35.0,
                severity="CRITICAL"
            ))
        elif intent.financial_wire_detected:
            raw_score += 20.0
            reasons.append(DetectionReason(
                category="BEC & Intent",
                description=f"Financial transaction/account modification requests: ({', '.join(intent.financial_keywords[:3])}).",
                weight=20.0,
                severity="MEDIUM"
            ))
        elif intent.urgency_detected:
            raw_score += 15.0
            reasons.append(DetectionReason(
                category="Urgency Cue",
                description=f"Artificial time-pressure language detected: ({', '.join(intent.urgency_keywords[:3])}).",
                weight=15.0,
                severity="LOW"
            ))

        if intent.authority_pretext_detected:
            raw_score += 25.0
            reasons.append(DetectionReason(
                category="Authority Pretexting",
                description=f"Executive confidentiality / secrecy pretexting: ({', '.join(intent.authority_keywords[:2])}).",
                weight=25.0,
                severity="HIGH"
            ))

        # -------------------------------------------------------------
        # 4. Final Threat Score & Risk Level Normalization
        # -------------------------------------------------------------
        threat_score = min(100, max(0, int(round(raw_score))))

        if threat_score >= 70:
            risk_level = "CRITICAL"
        elif threat_score >= 45:
            risk_level = "HIGH"
        elif threat_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # -------------------------------------------------------------
        # 5. Determine Threat Archetype (Paper 2 Taxonomy)
        # -------------------------------------------------------------
        if (auth.display_name_spoofed or intent.authority_pretext_detected) and intent.financial_wire_detected:
            threat_archetype = "CEO Fraud / Executive Spoofing"
        elif intent.financial_wire_detected and ("bank" in intent.financial_keywords or "invoice" in intent.financial_keywords or "routing" in intent.financial_keywords):
            threat_archetype = "Bogus Invoice / Banking Redirection"
        elif malicious_urls or (suspicious_urls and intent.urgency_detected):
            threat_archetype = "Credential Phishing"
        elif auth.reply_to_mismatch and (intent.urgency_detected or intent.financial_wire_detected):
            threat_archetype = "Account Compromise / Response Redirection"
        elif suspicious_urls:
            threat_archetype = "Suspicious Link Threat"
        elif threat_score > 35:
            threat_archetype = "Social Engineering Lure"
        else:
            threat_archetype = "Clean Email"

        # -------------------------------------------------------------
        # 6. Calibrated Confidence Calculation
        # Evaluates degree of multi-signal convergence vs isolated triggers
        # -------------------------------------------------------------
        evidence_count = len(reasons)
        if threat_score >= 75:
            # High score with multiple corroborating signals -> high confidence
            confidence = min(0.98, 0.75 + (evidence_count * 0.05))
        elif threat_score <= 15:
            # Very low score with no critical triggers -> high confidence benign
            if auth.spf.status == "pass" and auth.dkim.status == "pass":
                confidence = 0.95
            else:
                confidence = 0.85
        else:
            # Intermediate scores have higher ambiguity (Paper 1 and Paper 3 findings)
            confidence = max(0.50, min(0.78, 0.45 + (evidence_count * 0.06)))

        confidence = round(confidence, 2)

        # -------------------------------------------------------------
        # 7. Recommended SOC Actions (Procedural Security from Paper 2)
        # -------------------------------------------------------------
        if threat_archetype == "CEO Fraud / Executive Spoofing":
            actions.append("HALT any payment, wire transfer, or gift card issuance immediately.")
            actions.append("Initiate out-of-band verification by calling the executive on an established internal phone number.")
            actions.append("Block sender address and flag display name on email security gateway.")
        elif threat_archetype == "Bogus Invoice / Banking Redirection":
            actions.append("Do NOT update vendor payment or ACH/routing details based on this communication.")
            actions.append("Perform two-party procedural verification with vendor accounts payable using the primary phone number on contract.")
            actions.append("Quarantine email and audit past 14 days of correspondence with this vendor.")
        elif threat_archetype in ("Credential Phishing", "Suspicious Link Threat"):
            actions.append("Block malicious domain(s) at network firewall and DNS resolvers.")
            actions.append("If user clicked link, force immediate password reset and revoke active session tokens.")
            actions.append("Submit extracted URLs to internal sandbox for threat intelligence ingestion.")
        elif threat_archetype == "Account Compromise / Response Redirection":
            actions.append("Audit mailbox rules of sender account for unauthorized forwarding/redirect rules.")
            actions.append("Temporarily disable compromised credentials and enforce multi-factor authentication re-enrollment.")
        elif risk_level == "LOW":
            actions.append("No immediate containment required. Message meets standard authentication criteria.")
            actions.append("Standard security awareness: Report if unexpected wire requests follow.")
        else:
            actions.append("Investigate sender history and verify authenticity with sender through alternate channel.")

        return threat_score, confidence, risk_level, threat_archetype, intent, reasons, actions

class CitadelDetectorOrchestrator:
    """
    Main orchestrator that coordinates parser, header analyzer, URL engine,
    heuristic detector, and ML classifier to produce the final AnalysisResult.

    Detection Architecture:
        Email → Parse → [Heuristic Detector] + [ML Classifier] → Signal Aggregation → Score → Report
    """
    def __init__(self, detector: Optional[BaseDetector] = None):
        self.detector = detector or HeuristicRuleDetector()
        self._ml_classifier = None
        self._ml_init_attempted = False

    def _get_ml_classifier(self):
        """Lazily initialize the ML classifier singleton."""
        if not self._ml_init_attempted:
            self._ml_init_attempted = True
            try:
                from backend.ml.classifier import get_ml_classifier
                self._ml_classifier = get_ml_classifier()
            except Exception:
                self._ml_classifier = None
        return self._ml_classifier

    def analyze(self, parsed_email: ParsedEmail, filename: str = "unnamed.eml", raw_bytes: Optional[bytes] = None) -> AnalysisResult:
        from backend.headers import analyze_headers
        from backend.url_analyzer import analyze_urls
        from backend.schemas import MLClassification

        # 1. Header & Identity Analysis
        auth_analysis = analyze_headers(parsed_email)

        # 2. URL Intelligence
        url_analyses = analyze_urls(parsed_email.urls)

        # 3. Heuristic Detection (Phase 1 — unchanged)
        (heuristic_score, heuristic_conf, risk_level,
         threat_archetype, intent, reasons, actions) = self.detector.evaluate(
            parsed_email, auth_analysis, url_analyses
        )

        # 4. ML Classification (Phase 2 — additive signal)
        ml_result = MLClassification()
        ml_classifier = self._get_ml_classifier()
        ml_boost = 0
        if ml_classifier and ml_classifier.is_trained:
            analysis_text = f"{parsed_email.subject}\n{parsed_email.normalized_body}"
            ml_pred = ml_classifier.predict(analysis_text)
            ml_result = MLClassification(
                ml_available=ml_pred.get("ml_available", False),
                predicted_label=ml_pred.get("predicted_label", "unknown"),
                probabilities=ml_pred.get("probabilities", {}),
                ml_confidence=ml_pred.get("ml_confidence", 0.0)
            )

            # ML boosts the heuristic score when both agree on a threat
            if ml_result.ml_available:
                phish_prob = ml_result.probabilities.get("phishing", 0.0)
                bec_prob = ml_result.probabilities.get("bec", 0.0)
                threat_prob = phish_prob + bec_prob

                if ml_result.predicted_label in ("phishing", "bec") and ml_result.ml_confidence >= 0.6:
                    # ML confirms threat — add boost proportional to ML confidence
                    ml_boost = int(threat_prob * 15)
                    reasons.append(DetectionReason(
                        category="ML Classification",
                        description=f"TF-IDF + LR classifier predicts '{ml_result.predicted_label}' "
                                    f"(p={ml_result.ml_confidence:.2f}). "
                                    f"Probabilities: phishing={phish_prob:.2f}, bec={bec_prob:.2f}.",
                        weight=float(ml_boost),
                        severity="HIGH" if ml_result.ml_confidence >= 0.8 else "MEDIUM"
                    ))
                elif ml_result.predicted_label == "benign" and ml_result.ml_confidence >= 0.7 and heuristic_score >= 30:
                    # ML disagrees with heuristic, signal ambiguity
                    reasons.append(DetectionReason(
                        category="ML Classification",
                        description=f"ML classifier predicts 'benign' (p={ml_result.ml_confidence:.2f}) "
                                    f"while heuristic score is {heuristic_score}. Conflict suggests manual review.",
                        weight=0.0,
                        severity="INFO"
                    ))

        # 4b. Contextual NLP & Pretexting Engine (Phase 4)
        from backend.schemas import ContextualNLPAnalysis
        nlp_result = ContextualNLPAnalysis()
        nlp_boost = 0
        try:
            from backend.nlp import get_nlp_engine
            nlp_data = get_nlp_engine().analyze_context(parsed_email.subject, parsed_email.normalized_body)
            nlp_result = ContextualNLPAnalysis(
                nlp_engine=nlp_data.get("nlp_engine", "Contextual Pretexting Vectorizer"),
                dominant_archetype=nlp_data.get("dominant_archetype", "UNKNOWN"),
                archetype_similarities=nlp_data.get("archetype_similarities", {}),
                coercion_score=nlp_data.get("coercion_score", 0.0),
                coercion_level=nlp_data.get("coercion_level", "LOW"),
                coercion_breakdown=nlp_data.get("coercion_breakdown", {}),
                tone=nlp_data.get("tone", "NEUTRAL")
            )

            # Signal extraction from contextual NLP
            if nlp_result.dominant_archetype != "BENIGN_COLLABORATION" and nlp_result.dominant_archetype != "UNKNOWN":
                sim = nlp_result.archetype_similarities.get(nlp_result.dominant_archetype, 0.0)
                if sim >= 0.15:
                    nlp_boost = min(12, int(sim * 25))
                    reasons.append(DetectionReason(
                        category="Contextual NLP",
                        description=f"Semantic vector alignment to '{nlp_result.dominant_archetype}' "
                                    f"(cosine similarity: {sim:.2f}). Tone classified as '{nlp_result.tone}'.",
                        weight=float(nlp_boost),
                        severity="HIGH" if sim >= 0.3 else "MEDIUM"
                    ))

            if nlp_result.coercion_level in ("CRITICAL", "HIGH"):
                c_boost = 8 if nlp_result.coercion_level == "CRITICAL" else 4
                nlp_boost += c_boost
                all_coercion_markers = []
                for cat, kw_list in nlp_result.coercion_breakdown.items():
                    all_coercion_markers.extend(kw_list)
                reasons.append(DetectionReason(
                    category="Social Engineering",
                    description=f"High Psychological Coercion Index ({nlp_result.coercion_score:.2f}/1.0). "
                                f"Linguistic cues: {', '.join(all_coercion_markers[:4])}",
                    weight=float(c_boost),
                    severity="HIGH" if nlp_result.coercion_level == "CRITICAL" else "MEDIUM"
                ))
        except Exception:
            pass

        ml_boost += nlp_boost

        # 5. Final Score Aggregation
        threat_score = min(100, max(0, heuristic_score + ml_boost))

        # Recalculate risk level after ML boost
        if threat_score >= 70:
            risk_level = "CRITICAL"
        elif threat_score >= 45:
            risk_level = "HIGH"
        elif threat_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 6. Multi-Dimensional Enrichment (Phase 3: Domain, GeoIP, Threat Intel)
        enrichment_data = {}
        try:
            from backend.enrichment import run_full_enrichment
            enrichment_data = run_full_enrichment(parsed_email, url_analyses)

            # Sender domain reputation signals
            sender_enrichment = enrichment_data.get("sender_domain")
            if sender_enrichment:
                if sender_enrichment.get("reputation_label") in ("SUSPICIOUS", "MALICIOUS"):
                    rep_score = sender_enrichment.get("reputation_score", 50)
                    boost = max(5, int((50 - rep_score) * 0.3))
                    ml_boost += boost
                    reasons.append(DetectionReason(
                        category="Domain Intelligence",
                        description=f"Sender domain '{sender_enrichment.get('domain', '')}' "
                                    f"reputation: {sender_enrichment.get('reputation_label')} "
                                    f"(score {rep_score}/100). "
                                    + "; ".join(sender_enrichment.get("signals", [])[:2]),
                        weight=float(boost),
                        severity="HIGH" if rep_score < 25 else "MEDIUM"
                    ))
                if sender_enrichment.get("brand_impersonation"):
                    reasons.append(DetectionReason(
                        category="Domain Intelligence",
                        description=f"Sender domain may impersonate brand '{sender_enrichment.get('impersonated_brand')}'",
                        weight=8.0,
                        severity="HIGH"
                    ))
                    ml_boost += 8

            # URL domain reputation signals
            for domain, rep in enrichment_data.get("domains", {}).items():
                if rep.get("reputation_label") in ("SUSPICIOUS", "MALICIOUS"):
                    rep_score = rep.get("reputation_score", 50)
                    boost = max(3, int((50 - rep_score) * 0.2))
                    ml_boost += boost
                    reasons.append(DetectionReason(
                        category="Domain Intelligence",
                        description=f"URL domain '{domain}' reputation: {rep.get('reputation_label')} "
                                    f"(score {rep_score}/100). "
                                    + "; ".join(rep.get("signals", [])[:2]),
                        weight=float(boost),
                        severity="HIGH" if rep_score < 25 else "MEDIUM"
                    ))

            # IP Geolocation & Infrastructure risk signals
            for ip, geo in enrichment_data.get("ips", {}).items():
                if geo.get("risk_category") in ("CRITICAL_RISK", "HIGH_RISK", "ANONYMIZER_TOR"):
                    geo_boost = 10 if geo["risk_category"] == "CRITICAL_RISK" else 6
                    ml_boost += geo_boost
                    reasons.append(DetectionReason(
                        category="Infrastructure & GeoIP",
                        description=f"Resolved IP {ip} geolocated in {geo.get('country')} ({geo.get('org')}). "
                                    f"Risk: {geo.get('risk_category')} — " + "; ".join(geo.get("flags", [])[:1]),
                        weight=float(geo_boost),
                        severity="HIGH" if geo["risk_category"] == "CRITICAL_RISK" else "MEDIUM"
                    ))

            # Threat Intelligence IOC Matches
            ti = enrichment_data.get("threat_intel", {})
            if ti.get("matched"):
                for match in ti.get("matches", []):
                    ti_boost = 15 if match["severity"] == "CRITICAL" else 10
                    ml_boost += ti_boost
                    reasons.append(DetectionReason(
                        category="Threat Intelligence",
                        description=f"IOC Match ({match['ioc_type'].upper()}): '{match['indicator']}' attributed to "
                                    f"{match['threat_group']} ({match['threat_type']}) [Conf: {match['confidence']:.2f}]",
                        weight=float(ti_boost),
                        severity=match["severity"]
                    ))
        except Exception as e:
            enrichment_data["error"] = f"Enrichment unavailable: {str(e)}"

        # 7. Final Score Aggregation (after all signal sources)
        threat_score = min(100, max(0, heuristic_score + ml_boost))

        # Recalculate risk level after all boosts
        if threat_score >= 70:
            risk_level = "CRITICAL"
        elif threat_score >= 45:
            risk_level = "HIGH"
        elif threat_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 8. Combined Confidence (heuristic + ML agreement factor)
        evidence_count = len(reasons)
        if ml_result.ml_available and ml_result.ml_confidence > 0:
            ml_agrees = (
                (ml_result.predicted_label in ("phishing", "bec") and heuristic_score >= 40) or
                (ml_result.predicted_label == "benign" and heuristic_score < 25)
            )
            if ml_agrees:
                confidence = min(0.98, heuristic_conf * 0.6 + ml_result.ml_confidence * 0.4)
            else:
                confidence = max(0.45, min(0.70, heuristic_conf * 0.7))
        else:
            confidence = heuristic_conf
        confidence = round(confidence, 2)

        metadata = EmailMetadata(
            subject=parsed_email.subject,
            sender=f"{parsed_email.sender_display_name} <{parsed_email.sender_email}>" if parsed_email.sender_display_name else parsed_email.sender_email,
            sender_display_name=parsed_email.sender_display_name,
            sender_email=parsed_email.sender_email,
            recipient=parsed_email.recipient,
            reply_to=parsed_email.reply_to_email if parsed_email.reply_to_email else None,
            return_path=parsed_email.return_path if parsed_email.return_path else None,
            date=parsed_email.date,
            message_id=parsed_email.message_id
        )

        body_preview = parsed_email.normalized_body[:1000]

        result = AnalysisResult(
            case_id=generate_case_id(),
            filename=filename,
            metadata=metadata,
            authentication=auth_analysis,
            urls=url_analyses,
            intent=intent,
            ml_classification=ml_result,
            nlp_analysis=nlp_result,
            threat_score=threat_score,
            confidence=confidence,
            risk_level=risk_level,
            threat_archetype=threat_archetype,
            reasons=reasons,
            recommended_actions=actions,
            body_text_preview=body_preview,
            enrichment=enrichment_data if enrichment_data else None
        )

        # 9. Threat Correlation & Entity Graph (Phase 5)
        try:
            from backend.correlation import build_threat_graph
            res_dict = result.model_dump()
            result.threat_graph = build_threat_graph(res_dict)
        except Exception:
            result.threat_graph = {"nodes": [], "edges": [], "summary": {}}

        # 10. Cryptographic Evidence Integrity & Merkle Ledger Anchoring (Phase 9)
        try:
            from backend.integrity import get_evidence_ledger
            from backend.schemas import EvidenceIntegrity
            ledger = get_evidence_ledger()

            # Ensure we use exact raw bytes (independent of parsing transformations)
            evidence_bytes = raw_bytes if raw_bytes is not None else getattr(parsed_email, "raw_eml_bytes", b"")
            if not evidence_bytes:
                evidence_bytes = (
                    f"From: {parsed_email.sender_email}\r\n"
                    f"Subject: {parsed_email.subject}\r\n\r\n"
                    f"{parsed_email.plain_body}"
                ).encode("utf-8")

            headers_dict = {
                "subject": parsed_email.subject,
                "sender": f"{parsed_email.sender_display_name} <{parsed_email.sender_email}>" if parsed_email.sender_display_name else parsed_email.sender_email,
                "recipient": parsed_email.recipient,
                "date": parsed_email.date,
                "message_id": parsed_email.message_id,
                "reply_to": parsed_email.reply_to_email,
                "return_path": parsed_email.return_path
            }
            verdict_dict = {
                "threat_score": result.threat_score,
                "risk_level": result.risk_level,
                "threat_archetype": result.threat_archetype
            }

            block = ledger.record_case_evidence(
                case_id=result.case_id,
                raw_eml_bytes=evidence_bytes,
                headers_dict=headers_dict,
                verdict_dict=verdict_dict
            )

            result.integrity = EvidenceIntegrity(
                evidence_sha256=block["evidence_sha256"],
                verdict_sha256=block["verdict_sha256"],
                merkle_root=block["merkle_root"],
                block_index=block["block_index"],
                block_hash=block["block_hash"],
                previous_block_hash=block["previous_block_hash"],
                chain_of_custody_timestamp=block["timestamp"],
                integrity_status="INTEGRITY: VERIFIED",
                ledger_name="Citadel Tamper-Evident Cryptographic Ledger",
                verification_endpoint=f"/api/case/{result.case_id}/verify-integrity"
            )
        except Exception:
            pass

        # Store in case results repository for forensic reporting (Phase 8) and case management (Phase 7)
        try:
            from backend.reports import store_case_result
            store_case_result(result)
        except Exception:
            pass

        try:
            from backend.cases import get_case_repository
            get_case_repository().create_or_update_from_analysis(result)
        except Exception:
            pass

        return result
