"""
Citadel Security Platform - Contextual NLP & Intent Analysis Engine
Implements contextual pretexting detection, psychological coercion scoring,
and semantic vector matching across BEC and Phishing archetypes.
Designed for modular transformer integration (DistilBERT/RoBERTa) with a high-performance
statistical semantic cosine fallback for instant zero-dependency execution.
"""
import re
import math
from typing import Dict, Any, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

# Archetype Reference Profiles (Curated semantic anchor corpora for BEC/Phishing taxonomy)
ARCHETYPE_ANCHORS = {
    "CEO_FRAUD_PRETEXT": (
        "strictly confidential executive request do not discuss with colleagues or staff "
        "wire transfer immediately acquisition pending in a board meeting cannot take phone calls "
        "handle this personally urgent funds transfer out of band settlement discreet payment authorization"
    ),
    "INVOICE_FRAUD_PRETEXT": (
        "vendor payment banking details alteration remittance advice new routing number "
        "update our direct deposit instructions invoice overdue pending disbursement ACH wire "
        "amended account details payment diverted to new bank beneficiary account statement"
    ),
    "CREDENTIAL_HARVEST_PRETEXT": (
        "account suspended unauthorized login attempt verify credentials immediately password expiring "
        "session expired click secure link to re-authenticate IT security update required multi-factor authentication "
        "mailbox quota exceeded confirm identity to avoid service termination"
    ),
    "BENIGN_COLLABORATION": (
        "meeting agenda sprint planning quarterly review slides attached code review pull request "
        "lunch on Thursday conference room reservation project milestone status update documentation wiki "
        "calendar invite thank you team let me know your thoughts"
    )
}

# Psychological Coercion & Pressure Lexicons
COERCION_MARKERS = {
    "urgency": [
        r'\burgent\b', r'\basap\b', r'\bimmediate(?:ly)?\b', r'\bright\s+away\b',
        r'\btime\s+sensitive\b', r'\bdeadline\b', r'\btoday\s+before\s+close\b'
    ],
    "confidentiality_isolation": [
        r'\bstrictly\s+confidential\b', r'\bkeep\s+this\s+(?:between\s+us|private)\b',
        r'\bdo\s+not\s+(?:discuss|mention|tell)\b', r'\bdiscreet(?:ly)?\b', r'\bsecret\b'
    ],
    "authority_pretext": [
        r'\b(?:i\s+am\s+in\s+a|in\s+the)\s+board\s+meeting\b', r'\bexecutive\s+approval\b',
        r'\bcannot\s+take\s+calls\b', r'\btraveling\b', r'\bfrom\s+the\s+ceo\b'
    ],
    "consequence_intimidation": [
        r'\baccount\s+(?:suspended|terminated|disabled)\b', r'\blegal\s+action\b',
        r'\bbreach\s+of\s+policy\b', r'\bimmediate\s+disciplinary\b', r'\bfailure\s+to\s+comply\b'
    ]
}


class ContextualNLPEngine:
    """
    Contextual NLP analyzer that extracts:
      - Semantic Cosine Similarity against known BEC/Phishing archetypes
      - Psychological Coercion Index (Urgency, Isolation, Authority, Intimidation)
      - Sentiment & Tone Profile (Coercive, Imperative, Transactional, Informational)
    """
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words='english',
            sublinear_tf=True
        )
        self.anchor_names = list(ARCHETYPE_ANCHORS.keys())
        self.anchor_texts = list(ARCHETYPE_ANCHORS.values())
        # Fit vectorizer on anchor profiles
        self.anchor_vectors = self.vectorizer.fit_transform(self.anchor_texts)

    def analyze_context(self, subject: str, body: str) -> Dict[str, Any]:
        """
        Runs comprehensive contextual NLP analysis on the combined email text.
        """
        full_text = f"{subject} {body}".strip()
        if not full_text:
            return {
                "nlp_engine": "Contextual Pretexting Vectorizer (RoBERTa-Aligned Fallback)",
                "dominant_archetype": "UNKNOWN",
                "archetype_similarities": {},
                "coercion_score": 0.0,
                "coercion_level": "LOW",
                "coercion_breakdown": {},
                "tone": "NEUTRAL"
            }

        # 1. Semantic Cosine Similarity against Archetype Anchors
        query_vec = self.vectorizer.transform([full_text])
        sim_scores = cosine_similarity(query_vec, self.anchor_vectors)[0]

        similarities = {}
        for name, score in zip(self.anchor_names, sim_scores):
            similarities[name] = round(float(score), 4)

        # Identify dominant archetype
        dominant_idx = int(np.argmax(sim_scores))
        dominant_score = similarities[self.anchor_names[dominant_idx]]
        dominant_archetype = self.anchor_names[dominant_idx] if dominant_score > 0.05 else "BENIGN_COLLABORATION"

        # 2. Psychological Coercion & Pressure Velocity
        coercion_matches = {}
        total_coercion_hits = 0

        lower_text = full_text.lower()
        for category, patterns in COERCION_MARKERS.items():
            hits = []
            for pat in patterns:
                found = re.findall(pat, lower_text)
                if found:
                    hits.extend(found)
            coercion_matches[category] = list(set(hits))
            total_coercion_hits += len(hits)

        # Normalized Coercion Score (0.0 to 1.0)
        coercion_score = round(min(1.0, total_coercion_hits * 0.25), 2)
        if coercion_score >= 0.6:
            coercion_level = "CRITICAL"
        elif coercion_score >= 0.35:
            coercion_level = "HIGH"
        elif coercion_score >= 0.15:
            coercion_level = "MODERATE"
        else:
            coercion_level = "LOW"

        # 3. Tone & Intent Classification
        if coercion_matches.get("confidentiality_isolation") and coercion_matches.get("authority_pretext"):
            tone = "Executive Coercive / Isolation"
        elif coercion_matches.get("consequence_intimidation"):
            tone = "Intimidating / Punitive Urgency"
        elif coercion_matches.get("urgency"):
            tone = "Urgent / Action-Demanding"
        elif similarities.get("INVOICE_FRAUD_PRETEXT", 0) > 0.15:
            tone = "Transactional / Financial Redirection"
        else:
            tone = "Informative / Professional Sync"

        return {
            "nlp_engine": "Contextual Pretexting Vectorizer (RoBERTa-Aligned Fallback)",
            "dominant_archetype": dominant_archetype,
            "archetype_similarities": similarities,
            "coercion_score": coercion_score,
            "coercion_level": coercion_level,
            "coercion_breakdown": coercion_matches,
            "tone": tone
        }


# Singleton instance
_nlp_engine_instance = None

def get_nlp_engine() -> ContextualNLPEngine:
    global _nlp_engine_instance
    if _nlp_engine_instance is None:
        _nlp_engine_instance = ContextualNLPEngine()
    return _nlp_engine_instance
