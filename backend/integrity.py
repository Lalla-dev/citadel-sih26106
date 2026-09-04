"""
Citadel Security Platform - Cryptographic Evidence Integrity & Merkle Evidence Ledger (Phase 6 & 9)
Provides append-only, tamper-evident cryptographic evidence anchoring backed by relational storage.
  1. SHA-256 hashing of original raw .eml RFC 5322 bytes (prior to any parsing).
  2. SHA-256 digest of relevant parsed headers and detection verdict.
  3. Append-only cryptographic/Merkle evidence ledger maintaining hash linkage.
  4. Real-time cryptographic verification proving evidence authenticity and detection integrity.
  5. Relational persistence (PostgreSQL / SQLite) ensuring evidence survives server restart.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy import select

from backend.database import (
    get_db_session,
    EvidenceLedgerBlockModel,
    record_audit_log
)

logger = logging.getLogger("citadel.integrity")

# Genesis block constants
GENESIS_PREV_HASH = "0" * 64


def compute_sha256_bytes(data: bytes) -> str:
    """Computes SHA-256 cryptographic digest of arbitrary raw bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_verdict_digest(headers: Dict[str, Any], verdict: Dict[str, Any]) -> str:
    """
    Computes a canonical SHA-256 digest of relevant parsed email headers and detection verdict.
    Sorts dictionary keys for deterministic cross-platform repeatability.
    """
    canonical_payload = {
        "headers": {
            "subject": str(headers.get("subject", "")).strip(),
            "from": str(headers.get("sender", "")).strip(),
            "to": str(headers.get("recipient", "")).strip(),
            "date": str(headers.get("date", "")).strip(),
            "message_id": str(headers.get("message_id", "")).strip(),
            "reply_to": str(headers.get("reply_to", "")).strip() if headers.get("reply_to") else None,
            "return_path": str(headers.get("return_path", "")).strip() if headers.get("return_path") else None,
        },
        "verdict": {
            "threat_score": int(verdict.get("threat_score", 0)),
            "risk_level": str(verdict.get("risk_level", "LOW")),
            "threat_archetype": str(verdict.get("threat_archetype", "Clean Email")),
        }
    }
    encoded = json.dumps(canonical_payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def compute_merkle_root(evidence_sha256: str, verdict_sha256: str) -> str:
    """Computes a 2-leaf Merkle root from the evidence hash and verdict digest."""
    h_ev = hashlib.sha256(evidence_sha256.encode('utf-8')).digest()
    h_vd = hashlib.sha256(verdict_sha256.encode('utf-8')).digest()
    return hashlib.sha256(h_ev + h_vd).hexdigest()


def compute_block_hash(
    block_index: int,
    timestamp: str,
    case_id: str,
    evidence_sha256: str,
    verdict_sha256: str,
    previous_block_hash: str,
    merkle_root: str
) -> str:
    """Computes the cryptographic block hash binding all block data and chain linkage."""
    header_str = f"{block_index}|{timestamp}|{case_id}|{evidence_sha256}|{verdict_sha256}|{previous_block_hash}|{merkle_root}"
    return hashlib.sha256(header_str.encode('utf-8')).hexdigest()


class EvidenceLedger:
    """
    Append-only tamper-evident cryptographic evidence ledger.
    Maintains a sequential chain of blocks anchored by SHA-256 previous-block hashes and Merkle roots.
    Persists blocks and raw RFC 5322 evidence bytes to PostgreSQL / SQLite when persist_to_db=True.
    """
    def __init__(self, persist_to_db: bool = False):
        self.persist_to_db = persist_to_db
        self.chain: List[Dict[str, Any]] = []
        self.case_evidence_store: Dict[str, bytes] = {}
        self.case_verdict_store: Dict[str, Dict[str, Any]] = {}
        self.case_to_block_map: Dict[str, int] = {}

        if persist_to_db:
            self.load_from_db()
        else:
            self._init_genesis_block()

    def _init_genesis_block(self):
        """Initializes the immutable Genesis block #0."""
        timestamp = "2026-01-01T00:00:00Z"
        case_id = "CASE-GENESIS-ANCHOR"
        evidence_sha256 = hashlib.sha256(b"Citadel Genesis Evidence Anchor").hexdigest()
        verdict_sha256 = hashlib.sha256(b"Citadel Genesis Verdict Anchor").hexdigest()
        merkle_root = compute_merkle_root(evidence_sha256, verdict_sha256)
        block_hash = compute_block_hash(0, timestamp, case_id, evidence_sha256, verdict_sha256, GENESIS_PREV_HASH, merkle_root)

        genesis_block = {
            "block_index": 0,
            "timestamp": timestamp,
            "case_id": case_id,
            "evidence_sha256": evidence_sha256,
            "verdict_sha256": verdict_sha256,
            "previous_block_hash": GENESIS_PREV_HASH,
            "merkle_root": merkle_root,
            "block_hash": block_hash
        }
        self.chain.append(genesis_block)

    def load_from_db(self):
        """Loads all blocks and raw evidence from the database in sequential order."""
        try:
            with get_db_session() as session:
                models = session.execute(
                    select(EvidenceLedgerBlockModel).order_by(EvidenceLedgerBlockModel.block_index.asc())
                ).scalars().all()

                if not models:
                    self._init_genesis_block()
                    g = self.chain[0]
                    session.add(EvidenceLedgerBlockModel(
                        block_index=0,
                        timestamp=g["timestamp"],
                        case_id=g["case_id"],
                        evidence_sha256=g["evidence_sha256"],
                        verdict_sha256=g["verdict_sha256"],
                        previous_block_hash=g["previous_block_hash"],
                        merkle_root=g["merkle_root"],
                        block_hash=g["block_hash"],
                        raw_eml_bytes=b"Citadel Genesis Evidence Anchor",
                        headers_json="{}",
                        verdict_json="{}"
                    ))
                    return

                self.chain.clear()
                self.case_evidence_store.clear()
                self.case_verdict_store.clear()
                self.case_to_block_map.clear()

                for m in models:
                    block = {
                        "block_index": m.block_index,
                        "timestamp": m.timestamp,
                        "case_id": m.case_id,
                        "evidence_sha256": m.evidence_sha256,
                        "verdict_sha256": m.verdict_sha256,
                        "previous_block_hash": m.previous_block_hash,
                        "merkle_root": m.merkle_root,
                        "block_hash": m.block_hash
                    }
                    self.chain.append(block)
                    if m.block_index > 0:
                        self.case_evidence_store[m.case_id] = m.raw_eml_bytes
                        self.case_verdict_store[m.case_id] = {
                            "headers": json.loads(m.headers_json) if m.headers_json else {},
                            "verdict": json.loads(m.verdict_json) if m.verdict_json else {}
                        }
                        self.case_to_block_map[m.case_id] = m.block_index
        except Exception as e:
            logger.warning(f"Could not load ledger from database: {e}")
            if not self.chain:
                self._init_genesis_block()

    def record_case_evidence(
        self,
        case_id: str,
        raw_eml_bytes: bytes,
        headers_dict: Dict[str, Any],
        verdict_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Anchors a new email case into the cryptographic ledger:
          1. Computes SHA-256 of the exact original raw .eml bytes.
          2. Computes SHA-256 digest of parsed headers and detection verdict.
          3. Appends a new block linked to the latest block hash.
          4. Persists the block and raw RFC 5322 bytes into PostgreSQL / SQLite when persist_to_db=True.
        """
        evidence_sha256 = compute_sha256_bytes(raw_eml_bytes)
        verdict_sha256 = compute_verdict_digest(headers_dict, verdict_dict)
        merkle_root = compute_merkle_root(evidence_sha256, verdict_sha256)
        timestamp = datetime.now(timezone.utc).isoformat()

        if self.persist_to_db:
            try:
                with get_db_session() as session:
                    latest = session.execute(
                        select(EvidenceLedgerBlockModel).order_by(EvidenceLedgerBlockModel.block_index.desc())
                    ).scalars().first()

                    if not latest:
                        self._init_genesis_block()
                        g = self.chain[0]
                        latest = EvidenceLedgerBlockModel(
                            block_index=0,
                            timestamp=g["timestamp"],
                            case_id=g["case_id"],
                            evidence_sha256=g["evidence_sha256"],
                            verdict_sha256=g["verdict_sha256"],
                            previous_block_hash=g["previous_block_hash"],
                            merkle_root=g["merkle_root"],
                            block_hash=g["block_hash"],
                            raw_eml_bytes=b"Citadel Genesis Evidence Anchor",
                            headers_json="{}",
                            verdict_json="{}"
                        )
                        session.add(latest)
                        session.flush()

                    previous_block_hash = latest.block_hash
                    block_index = latest.block_index + 1

                    block_hash = compute_block_hash(
                        block_index, timestamp, case_id, evidence_sha256, verdict_sha256, previous_block_hash, merkle_root
                    )

                    db_block = EvidenceLedgerBlockModel(
                        block_index=block_index,
                        timestamp=timestamp,
                        case_id=case_id,
                        evidence_sha256=evidence_sha256,
                        verdict_sha256=verdict_sha256,
                        previous_block_hash=previous_block_hash,
                        merkle_root=merkle_root,
                        block_hash=block_hash,
                        raw_eml_bytes=raw_eml_bytes,
                        headers_json=json.dumps(headers_dict),
                        verdict_json=json.dumps(verdict_dict)
                    )
                    session.add(db_block)

                block = {
                    "block_index": block_index,
                    "timestamp": timestamp,
                    "case_id": case_id,
                    "evidence_sha256": evidence_sha256,
                    "verdict_sha256": verdict_sha256,
                    "previous_block_hash": previous_block_hash,
                    "merkle_root": merkle_root,
                    "block_hash": block_hash
                }
                self.chain.append(block)
                self.case_evidence_store[case_id] = raw_eml_bytes
                self.case_verdict_store[case_id] = {
                    "headers": headers_dict,
                    "verdict": verdict_dict
                }
                self.case_to_block_map[case_id] = block_index

                record_audit_log(
                    event_type="EVIDENCE_ANCHORED",
                    actor="Citadel Cryptographic Ledger",
                    case_id=case_id,
                    details=f"Block #{block_index}, SHA-256: {evidence_sha256[:16]}..."
                )
                return block
            except Exception as e:
                logger.warning(f"Could not persist ledger block: {e}")

        previous_block = self.chain[-1]
        previous_block_hash = previous_block["block_hash"]
        block_index = len(self.chain)

        block_hash = compute_block_hash(
            block_index, timestamp, case_id, evidence_sha256, verdict_sha256, previous_block_hash, merkle_root
        )

        block = {
            "block_index": block_index,
            "timestamp": timestamp,
            "case_id": case_id,
            "evidence_sha256": evidence_sha256,
            "verdict_sha256": verdict_sha256,
            "previous_block_hash": previous_block_hash,
            "merkle_root": merkle_root,
            "block_hash": block_hash
        }

        self.chain.append(block)
        self.case_evidence_store[case_id] = raw_eml_bytes
        self.case_verdict_store[case_id] = {
            "headers": headers_dict,
            "verdict": verdict_dict
        }
        self.case_to_block_map[case_id] = block_index

        return block

    def get_case_block(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the ledger block for a given case_id."""
        b_idx = self.case_to_block_map.get(case_id)
        if b_idx is not None and b_idx < len(self.chain):
            return self.chain[b_idx]

        if self.persist_to_db:
            try:
                with get_db_session() as session:
                    model = session.execute(
                        select(EvidenceLedgerBlockModel).where(EvidenceLedgerBlockModel.case_id == case_id)
                    ).scalar_one_or_none()
                    if model:
                        return {
                            "block_index": model.block_index,
                            "timestamp": model.timestamp,
                            "case_id": model.case_id,
                            "evidence_sha256": model.evidence_sha256,
                            "verdict_sha256": model.verdict_sha256,
                            "previous_block_hash": model.previous_block_hash,
                            "merkle_root": model.merkle_root,
                            "block_hash": model.block_hash
                        }
            except Exception as e:
                logger.warning(f"Could not fetch block for {case_id} from database: {e}")

        return None

    def verify_ledger_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Validates the cryptographic integrity of the entire ledger chain:
          - Verifies each block hash matches its recalculated value.
          - Verifies previous_block_hash linkage between consecutive blocks.
        """
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            # 1. Linkage check
            if curr["previous_block_hash"] != prev["block_hash"]:
                return False, f"Broken chain linkage at block #{i}: prev hash mismatch"

            # 2. Block hash recalculation check
            recomputed = compute_block_hash(
                curr["block_index"], curr["timestamp"], curr["case_id"],
                curr["evidence_sha256"], curr["verdict_sha256"],
                curr["previous_block_hash"], curr["merkle_root"]
            )
            if curr["block_hash"] != recomputed:
                return False, f"Tampered block hash at block #{i}"

            # 3. Merkle root check
            recomputed_merkle = compute_merkle_root(curr["evidence_sha256"], curr["verdict_sha256"])
            if curr["merkle_root"] != recomputed_merkle:
                return False, f"Tampered Merkle root at block #{i}"

        return True, None

    def verify_case(self, case_id: str) -> Dict[str, Any]:
        """
        Performs comprehensive tamper-evident verification for a specific case:
          1. Verifies stored raw .eml bytes match recorded evidence_sha256.
          2. Verifies stored parsed headers and verdict match recorded verdict_sha256.
          3. Verifies Merkle root.
          4. Verifies entire ledger chain linkage up to this block.
        """
        block = self.get_case_block(case_id)
        if not block:
            return {
                "status": "INTEGRITY: TAMPERED",
                "verified": False,
                "case_id": case_id,
                "error": f"No cryptographic ledger block found for {case_id}",
                "checks": {
                    "evidence_hash_match": False,
                    "verdict_hash_match": False,
                    "merkle_root_valid": False,
                    "ledger_linkage_valid": False
                }
            }

        # 1. Check raw evidence hash
        stored_bytes = self.case_evidence_store.get(case_id)
        evidence_match = False
        current_evidence_hash = "NOT_FOUND"
        if stored_bytes is not None:
            current_evidence_hash = compute_sha256_bytes(stored_bytes)
            evidence_match = (current_evidence_hash == block["evidence_sha256"])

        # 2. Check verdict digest
        stored_verdict = self.case_verdict_store.get(case_id)
        verdict_match = False
        current_verdict_hash = "NOT_FOUND"
        if stored_verdict is not None:
            current_verdict_hash = compute_verdict_digest(
                stored_verdict.get("headers", {}),
                stored_verdict.get("verdict", {})
            )
            verdict_match = (current_verdict_hash == block["verdict_sha256"])

        # 3. Check Merkle root
        recomputed_merkle = compute_merkle_root(block["evidence_sha256"], block["verdict_sha256"])
        merkle_match = (recomputed_merkle == block["merkle_root"])

        # 4. Check entire ledger chain
        ledger_valid, ledger_error = self.verify_ledger_integrity()

        all_passed = evidence_match and verdict_match and merkle_match and ledger_valid

        if self.persist_to_db:
            record_audit_log(
                event_type="INTEGRITY_VERIFIED",
                actor="Citadel Verification Engine",
                case_id=case_id,
                details=f"Result: {'PASS' if all_passed else 'TAMPER_DETECTED'}"
            )

        return {
            "status": "INTEGRITY: VERIFIED" if all_passed else "INTEGRITY: TAMPERED",
            "verified": all_passed,
            "case_id": case_id,
            "block_index": block["block_index"],
            "timestamp": block["timestamp"],
            "evidence_sha256": block["evidence_sha256"],
            "current_evidence_sha256": current_evidence_hash,
            "verdict_sha256": block["verdict_sha256"],
            "current_verdict_sha256": current_verdict_hash,
            "merkle_root": block["merkle_root"],
            "block_hash": block["block_hash"],
            "previous_block_hash": block["previous_block_hash"],
            "checks": {
                "evidence_hash_match": evidence_match,
                "verdict_hash_match": verdict_match,
                "merkle_root_valid": merkle_match,
                "ledger_linkage_valid": ledger_valid
            },
            "ledger_error": ledger_error,
            "summary": (
                "Cryptographic evidence integrity confirmed: original RFC 5322 message bytes and "
                "forensic verdict match the append-only cryptographic evidence ledger without tampering."
                if all_passed else
                f"TAMPER DETECTED: Hash mismatch or broken ledger linkage ({ledger_error or 'Evidence/verdict altered'})."
            )
        }

    # Simulation / Demo helpers to test tamper detection
    def simulate_tamper_evidence(self, case_id: str, altered_bytes: bytes) -> bool:
        """Injects modified evidence bytes to demonstrate tamper detection in tests/demo."""
        if case_id in self.case_evidence_store:
            self.case_evidence_store[case_id] = altered_bytes
            if self.persist_to_db:
                record_audit_log(
                    event_type="TAMPER_SIMULATED",
                    actor="Analyst / Test Engine",
                    case_id=case_id,
                    details="Altered raw evidence bytes"
                )
            return True
        return False

    def simulate_tamper_verdict(self, case_id: str, new_threat_score: int) -> bool:
        """Injects modified verdict score to demonstrate detection in tests/demo."""
        if case_id in self.case_verdict_store:
            self.case_verdict_store[case_id]["verdict"]["threat_score"] = new_threat_score
            if self.persist_to_db:
                record_audit_log(
                    event_type="TAMPER_SIMULATED",
                    actor="Analyst / Test Engine",
                    case_id=case_id,
                    details=f"Altered threat score to {new_threat_score}"
                )
            return True
        return False

    def simulate_tamper_block(self, block_index: int, forged_prev_hash: str) -> bool:
        """Injects corrupted previous_block_hash into ledger to demonstrate chain break."""
        if 0 < block_index < len(self.chain):
            self.chain[block_index]["previous_block_hash"] = forged_prev_hash
            if self.persist_to_db:
                record_audit_log(
                    event_type="TAMPER_SIMULATED",
                    actor="Analyst / Test Engine",
                    case_id=self.chain[block_index].get("case_id"),
                    details=f"Corrupted block #{block_index} previous_block_hash"
                )
            return True
        return False


# Module-level singleton instance for the evidence ledger (loads from database on start)
_evidence_ledger = None

def get_evidence_ledger() -> EvidenceLedger:
    global _evidence_ledger
    if _evidence_ledger is None:
        _evidence_ledger = EvidenceLedger(persist_to_db=True)
    return _evidence_ledger
