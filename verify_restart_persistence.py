"""
Standalone verification script for Phase 6 Process-Kill & Restart Testing.
Runs Part 1 (pre-restart operations) or Part 2 (post-restart verifications).
"""
import sys
import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

def get(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read().decode("utf-8")

def post_json(path, data):
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read().decode("utf-8")

def patch_json(path, data):
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, headers={"Content-Type": "application/json"}, method="PATCH")
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read().decode("utf-8")

def run_part_1():
    print("=== RUNNING PART 1: PRE-KILL INGESTION & MUTATION ===")
    # 1. Health check
    status, body = get("/api/health")
    health = json.loads(body)
    print(f"[Health] Status: {status}, Backend: {health.get('database_backend')}")

    # 2. Ingest sample BEC
    status, body = get("/api/sample/bec_ceo_wire_fraud.eml")
    analysis = json.loads(body)
    case_id = analysis["case_id"]
    threat_score = analysis["threat_score"]
    threat_archetype = analysis["threat_archetype"]
    print(f"[Ingested] Case ID: {case_id}, Score: {threat_score}, Archetype: {threat_archetype}")

    # 3. Update status & assign analyst
    status, body = patch_json(f"/api/cases/{case_id}/status", {
        "status": "INVESTIGATING",
        "analyst": "Lead Analyst Sarah Chen"
    })
    updated_case = json.loads(body)
    print(f"[Status Updated] Status: {updated_case['status']}, Assigned Analyst: {updated_case['assigned_analyst']}")

    # 4. Add analyst note
    note_content = "Confirmed BEC attempt targeting CFO Robert. Wire payment halted."
    status, body = post_json(f"/api/cases/{case_id}/notes", {
        "author": "Lead Analyst Sarah Chen",
        "note": note_content
    })
    case_with_notes = json.loads(body)
    print(f"[Note Added] Notes count: {len(case_with_notes['notes'])}, Latest: {case_with_notes['notes'][-1]['note']}")

    # 5. Verify integrity before kill
    status, body = post_json(f"/api/case/{case_id}/verify-integrity", {})
    integrity_pre = json.loads(body)
    print(f"[Pre-Kill Integrity] Status: {integrity_pre['status']}, Verified: {integrity_pre['verified']}")

    # Save state to file for Part 2
    state = {
        "case_id": case_id,
        "threat_score": threat_score,
        "threat_archetype": threat_archetype,
        "note_content": note_content,
        "evidence_sha256": integrity_pre["evidence_sha256"],
        "merkle_root": integrity_pre["merkle_root"]
    }
    with open("restart_test_state.json", "w") as f:
        json.dump(state, f, indent=2)
    print("[Part 1 Complete] State saved to restart_test_state.json")

def run_part_2():
    print("=== RUNNING PART 2: POST-KILL & RESTART VERIFICATION ===")
    with open("restart_test_state.json", "r") as f:
        state = json.load(f)

    case_id = state["case_id"]
    print(f"[Verifying Target Case] {case_id}")

    # 1. Health check
    status, body = get("/api/health")
    health = json.loads(body)
    print(f"[Health] Status: {status}, Backend: {health.get('database_backend')}")
    assert status == 200

    # 2. Case retrieval across restart
    status, body = get(f"/api/cases/{case_id}")
    assert status == 200
    case_data = json.loads(body)
    print(f"[Case Survived] Case ID: {case_data['case_id']}")
    print(f"[Status Survived] Status: {case_data['status']} (Expected: INVESTIGATING)")
    print(f"[Analyst Survived] Analyst: {case_data['assigned_analyst']} (Expected: Lead Analyst Sarah Chen)")
    assert case_data["status"] == "INVESTIGATING"
    assert case_data["assigned_analyst"] == "Lead Analyst Sarah Chen"

    # 3. Notes retrieval across restart
    notes = case_data.get("notes", [])
    print(f"[Notes Survived] Retrieved {len(notes)} note(s)")
    assert len(notes) >= 1
    found_note = any(n["note"] == state["note_content"] for n in notes)
    assert found_note
    print(f"[Note Content Match] Verified note content preserved: '{notes[-1]['note']}'")

    # 4. Audit events retrieval from database across restart
    from backend.database import get_db_session, AuditLogModel
    from sqlalchemy import select
    with get_db_session() as session:
        logs = session.execute(
            select(AuditLogModel).where(AuditLogModel.case_id == case_id).order_by(AuditLogModel.id.asc())
        ).scalars().all()
        print(f"[Audit Logs Survived] Found {len(logs)} audit event(s) for {case_id}")
        event_types = [l.event_type for l in logs]
        print(f"[Audit Event Types in DB] {event_types}")
        assert "CASE_CREATED" in event_types
        assert "STATUS_CHANGED" in event_types
        assert "NOTE_ADDED" in event_types
        assert "EVIDENCE_ANCHORED" in event_types

    # 5. Cryptographic Evidence Ledger verification across restart
    status, body = post_json(f"/api/case/{case_id}/verify-integrity", {})
    assert status == 200
    integrity_post = json.loads(body)
    print(f"[Post-Restart Integrity] Status: {integrity_post['status']}")
    print(f"[Block Chain Verified] {integrity_post['verified']}")
    print(f"[Evidence Hash Match] {integrity_post['evidence_sha256'] == state['evidence_sha256']}")
    print(f"[Merkle Root Match] {integrity_post['merkle_root'] == state['merkle_root']}")
    assert integrity_post["status"] == "INTEGRITY: VERIFIED"
    assert integrity_post["verified"] is True
    assert integrity_post["evidence_sha256"] == state["evidence_sha256"]
    assert integrity_post["merkle_root"] == state["merkle_root"]

    # 6. Forensic HTML Report across restart (memory cache was cleared!)
    status, html_body = get(f"/api/case/{case_id}/report")
    print(f"[Forensic HTML Report] Status: {status}, HTML Length: {len(html_body)} bytes")
    assert status == 200
    assert "Citadel Forensic Dossier" in html_body
    assert case_id in html_body
    assert "INTEGRITY: VERIFIED" in html_body

    # 7. Forensic JSON Report across restart
    status, json_body = get(f"/api/case/{case_id}/report/json")
    print(f"[Forensic JSON Report] Status: {status}")
    assert status == 200
    report_data = json.loads(json_body)
    assert report_data["case_identification"]["case_id"] == case_id
    assert report_data["case_identification"]["threat_score"] == state["threat_score"]
    assert report_data["evidence_integrity"]["status"] == "INTEGRITY: VERIFIED"

    # 8. Samples verification (Benign, Phishing, BEC)
    print("[Verifying Pipeline Endpoints & Samples Post-Restart]")
    status, body = get("/api/sample/benign_internal_memo.eml")
    assert status == 200
    benign = json.loads(body)
    print(f" - Benign Sample: Score {benign['threat_score']}, Risk {benign['risk_level']}")
    assert benign["threat_score"] <= 35

    status, body = get("/api/sample/phishing_credential_harvest.eml")
    assert status == 200
    phish = json.loads(body)
    print(f" - Phishing Sample: Score {phish['threat_score']}, Risk {phish['risk_level']}")
    assert phish["threat_score"] >= 70

    status, body = get("/api/sample/bec_invoice_bank_change.eml")
    assert status == 200
    bec2 = json.loads(body)
    print(f" - BEC Sample: Score {bec2['threat_score']}, Risk {bec2['risk_level']}")
    assert bec2["threat_score"] >= 75

    print("=== ALL PROCESS-RESTART PERSISTENCE VERIFICATIONS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "part2":
        run_part_2()
    else:
        run_part_1()
