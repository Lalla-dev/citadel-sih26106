"""
Citadel Security Platform - REST API & Web Server
Serves the detection pipeline endpoints and mounts the SOC analyst dashboard.
"""
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse

from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator
from backend.schemas import AnalysisResult

app = FastAPI(
    title="Citadel Email Security Platform",
    description="Adversarial-resilient phishing and Business Email Compromise (BEC) detection engine.",
    version="1.0.0"
)

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
FRONTEND_DIR = BASE_DIR / "frontend"

orchestrator = CitadelDetectorOrchestrator()

# Known metadata descriptions for pre-packaged samples (Explicitly synthetic benchmark test data)
SAMPLE_DESCRIPTIONS = {
    "benign_project_update.eml": {
        "title": "Benign Corporate Sync",
        "category": "Synthetic Benchmark (Clean)",
        "description": "Synthesized internal sprint sync test case demonstrating passing SPF and DKIM authentication."
    },
    "credential_phishing_link.eml": {
        "title": "Credential Phishing Alert",
        "category": "Synthetic Benchmark (Phishing)",
        "description": "Synthesized account suspension lure testing high-entropy IP-based obfuscated link detection."
    },
    "bec_ceo_wire_fraud.eml": {
        "title": "CEO Wire Fraud (BEC)",
        "category": "Synthetic Benchmark (BEC)",
        "description": "Synthesized executive display-name spoofing scenario testing Reply-To diversion and acquisition wire pretexting."
    },
    "bec_invoice_bank_change.eml": {
        "title": "Bogus Vendor Invoice",
        "category": "Synthetic Benchmark (BEC)",
        "description": "Synthesized vendor banking details modification scenario testing remittance and routing cues."
    }
}

from backend.database import init_db, get_active_backend

@app.on_event("startup")
def on_startup():
    """Initializes persistent database layer (PostgreSQL or SQLite fallback)."""
    init_db()

@app.get("/api/health")
def health_check():
    ml_status = "unavailable"
    try:
        from backend.ml.classifier import get_ml_classifier
        clf = get_ml_classifier()
        ml_status = "active" if clf.is_trained else "not_trained"
    except Exception:
        pass

    db_backend = "unknown"
    try:
        db_backend = get_active_backend()
    except Exception:
        pass

    return {
        "status": "operational",
        "system": "Citadel Phase 2 MVP",
        "ml_engine": ml_status,
        "database_backend": db_backend
    }

@app.get("/api/ml/status")
def ml_model_status():
    """Returns ML model training metrics and status."""
    try:
        from backend.ml.classifier import get_ml_classifier
        clf = get_ml_classifier()
        return {
            "ml_available": clf.is_trained,
            "model_type": "TF-IDF + Logistic Regression",
            "training_metrics": clf.training_metrics if clf.is_trained else None,
            "disclaimer": "Trained on synthetic benchmark corpus."
        }
    except Exception as e:
        return {"ml_available": False, "error": str(e)}

@app.get("/api/samples")
def list_samples() -> List[Dict[str, Any]]:
    """Lists pre-packaged sample .eml files available for testing."""
    samples = []
    if SAMPLES_DIR.exists():
        for file in sorted(SAMPLES_DIR.glob("*.eml")):
            fname = file.name
            meta = SAMPLE_DESCRIPTIONS.get(fname, {
                "title": fname.replace("_", " ").replace(".eml", "").title(),
                "category": "Custom",
                "description": "Pre-packaged sample email."
            })
            samples.append({
                "filename": fname,
                "title": meta["title"],
                "category": meta["category"],
                "description": meta["description"],
                "size_bytes": file.stat().st_size
            })
    return samples

@app.get("/api/sample/{name}", response_model=AnalysisResult)
def analyze_sample(name: str):
    """Analyzes a pre-packaged sample email."""
    # Basic filename sanitization to prevent path traversal
    safe_name = os.path.basename(name)
    file_path = SAMPLES_DIR / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Sample '{name}' not found.")
    
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
        parsed = parse_eml(raw_bytes)
        return orchestrator.analyze(parsed, filename=safe_name, raw_bytes=raw_bytes)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/sample/{name}/graph")
def get_sample_threat_graph(name: str):
    """Returns the forensic entity correlation graph for a sample email."""
    result = analyze_sample(name)
    return result.threat_graph

@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_uploaded_eml(file: UploadFile = File(...)):
    """Accepts an uploaded .eml file and returns comprehensive threat and forensic analysis."""
    if not file.filename.lower().endswith((".eml", ".txt", ".msg")):
        # Allow generic text or eml
        pass

    try:
        content = await file.read()
        parsed = parse_eml(content)
        return orchestrator.analyze(parsed, filename=file.filename, raw_bytes=content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error parsing .eml file: {str(e)}")

@app.post("/api/case/{case_id}/verify-integrity")
def verify_case_integrity_endpoint(case_id: str):
    """
    Cryptographic verification endpoint for evidence integrity.
    Verifies that the original raw .eml bytes, parsed headers, and detection verdict
    match the append-only cryptographic evidence ledger without tampering.
    """
    from backend.integrity import get_evidence_ledger
    ledger = get_evidence_ledger()
    verification = ledger.verify_case(case_id)
    if "error" in verification and "No cryptographic ledger block found" in verification["error"]:
        raise HTTPException(status_code=404, detail=verification["error"])
    return verification

@app.post("/api/case/{case_id}/simulate-tamper")
def simulate_tamper_endpoint(case_id: str, action: str = "evidence"):
    """
    Simulates tampering for live SOC demonstration and unit testing:
      action='evidence': Modifies raw stored .eml bytes.
      action='verdict': Modifies threat score.
      action='ledger': Forges previous block hash.
    """
    from backend.integrity import get_evidence_ledger
    ledger = get_evidence_ledger()
    if action == "evidence":
        success = ledger.simulate_tamper_evidence(case_id, b"CORRUPTED_FORGED_EVIDENCE_BYTES_XYZ")
    elif action == "verdict":
        success = ledger.simulate_tamper_verdict(case_id, 0)
    elif action == "ledger":
        block = ledger.get_case_block(case_id)
        if block:
            success = ledger.simulate_tamper_block(block["block_index"], "f" * 64)
        else:
            success = False
    else:
        success = False

    if not success:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found or cannot be tampered.")
    return {"status": "TAMPER_SIMULATED", "case_id": case_id, "tamper_mode": action}

@app.get("/api/case/{case_id}/report", response_class=HTMLResponse)
def get_case_report_html(case_id: str):
    """
    Generates and returns the printable HTML forensic incident dossier for a case.
    """
    from backend.reports import get_case_result, generate_html_report
    result = get_case_result(case_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"Case '{case_id}' not found. Please analyze an email to generate a case dossier."
        )
    return HTMLResponse(content=generate_html_report(result))

@app.get("/api/case/{case_id}/report/json")
def get_case_report_json(case_id: str):
    """
    Returns the SIEM/SOAR-ready structured JSON forensic export for a case.
    """
    from backend.reports import get_case_result, generate_json_report
    result = get_case_result(case_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"Case '{case_id}' not found. Please analyze an email to generate a case dossier."
        )
    return generate_json_report(result)

# -------------------------------------------------------------
# Phase 7: SOC Case Management & Incident Triage Endpoints
# -------------------------------------------------------------
@app.get("/api/cases")
def list_cases_endpoint(
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    search: Optional[str] = None
):
    """
    Returns the live SOC incident queue filtered by status, risk level, or keyword.
    Includes aggregate queue statistics.
    """
    from backend.cases import get_case_repository
    repo = get_case_repository()
    cases = repo.list_cases(status=status, risk_level=risk_level, search=search)
    stats = repo.get_queue_statistics()
    return {
        "cases": [c.model_dump(exclude={"analysis_result"}) for c in cases],
        "stats": stats,
        "count": len(cases)
    }

@app.get("/api/cases/{case_id}")
def get_case_details_endpoint(case_id: str):
    """
    Retrieves full details for a case ticket, including historical notes and full AnalysisResult.
    """
    from backend.cases import get_case_repository
    repo = get_case_repository()
    ticket = repo.get_case(case_id)
    if not ticket:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return ticket.model_dump()

@app.patch("/api/cases/{case_id}/status")
def update_case_status_endpoint(case_id: str, payload: Dict[str, Any]):
    """
    Updates the incident lifecycle status and optionally re-assigns an analyst.
    Allowed statuses: NEW, TRIAGED, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    """
    from backend.cases import get_case_repository
    repo = get_case_repository()
    status = payload.get("status")
    analyst = payload.get("analyst")
    if not status:
        raise HTTPException(status_code=400, detail="Missing required field 'status'.")

    try:
        updated = repo.update_status(case_id, status=status, analyst=analyst)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
        return updated.model_dump()
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

@app.post("/api/cases/{case_id}/notes")
def add_case_note_endpoint(case_id: str, payload: Dict[str, Any]):
    """
    Adds a timestamped analyst investigation note to the case ticket.
    """
    from backend.cases import get_case_repository
    repo = get_case_repository()
    note_text = payload.get("note")
    author = payload.get("author", "SOC Analyst")
    if not note_text:
        raise HTTPException(status_code=400, detail="Missing required field 'note'.")

    updated = repo.add_note(case_id, note_text=note_text, author=author)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return updated.model_dump()

# Mount static frontend files if directory exists
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_dashboard():
        return FileResponse(FRONTEND_DIR / "index.html")
