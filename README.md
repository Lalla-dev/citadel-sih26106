<img width="1919" height="1114" alt="image" src="https://github.com/user-attachments/assets/8c301890-3062-4a32-91cf-ad5358bb416a" />
<img width="1919" height="1114" alt="image" src="https://github.com/user-attachments/assets/c413e897-4cd9-40b3-8d83-57bebbd4def7" />
<img width="1919" height="1109" alt="image" src="https://github.com/user-attachments/assets/a74de93f-ee01-42ce-b80f-f35ef5858c92" />
<img width="1919" height="1110" alt="image" src="https://github.com/user-attachments/assets/d95e82f4-633b-4e14-bcad-c34502a1d144" />
<img width="1919" height="1114" alt="image" src="https://github.com/user-attachments/assets/21b486cb-6be7-4399-87dd-2a103283b59b" />
<img width="1919" height="1113" alt="image" src="https://github.com/user-attachments/assets/a553e7d1-d9ac-4ff7-994a-132ad1b2f9f8" />
<img width="1919" height="1115" alt="image" src="https://github.com/user-attachments/assets/87193e03-824f-454f-baea-326875fbe8b4" />
<img width="1919" height="1115" alt="image" src="https://github.com/user-attachments/assets/25335d0d-17d3-432c-998c-eb592ee8e9f3" />```markdown
# Citadel — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
SIH26106 · Smart India Hackathon (SIH 2026)

An analyst-focused prototype for ingesting suspicious email, extracting forensic evidence, applying AI-assisted detection and BEC/NLP analysis, enriching and correlating indicators, triaging incidents in a SOC workflow, and preserving tamper-evident forensic artifacts.

---

## Table of contents
- Project overview
- Problem statement
- Key features
- Technical approach / 12-stage workflow
- System architecture
- Technology stack
- Project structure (typical / expected)
- Local installation & setup
- How to run the application (development)
- Testing
- Demonstration scenarios
- Security & privacy considerations
- Current limitations (prototype transparency)
- Future roadmap (planned work)
- Smart India Hackathon information
- Team
- Research foundation
- Contact & contribution

---

## Project overview
Citadel provides a single investigator workspace to detect, investigate, correlate and preserve evidence from suspicious email. The platform goes beyond simple phishing classification — it extracts headers, message artifacts and IOCs, analyzes social-engineering features, applies a lightweight ML classification, enriches infrastructure data (DNS / ASN / GeoIP), correlates entities into a relationship graph, supports SOC case management, and produces forensic reports with local cryptographic evidence integrity.

Core product goals:
- Combine detection with investigation and reproducible forensic evidence.
- Provide explainable signals and analyst-friendly UI panels.
- Support SOC triage and case workflows for rapid incident handling.

---

## Problem statement
Phishing, spoofing and Business Email Compromise (BEC) attacks distribute signals across headers, sender identity, message content, URLs, and infrastructure. Many existing systems flag suspicious mail but stop short of providing an investigation workflow that correlates indicators, preserves evidence, and supports SOC case actions. Citadel addresses this gap by integrating parsing, analysis, enrichment, correlation and evidence preservation into a single prototype platform.

---

## Key features
(Described only as implemented / shown in supplied material)
- Email ingestion (drag & drop / file upload of .eml)
- Parsing of RFC 5322 / MIME structure (headers, body, attachments)
- Header authentication & identity summary (analysis from available headers)
- Social-engineering / BEC intent radar (urgency, authority, financial/credential requests)
- ML classification (TF‑IDF + n-gram features + Logistic Regression; outputs class and confidence)
- IOC extraction: URLs, domains, IPs; URL structural and entropy analysis
- Enrichment: DNS, approximate GeoIP, ASN and curated intelligence (prototype/offline)
- Threat correlation: interactive force-directed graph connecting email ↔ sender ↔ domain ↔ URL ↔ IP ↔ ASN
- Unified risk scoring and detection reasoning cards
- SOC triage queue and case management UI
- Evidence integrity: SHA-256 fingerprints and a locally maintained Merkle-linked evidence ledger
- Forensic report generation (HTML / JSON) and downloadable artifacts
- Normalized message inspector for forensic review

---

## Technical approach — 12-stage workflow
The UI and pipeline implement the following end-to-end stages:

1. EMAIL INGESTION  
   - Accepts .eml (raw MIME) and preserves original bytes as evidence.

2. PARSE  
   - RFC 5322 / MIME processing to extract headers, recipients, subject, body, HTML, attachments and URLs.

3. SECURITY ANALYSIS  
   - Analyze authentication-related signals present in headers (interpreting SPF/DKIM/DMARC fields when available).  
   - NOTE: current prototype parses authentication information from email headers; it does not perform independent live DNS-based SPF/DKIM/DMARC verification.

4. AI / ML DETECTION  
   - TF‑IDF + 1–2 gram features, Logistic Regression, multi-class (Benign / Phishing / BEC) with confidence score.

5. NLP / BEC ANALYSIS  
   - Detect social-engineering cues (urgency, authority, financial requests, credential prompts, CEO fraud patterns) and compute a Psychological Coercion Index (PCI).

6. IOC EXTRACTION  
   - Extract URLs, domains and IPs; compute URL features (Shannon entropy, length, digit/special ratios, subdomain depth, punycode, encoding flags).

7. ENRICHMENT  
   - Offline/curated enrichment: DNS, approximate GeoIP, ASN, and local threat intelligence records.

8. THREAT CORRELATION  
   - Build an interactive graph connecting email → sender → domain → URL → IP → ASN → intelligence artefacts to help analysts pivot.

9. RISK SCORING  
   - Aggregate signals (header analysis, heuristics, ML, NLP, URL analysis, enrichment, correlation) into threat score, risk level, classification, confidence and detection reasons.

10. SOC CASE  
    - Convert analysis results into a SOC case: queue, triage, status, assignment, analyst notes and audit history.

11. EVIDENCE INTEGRITY  
    - Compute SHA-256 of original email bytes.  
    - Store evidence records in a local Merkle-linked ledger for tamper-evident verification.  
    - NOTE: this is a local Merkle ledger; it is not a distributed blockchain network.

12. FORENSIC REPORT & DASHBOARD  
    - Generate forensic reports (HTML / JSON) that include executive summary, header analysis, ML/NLP results, IOC analysis, correlation visuals and integrity metadata.

Mermaid visualization of the pipeline:
```mermaid
flowchart LR
  A[Email Ingest (.eml)] --> B[Parse (RFC5322 / MIME)]
  B --> C[Security Analysis (headers)]
  B --> D[IOC Extraction (URLs, Domains, IPs)]
  B --> E[ML Classification (TF‑IDF + LR)]
  E --> F[NLP / BEC Analysis (PCI)]
  D --> G[Enrichment (DNS / GeoIP / ASN / curated intel)]
  C --> H[Scoring & Detection Reasons]
  F --> H
  G --> H
  H --> I[Threat Correlation Graph]
  I --> J[SOC Case Management]
  A --> K[Evidence Integrity (SHA-256 + Merkle)]
  H --> L[Forensic Report (HTML / JSON)]
```

---

## System architecture (high-level)
- Frontend: static HTML5/CSS3 and vanilla JavaScript providing the dashboard, upload UI, detailed analysis panels and force-directed graph visualizations.
- Backend: Python FastAPI application (served with Uvicorn) exposing analysis endpoints and orchestration of parsing, ML, enrichment, correlation and report generation.
- ML: scikit-learn based TF‑IDF vectorizer and Logistic Regression classifier (trained offline).
- Storage: file storage for original .eml artifacts and generated reports; lightweight relational store (e.g., PostgreSQL as a future/optional persistence) or file-backed metadata for cases and evidence ledger.
- Workers/Tasks: optional background task system (for heavier enrichment/report generation) — architectural placeholder; prototype can run analysis synchronously for demo.
- Evidence ledger: local Merkle-linked data structure storing SHA-256 hashes and linking records to provide tamper-evidence.

A concise architecture diagram (logical):
- Browser (UI) ↔ FastAPI backend ↔ Parser / Detector / Enricher / Correlator ↔ Storage (files + metadata)  
- Local Merkle ledger and report generator attached to backend

---

## Technology stack
As implemented and shown in the project materials:
- Frontend: HTML5, CSS3, Vanilla JavaScript (interactive graphs rendered client-side)
- Backend: Python, FastAPI, Uvicorn
- Email processing: Python email library (RFC 5322 / MIME parsing)
- ML: scikit-learn — TF‑IDF vectorizer, n-gram features, Logistic Regression
- IOC & security analysis: URL parsing, Shannon entropy calculations, heuristic detectors
- Enrichment: DNS, approximate GeoIP, ASN lookups, curated/offline threat intelligence
- Evidence Integrity: SHA-256 hashing, local Merkle-linked evidence ledger

Important: the README does not claim use of external technologies (React, Node, transformers, live commercial feeds, distributed blockchain) unless those are explicitly present in the repository.

---

## Project structure (typical / expected)
Use the repository's actual file layout if present. The prototype commonly uses the following organization:

- backend/                — FastAPI app, analysis modules, parser, ML model loader
  - backend/app.py
  - backend/api/
  - backend/analysis/
  - backend/models/
  - backend/integrity/
- frontend/               — HTML/CSS/JS dashboard and visualization assets
  - frontend/index.html
  - frontend/assets/
  - frontend/js/
- data/                   — sample .eml files, fixtures
- tests/                  — automated tests (unit / integration)
- reports/                — generated forensic report examples (HTML / JSON)
- requirements.txt        — Python dependencies
- README.md               — this document

Note: Replace or align this layout with the repository's actual file/folder names where applicable.

---

## Local installation & setup
The instructions below are intentionally generic so they work across Windows, macOS and Linux. Adjust paths and commands to match the repository layout and project scripts.

1. Clone the repository
```bash
git clone https://github.com/Lalla-dev/citadel-sih26106.git
cd citadel-sih26106
```

2. Create and activate Python virtual environment
- macOS / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```
- Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Install Python dependencies
```bash
pip install -r requirements.txt
```
If a requirements file is not present, install at minimum:
```bash
pip install fastapi uvicorn scikit-learn python-multipart
```

4. Configuration
- Create a `.env` or config file with local settings (example names shown; use repository docs for exact variables):
```
APP_ENV=development
STORAGE_PATH=./data/artifacts
SECRET_KEY=change-me-for-demo
```

5. Sample data
- Use `data/` or `samples/` (if present) to try the demo ingestion scenarios.

---

## How to run the application (development)
Examples — adapt to repository-provided scripts.

Start the backend (FastAPI + Uvicorn):
```bash
# from repo root
uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```
- If the backend exposes static files for the frontend, open: http://127.0.0.1:8000
- If frontend is a static folder (frontend/index.html), you can open the HTML directly in a browser or serve it via a simple HTTP server:
```bash
# from frontend/ directory (Python 3)
python -m http.server 8080
# then open http://127.0.0.1:8080
```

Docker (if a Dockerfile / docker-compose.yml exists in the repo):
```bash
docker-compose up --build
# or
docker build -t citadel .
docker run -p 8000:8000 citadel
```

Follow the repository's actual start scripts if present (e.g., Makefile, start.sh).

---

## Testing
- Run unit tests with pytest:
```bash
pytest tests/
```
- Current development checkpoint: 96 passing tests (status at the time of this README). This number is a development checkpoint and may change as development continues.

- Linting & formatting: run configured linters (e.g., flake8, black) where available.

---

## Demonstration scenarios (controlled / synthetic)
Use the included sample messages or synthetic fixtures for each controlled demo:

1. Clean / benign project email  
   - Demonstrate ingestion, parsing, and a low-risk score with generation of a clean forensic report.

2. Credential phishing email  
   - Show URL extraction, entropy/structure signals, ML classification leaning toward phishing and IOC enrichment.

3. CEO fraud / Executive impersonation (BEC)  
   - Show NLP/BEC indicators (authority, financial request, urgency), PCI scoring, and triage to SOC queue.

4. Invoice / bank-detail-change BEC  
   - Show detection of payment instructions, domain reputation notes, URL analysis and case creation for SOC follow-up.

Important: these demonstration datasets are controlled/synthetic and should not be presented as live intelligence.

---

## Security & privacy considerations
- Treat ingested messages as sensitive data. Restrict access to the application and stored artifacts to authorized personnel only.
- Use HTTPS for all production deployments. Protect secrets (do not store credentials in repository).
- Minimize data retention when possible; provide deletion or archival controls for sensitive messages.
- Evidence artifacts include SHA-256 fingerprints and local Merkle links for tamper-evidence, but legal admissibility and chain-of-custody depend on deployment, access controls and organizational policies.
- When demoing on public networks, redact PII or use synthetic test messages.

---

## Current limitations (prototype transparency)
Be explicit about what is and is not implemented in the current prototype:
- Authentication analysis (SPF/DKIM/DMARC): derived from fields present in the email headers. The prototype does not perform independent live DNS/SPF/DKIM/DMARC verification.
- Threat intelligence: enrichment is based on offline/curated intelligence and local lookups in the prototype. No claimed live commercial threat-intel feed.
- GeoIP: approximate location derived from GeoIP databases — not exact physical location.
- ML: TF‑IDF + Logistic Regression baseline is used; transformer-based production inference is not claimed.
- Evidence ledger: local Merkle-linked ledger provides tamper-evidence in the prototype. It is not a distributed blockchain network.
- SOC actions: the UI supports analyst workflows and recommended playbooks; the system does not perform autonomous endpoint containment or enforcement.
- Legal / forensic admissibility: the system provides reproducible artifacts with integrity metadata but does not guarantee admissibility — consult legal processes and organizational policy.

---

## Future roadmap (planned / not yet implemented)
(Separate planned capabilities from implemented features)
Planned or desirable next steps (subject to team prioritization):
- Add persistent PostgreSQL storage and migration scripts
- Expand ML training datasets and evaluation with larger real-world corpora
- Optional transformer-based contextual NLP modules (research-phase)
- Configurable live SPF/DKIM/DMARC verification via DNS lookup
- Integration with live threat-intelligence feeds (configurable)
- Connector integrations: Gmail / Microsoft 365 ingestion
- SOC/SOAR integrations (ServiceNow, Jira, Splunk)
- Docker-compose and Kubernetes deployment manifests
- Role-based access control (RBAC), audit logging and enterprise hardening
- Optional blockchain anchoring for external evidence anchoring (research/POC)

All roadmap items are planned work; they are not claimed as currently implemented.

---

## Smart India Hackathon (SIH) information
- Project: Citadel — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform  
- Hackathon: Smart India Hackathon (SIH 2026)  
- Problem Statement ID: SIH26106  
- Organization: All India Council for Technical Education (AICTE)  
- Category / Theme: Software · Blockchain & Cybersecurity  
- Team name: Citadel · Team ID: 28  
- Mentor: Divya Ma'am  

Suggested demo duration: 8–12 minutes to showcase ingestion → triage → correlation → evidence preservation → report export.

---

## Team
(Replace placeholders with actual contributor names, roles and contact info)
- Team Lead / Product: [Name] — Product & Demo lead  
- Backend / Data Engineer: [Name] — Parsing, enrichment, ML orchestration  
- Frontend / UX Engineer: [Name] — Dashboard & visualizations  
- ML / Research Engineer: [Name] — classifier training, NLP/BEC features  
- DevOps / QA: [Name] — deployment, CI, tests  
- Mentor: Divya Ma'am

Add GitHub handles, email or institution affiliations here for judge contact.

---

## Research foundation
The Citadel prototype is informed by academic and applied research areas including:
- Explainable phishing-email detection and model interpretability
- Feature-engineering and ensemble approaches for email classification (TF‑IDF / n-grams / LR baseline)
- Adversarial robustness research for URL and content-based detection
- Business Email Compromise research on social-engineering and pretexting patterns
- Graph-based correlation for infrastructure and campaign analysis

The system emphasizes explainability, contextual understanding, infrastructure correlation and SOC usability rather than claiming production-ready detection metrics. Any datasets, papers or external references used during development should be recorded in `/docs/` and cited appropriately.

---

## Contribution, issues & contact
- To report issues or propose features: open an Issue in this repository.  
- For code contributions: fork the repo, create a branch, and open a pull request describing your changes and tests.  
- For security-sensitive disclosures, contact the maintainers privately (add contact details here).

---

## A final note on provenance & honesty
This README describes the Citadel prototype as presented in the provided project materials and dashboard screenshots. It deliberately avoids overstating capabilities — particularly for live verification, commercial threat feeds, distributed ledger claims, transformer inference, or legal guarantees. Replace placeholders (team names, contact info, configuration variables) with project-specific data before public release.

Thank you for reviewing Citadel — please see /docs/ and the project UI for guided walkthroughs and sample data for demonstrations.
```


