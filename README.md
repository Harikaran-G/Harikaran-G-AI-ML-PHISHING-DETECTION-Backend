# CyberShield — AI & ML Threat Detection Backend Engine

[![FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Architecture](https://img.shields.io/badge/Detection-Hybrid%20AI%20%2B%20ML%20%2B%20Rules-blue)]()
[![Security](https://img.shields.io/badge/Defense-SSRF%20Guard%20%2B%20Anti--Injection-emerald)]()

**CyberShield Backend** is a high-performance, asynchronous cybersecurity intelligence microservice designed for multi-vector threat detection and explainable decision support across **URLs**, **Files (PE/ELF/Scripts/Documents)**, and **Android Applications (APKs)**.

It combines **deterministic heuristic rules**, **supervised machine learning classifiers**, **unsupervised Isolation Forest anomaly detection**, **IOC relationship graph correlation**, and a **grounded Explainable AI (XAI) with MITRE ATT&CK knowledge retrieval (RAG)**.

---

## 🏛️ System Architecture

```
                         INCOMING TARGET
                                │
                 ┌──────────────┼──────────────┐
                 ↓              ↓              ↓
                URL            FILE           APK
                 │              │              │
                 └──────────────┼──────────────┘
                                ↓
                       FEATURE EXTRACTION
                                │
                 ┌──────────────┼──────────────┐
                 ↓              ↓              ↓
            RULE ENGINE     ML ENGINE      AI ENGINE
                 │              │              │
                 │        ┌─────┴─────┐        │
                 │        ↓           ↓        │
                 │   Classifier   Anomaly      │
                 │        │        Detection   │
                 │        └─────┬─────┘        │
                 │              │              │
                 └──────────────┼──────────────┘
                                ↓
                     THREAT INTELLIGENCE
                                ↓
                     IOC CORRELATION ENGINE
                                ↓
                     MULTI-SIGNAL RISK ENGINE
                                ↓
                     EXPLAINABLE AI LAYER (RAG)
                                ↓
                  FINAL SECURITY DECISION & DOSSIER
```

---

## ✨ Core Detection Capabilities

### 1. 🌐 SSRF-Guarded URL & Domain Analyzer
- **SSRF Defense Boundary**: Blocks RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`, `localhost`), and cloud instance metadata (`169.254.169.254`).
- **Feature Extraction**: 14 lexical and structural signals including hostname/path Shannon entropy, subdomain depth, digit/special character ratios, punycode/IDN homograph indicators, and URL keyword stacking.
- **ML Classifier**: `URL-GradientBoost-Ensemble` with calibrated probabilities and SHAP-equivalent feature importance rankings.
- **Anomaly Detection**: `IsolationForest-URL` detecting unknown zero-day / fast-flux domain patterns.

### 2. 📁 Static Binary & File Dissection Engine
- **Non-Execution Quarantine**: Safe static extraction without executing untrusted code on production hosts.
- **Cryptographic Fingerprinting**: Real-time SHA-256, SHA-1, and MD5 hash calculation.
- **Shannon Byte Entropy**: Evaluates packed sections, encrypted shellcode, and steganographic data.
- **Executable Heuristics**: Portable Executable (`pefile`) section analysis, double-extension mask detection (`.pdf.exe`), suspicious API imports, and embedded C2 IP/URL extraction.
- **ML Classifier**: `File-RandomForest-Static` with top contributing feature weights.

### 3. 📱 Android APK Static Inspector
- **Manifest & Component Extraction**: Dissects `AndroidManifest.xml`, exported activities, services, receivers, and intent-filter hooks using `androguard`.
- **Capability Matrix Risk**: Detects high-risk permission combinations (e.g. `SYSTEM_ALERT_WINDOW` screen overlays combined with `SEND_SMS` or `BIND_ACCESSIBILITY_SERVICE`).
- **ML Classifier**: `APK-Capability-GradientBoost` assessing device admin abuse and privilege escalation risks.

### 4. 🧠 Multi-Signal Risk Aggregator & Decision Support
- Aggregates **Rule Score (50%)**, **Supervised ML Probability (30%)**, **Isolation Forest Anomaly Score (20%)**, and **Cross-Vector IOC Correlation Boosts** into a deterministic normalized score (0–100).
- Emits explainable verdicts:
  - `SAFE` (0–29)
  - `SUSPICIOUS` (30–59)
  - `HIGH_RISK` (60–79)
  - `CRITICAL` (80–100)
  - `REQUIRES_REVIEW` (Flagged by Anomaly Detector for zero-day review)

### 5. 🛡️ Grounded Explainable AI (XAI) & MITRE ATT&CK RAG
- **Prompt Injection Defense**: Sanitizes and neutralizes adversarial instruction override tokens found within scanned files or URLs.
- **Zero Hallucination Policy**: All AI explanations are strictly grounded in extracted indicator artifacts.
- **MITRE ATT&CK Mapping**: Maps findings directly to techniques like `T1036.007` (Masquerading), `T1566.002` (Spearphishing Link), and `T1437.001` (Overlay Injection).
- **Interactive SOC Assistant**: Provides contextual question-answering over scan dossiers.

---

## 📁 Repository Structure

```
backend/
├── app/
│   ├── main.py                     # FastAPI application endpoints & middleware
│   ├── detectors/
│   │   ├── url_detector.py         # URL probe, DNS resolver & SSRF filter
│   │   ├── file_detector.py        # Static file, PE dissection & entropy calculation
│   │   └── apk_detector.py         # APK manifest & permission matrix analysis
│   ├── ml/
│   │   ├── features/
│   │   │   ├── url.py              # URL lexical & structural feature extractor
│   │   │   ├── file.py             # File static byte & PE feature extractor
│   │   │   └── apk.py              # APK capability feature extractor
│   │   ├── classifiers/
│   │   │   ├── url_classifier.py   # GradientBoost URL phishing classifier
│   │   │   ├── file_classifier.py  # RandomForest static malware classifier
│   │   │   └── apk_classifier.py   # GradientBoost APK capability classifier
│   │   ├── anomaly/
│   │   │   └── anomaly_detector.py # Isolation Forest unsupervised outlier engine
│   │   ├── correlation/
│   │   │   └── ioc_graph.py        # Node-link IOC relationship graph builder
│   │   └── scoring/
│   │       └── risk_engine.py      # Multi-signal deterministic risk aggregator
│   ├── ai/
│   │   ├── rag.py                  # MITRE ATT&CK security knowledge retriever
│   │   └── assistant.py            # Grounded AI reasoning & prompt-injection defense
│   └── services/
│       └── scoring_engine.py       # Baseline normalization engine
├── requirements.txt                # Python dependencies
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11 or 3.12
- `pip` and virtual environment support (`venv`)

### Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Harikaran-G/AI-ML-PHISHING-DETECTION-Backend.git
   cd AI-ML-PHISHING-DETECTION-Backend
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the FastAPI backend server:**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

5. **Verify server health:**
   ```bash
   curl http://localhost:8000/health
   ```
   Interactive Swagger documentation will be available at: **[http://localhost:8000/docs](http://localhost:8000/docs)**.

---

## 🔌 API Reference

### `GET /health`
Returns operational health status and engine readiness.

### `POST /analyze/url`
Performs SSRF-guarded inspection, ML classification, anomaly scoring, IOC graphing, and AI MITRE mapping on a web URL.
```json
{
  "url": "https://secure-login.bank-update.xn--p1ai.tk/auth"
}
```

### `POST /analyze/file`
Uploads a binary, document, script, or archive for isolated static analysis.
- **Content-Type**: `multipart/form-data`
- **Field**: `file: <Binary>`

### `POST /analyze/apk`
Uploads an Android APK package for manifest and permission matrix analysis.
- **Content-Type**: `multipart/form-data`
- **Field**: `file: <APK-Binary>`

### `POST /ai/assistant`
Interacts with the grounded AI Security Assistant to interrogate a specific scan result.
```json
{
  "query": "Why was this target classified as high risk?",
  "scanContext": { ... }
}
```

---

## 🔒 Defensive Security Policy
- This application is strictly intended for **authorized defensive analysis, threat intelligence triage, and educational security research**.
- Static engines **do not execute** binary payloads, shell scripts, or APK bytecode on the host environment.

---

## 📄 License
This project is licensed under the MIT License — see the repository license details for more information.
# Harikaran-G-AI-ML-PHISHING-DETECTION-Backend
