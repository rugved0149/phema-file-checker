PHEMA – Standalone Malicious File Checker
Overview

The PHEMA File Checker is a standalone static file analysis module designed as part of the broader Phishing & Hybrid Event Monitoring Architecture (PHEMA) system.

This project focuses on primary static detection and emits structured security events suitable for ingestion by a centralized correlation engine.

It is intentionally modular, correlation-friendly, and does not perform final verdict classification.

Project Intent

The objective of this module is to:

Perform static file inspection

Extract technical security indicators

Emit structured detection signals

Maintain strict modular independence

Avoid correlation, blocking, or behavioral analysis

This design aligns with modern SIEM/SOC architectures where detection modules emit granular events that are later correlated centrally.

Core Capabilities

SHA256 file hashing

YARA-based signature matching

Suspicious string pattern detection

File entropy analysis (packed/obfuscated indicators)

Event-based output format

FastAPI backend

Web-based upload interface

Deployment-ready architecture (Render-compatible)

Detection Model

This module operates under Primary Static Analysis Only:

✔ Reads file bytes
✔ Matches against YARA rules
✔ Identifies suspicious indicators
✔ Calculates entropy
✔ Emits independent detection events

It does NOT:

✘ Execute files
✘ Perform sandboxing
✘ Perform behavioral analysis
✘ Compute final risk score
✘ Label files as “malicious” or “safe”
✘ Correlate with other modules

Event Output Contract

Each detected indicator generates one independent structured event:

{
  "entity_id": "<file_hash>",
  "entity_type": "file",
  "module": "file_checker",
  "signal": "<indicator>",
  "confidence": 0.0 – 1.0,
  "severity": "low | medium | high",
  "metadata": { ... }
}

This ensures compatibility with centralized correlation services.

Architecture
Frontend (Upload UI)
        ↓
FastAPI Backend
        ↓
Static Analysis Engine
        ↓
Indicator Extraction
        ↓
Event Adapter
        ↓
Structured Detection Events

The module is intentionally designed to remain detection-focused and correlation-neutral.

Supported File Types

.txt

.ps1

.js

.vbs

.exe

.bin

.zip

Maximum file size: 10MB

Performance

Average scan time (small files): ~0.05 – 0.2 seconds

Depends on file size and number of YARA rules

Limitations

This project is intentionally constrained to:

Static analysis only

Signature-based detection

Heuristic string matching

Entropy-based suspicion

It does not detect:

Polymorphic malware without signature

Advanced obfuscation beyond entropy detection

Zero-day exploits

Memory-only malware

Runtime behavior anomalies

It should be considered a detection signal generator, not a complete antivirus solution.

Security Philosophy

The design follows the principle:

Detection modules should emit evidence, not verdicts.

This prevents premature classification and enables centralized risk computation across multiple signals.

Deployment

Designed to be deployed as:

Backend → Render (persistent Python service)

Frontend → Same service or static hosting

Start command:

uvicorn api.main:app --host 0.0.0.0 --port $PORT
Future Enhancements

Expanded YARA rule sets

Integration with phishing detection module

Session-based entity tracking

Cross-module correlation engine

Dashboard visualization

Automated hash intelligence lookup

Author

Rugved Suryawanshi
Computer Science Engineering
Cybersecurity Systems & Detection Architecture Focus