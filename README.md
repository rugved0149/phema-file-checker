# 🛡️ PHEMA – Standalone Malicious File Checker

---

## 🔎 Overview

The **PHEMA File Checker** is a standalone static file analysis module built as part of the broader **Phishing & Hybrid Event Monitoring Architecture (PHEMA)**.

It performs **primary static detection** and emits structured security events designed for ingestion by a centralized correlation engine.

This module is intentionally:

* 🧩 Modular
* 🔗 Correlation-friendly
* ⚖️ Verdict-neutral

It does **not** classify files as malicious or safe.

---

## 🎯 Project Intent

This module was designed to:

* 📂 Perform static file inspection
* 🧠 Extract technical security indicators
* 📡 Emit structured detection signals
* 🏗️ Maintain strict modular independence
* 🚫 Avoid correlation, blocking, or behavioral logic

The architecture mirrors modern **SIEM/SOC detection pipelines**, where modules emit granular evidence that is later correlated centrally.

---

## 🚀 Core Capabilities

* 🔐 SHA256 file hashing
* 🧬 YARA-based signature matching
* 🧾 Suspicious string pattern detection
* 📊 File entropy analysis (packed/obfuscated indicators)
* 📦 Event-based structured output
* ⚡ FastAPI backend
* 🌐 Web-based upload interface
* ☁️ Deployment-ready (Render-compatible)

---

## 🧪 Detection Model

This module operates under **Primary Static Analysis Only**.

### ✔ What It Does

* Reads file bytes
* Matches against YARA rules
* Identifies suspicious indicators
* Calculates entropy
* Emits independent detection events

### ✘ What It Does NOT Do

* Execute files
* Perform sandboxing
* Conduct behavioral analysis
* Compute final risk scores
* Label files as “malicious” or “safe”
* Correlate with other modules

This ensures the system remains **detection-focused and correlation-neutral**.

---

## 📡 Event Output Contract

Each detected indicator generates a structured event:

```json
{
  "entity_id": "<file_hash>",
  "entity_type": "file",
  "module": "file_checker",
  "signal": "<indicator>",
  "confidence": 0.0 – 1.0,
  "severity": "low | medium | high",
  "metadata": { ... }
}
```

This standardized format ensures seamless integration with centralized correlation services.

---

## 🏗️ Architecture

```
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
```

The module intentionally avoids risk aggregation to preserve forensic clarity.

---

## 📁 Supported File Types

* .txt
* .ps1
* .js
* .vbs
* .exe
* .bin
* .zip

📏 Maximum file size: **10MB**

---

## ⚡ Performance

* Average scan time (small files): **~0.05 – 0.2 seconds**
* Dependent on file size and YARA rule count

---

## ⚠️ Limitations

This project is intentionally constrained to:

* Static analysis only
* Signature-based detection
* Heuristic string matching
* Entropy-based suspicion

It does **not** detect:

* Polymorphic malware without signatures
* Advanced obfuscation beyond entropy detection
* Zero-day exploits
* Memory-only malware
* Runtime behavioral anomalies

It should be considered a **detection signal generator**, not a complete antivirus solution.

---

## 🧠 Security Philosophy

> Detection modules should emit evidence, not verdicts.

By separating detection from correlation:

* Evidence remains unbiased
* Risk aggregation becomes centralized
* Multi-signal intelligence becomes possible

This approach aligns with modern defensive security architecture.

---

## 🚀 Deployment

Designed for:

* Backend → Render (persistent Python service)
* Frontend → Same service or static hosting

Start command:

```
uvicorn api.main:app --host 0.0.0.0 --port $PORT
```

---

## 🔮 Future Enhancements

* Expanded YARA rule sets
* Integration with phishing detection module
* Session-based entity tracking
* Cross-module correlation engine
* Dashboard visualization
* Automated hash intelligence lookup

---

## 👨‍💻 Author

**Rugved Suryawanshi**
Computer Science Engineering

---
## License
© 2025 Rugved Suryawanshi.  
This project is licensed under the MIT License.  
Attribution is required in all copies or substantial portions of the Software.
