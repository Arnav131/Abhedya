# 🔐 Abhedya – Software Requirements Specification  
**Version:** 3.0 *(Hackathon Master Blueprint)*  
**Hardware Target:** NVIDIA RTX 5070 (CUDA Enabled)

---

## 1. Introduction

### 1.1 Purpose
Abhedya is an intelligent, zero-knowledge secrets manager designed for both standard users and developers. It securely stores credentials while utilizing **on-device, GPU-accelerated AI** to proactively defend against breaches and audit user behavior — without exposing plaintext data to external APIs.

---

### 1.2 Scope
This specification outlines the three phases of a **24-hour hackathon build**:

- **Phase 1:** Zero-Knowledge Core  
  *(React + Web Crypto API + Django)*  
- **Phase 2:** Active Hash Auditing  
  *(Custom Python Heuristic Engine)*  
- **Phase 3:** Local AI Defense  
  *(GPU-accelerated PyTorch + Local LLM Honeypots)*  

---

## 2. System Architecture

### 🔐 Zero-Knowledge Pipeline
- All **AES-256-GCM encryption** occurs entirely in the **React client (browser memory)**  
- Django acts as **"dumb storage"**, storing only ciphertext  
- No plaintext data ever leaves the client  

---

### 🤖 Local AI Edge
- AI models run **entirely on localhost**
- Powered by **RTX 5070 CUDA cores**
- Includes:
  - PyTorch RNN
  - Local LLMs (Llama / Mistral via Ollama)

---

## 3. Folder Structure

```plaintext
abhedya_root/
├── README.md
├── frontend/                  # React UI & Client-Side Cryptography
│   ├── src/
│   │   ├── components/        # UI (Dashboard, Auth, Audit Badges)
│   │   ├── utils/
│   │   │   └── vaultCrypto.js # PBKDF2 + AES-GCM logic
│   │   ├── App.js
│   │   └── index.js
│   └── package.json
│
└── backend/                   # Django Backend & AI Engines
    ├── manage.py
    ├── abhedya_api/       # Core settings & routing
    ├── vault/                 # Main App
    │   ├── models.py          # VaultEntry (Ciphertext + Metadata)
    │   ├── views.py           # API Endpoints
    │   └── urls.py
    │
    └── ai_engine/             # Threat Detection Modules
        ├── auditor.py         # Heuristic analysis
        ├── honeypot_llm.py    # Local LLM integration
        └── pytorch_model.py   # RNN password predictor