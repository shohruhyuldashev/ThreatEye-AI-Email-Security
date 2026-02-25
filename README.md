# ThreatEye – AI Powered Email Security Platform

ThreatEye is a real-time phishing detection platform that combines:

- Docker Mailserver (Postfix + Dovecot)
- Async IMAP IDLE Monitoring
- LLM-based Analysis (Ollama / Phi-3)
- Rule-based + Hybrid Threat Detection
- Automatic IMAP Quarantine
- GoPhish Simulation Integration

---

## 🏗 Architecture

Internet → Postfix (SMTP)
→ Dovecot (IMAP)
→ Async Email Watcher (IDLE)
→ AI Detection Engine
→ Auto Quarantine (IMAP Folder Move)
→ Dashboard (Frontend + API)

---

## 🔥 Features

- Real-time email interception
- Async IMAP IDLE monitoring
- Typosquatting detection
- URL threat scoring
- LLM reasoning engine
- Automatic quarantine folder move
- Docker-based production-style setup

---

## 🐳 Run Locally

```bash
docker compose up --build
````

Frontend: [http://localhost:3000](http://localhost:3000)
Backend API: [http://localhost:8000](http://localhost:8000)

---

## ⚙ Tech Stack

* FastAPI
* Docker
* Dovecot
* Postfix
* Ollama (Phi-3)
* SQLite
* GoPhish

---

## 📌 Project Goal

Build a realistic enterprise-style email security lab environment with AI-driven phishing detection and automated quarantine workflows.

````

