# AI Agent Security Gateway
### IT8599 — University Project

A cybersecurity simulation tool that mimics a network security gateway
protecting a company's **public-facing AI agent** from prompt injection attacks
by external website visitors.

---

## Project Structure

```
IT8599 project/
├── app.py          # Streamlit dashboard (main entry point)
├── engine.py       # Inspection & decision engine (rule-based)
├── database.py     # SQLite logging layer
├── requirements.txt
└── gateway_logs.db # Auto-created on first run
```

## Setup & Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the dashboard
streamlit run app.py
```

Then open http://localhost:8501 in your browser.

---

## How It Works

```
External Website Visitor
      │
      ▼
 [Gateway Input]  ──→  Tokenize + Normalize
      │
      ▼
 [Inspection Engine]
   - 18 HIGH-risk regex patterns  (injection, data probing, jailbreak)
   - 14 MEDIUM-risk patterns      (role-play, social engineering)
   - LOW = no match
      │
      ▼
 [Risk Classification]
   HIGH   = score 92  →  BLOCK  (never reaches AI agent)
   MEDIUM = score 55  →  FLAG   (held for security review)
   LOW    = score 15  →  ALLOW  (forwarded to AI agent)
      │
      ▼
 [SQLite Logger]  →  full audit trail persisted
      │
      ▼
 [Security Dashboard]  →  metrics, live log, admin table
