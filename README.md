# NEXAF — Next-Gen Explainable AI Firewall

NEXAF is a simple local real-time browser firewall demo. It analyzes browser URLs, explains every block, records telemetry in SQLite, activates browser protection rules, and temporarily drops traffic from sources that flood the analyzer.

## Components

- **Backend:** makes the security decision, normalizes payloads, stores events, creates protection rules, exports CSV logs, and performs self-healing rate protection.
- **Dashboard (`frontend/index.html`):** the reviewer console. It shows live counters, reasons, actions, active rules, self-healing state, filters, and downloadable logs.
- **Chrome extension:** the enforcement and user-facing browser layer. The service worker analyzes navigation and installs Chrome dynamic rules; the popup shows the current tab's decision, explanation, risk, AI provider, and installed rule count.
- **Blocked page:** Chrome displays `blocked.html` because a redirect is the safe way for a Manifest V3 extension to replace a navigation after a dynamic protection rule matches. It now shows the exact reason, threat, action, risk, and original URL instead of a generic message.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open `frontend/index.html`. Login: `admin` / `admin`. Load the extension from `frontend/` at `chrome://extensions` → Developer mode → Load unpacked.

## Reviewer simulation

Use either method while the dashboard is open:

```bash
python backend/simulate.py
```

or open `frontend/simulator.html` and click **Run complete reviewer demo**. It sends real XSS, SQL injection, path traversal, command injection, and request-flood traffic through the backend. The flood threshold is crossed, NEXAF records `TEMPORARY_BLOCK`, displays an active source block, waits for expiry, then sends a recovery probe so `RECOVERY` appears in the self-healing event stream.

For a quicker demo, start the backend with:

```bash
DEMO_MODE=1 uvicorn backend.main:app --reload
```

That uses 8 requests / 10 seconds / 15 seconds for the temporary block. Normal defaults remain 50 / 10 seconds / 30 seconds.

## AI explanation provider

Currently, unless configured otherwise, NEXAF uses **local deterministic rules** (`ai_provider: local-rules`) for immediate and safe explanations. The configured Manus model catalog does not contain Qwen, and no external AI key was available during testing.

The best free/private option for this college demo is **Ollama running locally**, with `qwen2.5:3b` or `llama3.2:3b`:

```bash
ollama pull qwen2.5:3b
export AI_PROVIDER=ollama
export OLLAMA_MODEL=qwen2.5:3b
uvicorn backend.main:app --reload
```

Ollama is free after installation, keeps URLs on the laptop, and has low latency. NEXAF still makes the block decision locally; Ollama only improves the plain-English explanation. If Ollama is offline or slow, the local explanation is used automatically.

Optional cloud providers are supported through environment variables: `AI_PROVIDER=grok` with `GROK_API_KEY`, or `AI_PROVIDER=qwen` with `QWEN_API_BASE`, `QWEN_API_KEY`, and `QWEN_MODEL`. Do not make an AI service the only protection mechanism.

## Tests

```bash
pytest -q backend/test_main.py
python -m py_compile backend/main.py backend/simulate.py
node --check frontend/popup.js
node --check frontend/service-worker.js
```

This is an application-layer browser firewall for a college demonstration, not a kernel-level packet filter or production WAF.
