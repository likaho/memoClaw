# Agentic IAM Demo

## Start in 2 commands

```bash
# Terminal 1 — backend
cd agentic-iam-demo/backend
pip install -r requirements.txt
uvicorn main:app --reload

# Terminal 2 — frontend (no build needed)
# Just open frontend/index.html in your browser
```

## Demo script (5 min)

1. **Step 1** — Register agent `ticket-buyer` owned by `alice`
2. **Step 2** — Issue delegated token (scopes: `buy:ticket, read:repo`)
3. **Step 3** — Request `buy:ticket` → show **ALLOW** + token claims (sub/act)
4. **Step 3** — Change action to `delete:repo` → show **DENY** (high-risk, CIBA escalation)
5. **Step 3** — Switch owner to `bob`, re-register, try `buy:ticket` → show **DENY** (owner ceiling)
6. **Step 4** — Show audit log with full sub/act attribution
7. **Bonus** — De-provision agent, show final audit entry
