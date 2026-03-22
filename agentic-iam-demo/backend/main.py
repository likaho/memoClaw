import uuid
from typing import Dict
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from trust_engine import evaluate
from audit import AuditEntry, record, get_log, now

app = FastAPI(title="Agentic IAM Demo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- In-memory stores ---
agents: Dict[str, dict] = {}   # agent_id -> agent record
tokens: Dict[str, dict] = {}   # token_id -> token record

# --- Models ---
class CreateAgentRequest(BaseModel):
    name: str
    owner: str          # human owner username
    model: str = "gpt-4o"
    version: str = "1.0"

class DelegateRequest(BaseModel):
    agent_id: str
    scopes: list[str]   # requested scopes

class ActionRequest(BaseModel):
    token_id: str
    action: str         # e.g. "buy:ticket", "delete:repo"
    resource: str       # e.g. "flight/NYC-LON", "github/my-repo"

# --- Routes ---

@app.post("/agents", summary="Register a new agent")
def create_agent(req: CreateAgentRequest):
    agent_id = f"agent:{req.name.lower().replace(' ', '-')}:{req.version}"
    if agent_id in agents:
        raise HTTPException(400, "Agent already exists")

    agents[agent_id] = {
        "agent_id": agent_id,
        "name": req.name,
        "owner": req.owner,
        "model": req.model,
        "version": req.version,
        "status": "active",
        "created_at": now(),
    }
    record(AuditEntry(
        timestamp=now(),
        agent_id=agent_id,
        owner=req.owner,
        action="agent:provisioned",
        resource="agent-registry",
        decision="ALLOW",
        reason=f"Agent '{agent_id}' registered and bound to owner '{req.owner}'.",
        token_id="n/a",
    ))
    return agents[agent_id]


@app.get("/agents", summary="List all agents")
def list_agents():
    return list(agents.values())


@app.post("/delegate", summary="Issue a delegated token to an agent")
def delegate(req: DelegateRequest):
    if req.agent_id not in agents:
        raise HTTPException(404, "Agent not found")

    agent = agents[req.agent_id]
    token_id = f"tok_{uuid.uuid4().hex[:10]}"

    tokens[token_id] = {
        "token_id": token_id,
        "agent_id": req.agent_id,
        "owner": agent["owner"],
        "scopes": req.scopes,
        # JWT-style claims for the demo
        "claims": {
            "sub": agent["owner"],          # human principal
            "act": req.agent_id,            # acting agent (RFC 8693)
            "scope": " ".join(req.scopes),
            "ttl": "900s",
        },
        "issued_at": now(),
    }
    record(AuditEntry(
        timestamp=now(),
        agent_id=req.agent_id,
        owner=agent["owner"],
        action="token:issued",
        resource="token-service",
        decision="ALLOW",
        reason=f"Delegated token issued. sub={agent['owner']}, act={req.agent_id}, scopes={req.scopes}",
        token_id=token_id,
    ))
    return tokens[token_id]


@app.post("/action", summary="Agent requests to perform an action")
def perform_action(req: ActionRequest):
    if req.token_id not in tokens:
        raise HTTPException(404, "Token not found — agent must obtain delegation first")

    token = tokens[req.token_id]
    agent_id = token["agent_id"]
    owner = token["owner"]

    decision, reason = evaluate(owner, agent_id, req.action, req.resource)

    entry = AuditEntry(
        timestamp=now(),
        agent_id=agent_id,
        owner=owner,
        action=req.action,
        resource=req.resource,
        decision=decision,
        reason=reason,
        token_id=req.token_id,
    )
    record(entry)

    return {
        "decision": decision,
        "reason": reason,
        "audit": entry,
        "token_claims": token["claims"],
    }


@app.get("/audit", summary="View audit log")
def audit_log():
    return get_log()


@app.delete("/agents/{agent_id}", summary="De-provision an agent")
def deprovision_agent(agent_id: str):
    if agent_id not in agents:
        raise HTTPException(404, "Agent not found")

    agent = agents.pop(agent_id)
    # Invalidate all tokens for this agent
    revoked = [tid for tid, t in list(tokens.items()) if t["agent_id"] == agent_id]
    for tid in revoked:
        tokens.pop(tid)

    record(AuditEntry(
        timestamp=now(),
        agent_id=agent_id,
        owner=agent["owner"],
        action="agent:deprovisioned",
        resource="agent-registry",
        decision="ALLOW",
        reason=f"Agent '{agent_id}' de-provisioned. {len(revoked)} token(s) revoked. Identity purged.",
        token_id="n/a",
    ))
    return {"status": "deprovisioned", "tokens_revoked": len(revoked)}
