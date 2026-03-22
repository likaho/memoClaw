from datetime import datetime, timezone
from typing import List
from pydantic import BaseModel

class AuditEntry(BaseModel):
    timestamp: str
    agent_id: str
    owner: str
    action: str
    resource: str
    decision: str
    reason: str
    token_id: str

_log: List[AuditEntry] = []

def record(entry: AuditEntry):
    _log.append(entry)

def get_log() -> List[AuditEntry]:
    return list(reversed(_log))

def now() -> str:
    return datetime.now(timezone.utc).isoformat()
