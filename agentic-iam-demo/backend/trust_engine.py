"""
Fake Trust Engine — evaluates agent action requests against simple policies.
In a real system this would be a PDP querying a policy store.
"""

from typing import Tuple

# Simulated policy store: owner -> allowed scopes
OWNER_POLICIES = {
    "alice": ["buy:ticket", "read:repo", "create:issue"],
    "bob":   ["read:repo", "create:issue"],
    "carol": ["buy:ticket"],
}

# Actions that always require explicit human approval (CIBA simulation)
HIGH_RISK_ACTIONS = {"delete:repo", "transfer:funds", "deploy:production"}

def evaluate(owner: str, agent_id: str, action: str, resource: str) -> Tuple[str, str]:
    """
    Returns (decision, reason) where decision is 'ALLOW' or 'DENY'.
    """
    owner_scopes = OWNER_POLICIES.get(owner, [])

    # Rule 1: owner ceiling — agent cannot exceed owner's permissions
    if action not in owner_scopes:
        return (
            "DENY",
            f"Owner '{owner}' does not have '{action}' in their entitlements. "
            "Agent cannot exceed owner permissions (owner ceiling policy)."
        )

    # Rule 2: high-risk actions are blocked pending human approval
    if action in HIGH_RISK_ACTIONS:
        return (
            "DENY",
            f"Action '{action}' is high-risk and requires explicit human approval via CIBA. "
            "Escalation initiated — agent halted pending out-of-band authorization."
        )

    # Rule 3: allow
    return (
        "ALLOW",
        f"Agent '{agent_id}' acting on behalf of '{owner}' is authorized to perform "
        f"'{action}' on '{resource}'. Scope within owner entitlements."
    )
