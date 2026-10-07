"""Minimized evidence for AUT-002 decisions."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def write_evidence(
    destination: Path,
    *,
    decision: str,
    tool_name: str,
    action_identity: str | None,
    executed: bool,
    verified: bool,
    reason: str,
    correlation_id: str,
    source: dict[str, object] | None = None,
) -> dict[str, Any]:
    evidence = {
        "control_id": "AUT-002",
        "policy_version": "1.0",
        "timestamp": datetime.now(UTC).isoformat(),
        "correlation_id": correlation_id,
        "tool_name": tool_name,
        "action_reference": hashlib.sha256(tool_name.encode()).hexdigest(),
        "action_identity": action_identity,
        "decision": decision,
        "executed": executed,
        "verified": verified,
        "reason": reason,
        "accountable_role": "Ops Manager",
    }
    if source is not None:
        allowed = {"agent_name", "agent_version", "response_id", "call_id", "approver_reference", "approval_authenticated", "mandate_sha256"}
        if set(source) - allowed:
            raise ValueError("unsupported_evidence_source_fields")
        evidence["source"] = source
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence