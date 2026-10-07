"""ACS enforcement boundary for AUT-002."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
from typing import Mapping

import yaml
from agent_control_specification import (
    AgentControl,
    ApprovalResolution,
    ApprovalResolver,
    Decision,
    InterventionPoint,
    InterventionPointResult,
    JsonValue,
)

_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "policy" / "acs_manifest.yaml"
_MANDATE_PATH = _MANIFEST_PATH.with_name("mandate.json")
DEFAULT_APPROVAL_TTL = timedelta(minutes=5)


class IrreversibleActionPolicyDispatcher:
    """Every invocation of the protected tool requires human approval."""

    def evaluate(self, invocation: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        if _MANDATE_PATH.exists():
            mandate = load_mandate()
            policy_input = invocation.get("input", {})
            snapshot = policy_input.get("snapshot", {}) if isinstance(policy_input, dict) else {}
            call = snapshot.get("tool_call")
            if not isinstance(call, dict):
                return {"decision": Decision.DENY.value, "reason": "missing_tool_call"}
            action = next((item for item in mandate["actions"] if item["toolName"] == call.get("name")), None)
            args = call.get("args", {})
            if action is None or not isinstance(args, dict) or set(args) != {"record_id"} or args.get("record_id") not in action["targets"]:
                return {"decision": Decision.DENY.value, "reason": "outside_mandate_scope"}
            decisions = {"allowed": Decision.ALLOW, "prohibited": Decision.DENY, "approval_required": Decision.ESCALATE}
            return {"decision": decisions[action["disposition"]].value, "reason": "reviewed_mandate_" + action["disposition"]}
        return {
            "decision": Decision.ESCALATE.value,
            "reason": "aut_002_irreversible_action_requires_approval",
            "message": "An Ops Manager must approve this exact action before execution.",
        }


@lru_cache(maxsize=1)
def load_mandate() -> dict:
    raw = _MANDATE_PATH.read_bytes()
    expected = os.environ.get("AUT002_MANDATE_SHA256")
    if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("mandate_hash_mismatch")
    data = json.loads(raw)
    if data.get("defaultDecision") != "deny" or data.get("mandateVersion") != "1.0.0":
        raise ValueError("unsupported_mandate")
    return data


@lru_cache(maxsize=1)
def get_control() -> AgentControl:
    if os.environ.get("AZURE_AI_PROJECT_ENDPOINT"):
        if not os.environ.get("AUT002_MANDATE_SHA256"):
            raise ValueError("mandatory_mandate_binding_missing")
        load_mandate()
    manifest = yaml.safe_load(_MANIFEST_PATH.read_text(encoding="utf-8"))
    return AgentControl.from_native(
        manifest,
        policy_dispatcher=IrreversibleActionPolicyDispatcher(),
    )


@dataclass
class ApprovalTicket:
    """Single-use approval evidence bound to ACS's action identity."""

    approved: bool
    issued_at: datetime
    ttl: timedelta = DEFAULT_APPROVAL_TTL
    expected_action_identity: str | None = None
    _action_identity: str | None = field(default=None, init=False, repr=False)
    _started: bool = field(default=False, init=False, repr=False)
    _completed: bool = field(default=False, init=False, repr=False)

    def resolver(self) -> ApprovalResolver:
        def _resolve(
            point: InterventionPoint,
            result: InterventionPointResult,
        ) -> ApprovalResolution:
            now = datetime.now(UTC)
            if (
                self._completed
                or not self.approved
                or self.issued_at > now
                or now - self.issued_at >= self.ttl
            ):
                return ApprovalResolution.deny()

            if point == InterventionPoint.PRE_TOOL_CALL:
                if self._started or (
                    self.expected_action_identity is not None
                    and self.expected_action_identity != result.action_identity
                ):
                    return ApprovalResolution.deny()
                self._action_identity = result.action_identity
                self._started = True

            if point == InterventionPoint.POST_TOOL_CALL:
                if self._action_identity is None:
                    return ApprovalResolution.deny()
                self._completed = True
            return ApprovalResolution.allow(result.action_identity)

        return _resolve


def denied_resolver(
    _point: InterventionPoint,
    _result: InterventionPointResult,
) -> ApprovalResolution:
    """Explicit resolver used when no human approval exists."""

    return ApprovalResolution.deny()


def resolver_for(ticket: ApprovalTicket | None) -> ApprovalResolver:
    if ticket is None:
        return denied_resolver
    return ticket.resolver()