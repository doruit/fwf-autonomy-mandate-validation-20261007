"""Runnable local AUT-002 demonstration with synthetic records."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from agent_control_specification import AgentControlBlocked

from .acs_gate import ApprovalTicket, get_control, resolver_for
from .evidence import write_evidence

TOOL_NAME = "permanently_delete_demo_record"


class SyntheticRecordStore:
    def __init__(self) -> None:
        self.records = {"synthetic-record-001"}

    async def permanently_delete(self, args: dict[str, str]) -> dict[str, object]:
        record_id = args["record_id"]
        self.records.remove(record_id)
        return {"record_id": record_id, "verified_absent": record_id not in self.records}


async def run_demo(destination: Path) -> list[dict[str, object]]:
    store = SyntheticRecordStore()
    control = get_control()
    correlation_id = str(uuid.uuid4())
    args = {"record_id": "synthetic-record-001"}
    evidence: list[dict[str, object]] = []

    async def execute(action_args: dict[str, str]) -> dict[str, object]:
        return await store.permanently_delete(action_args)

    try:
        await control.run_tool(TOOL_NAME, args, execute)
    except AgentControlBlocked:
        evidence.append(
            write_evidence(
                destination / "blocked.json",
                decision="escalate",
                tool_name=TOOL_NAME,
                action_identity=None,
                executed=False,
                verified=False,
                reason="approval_missing",
                correlation_id=correlation_id,
            )
        )

    ticket = ApprovalTicket(approved=True, issued_at=datetime.now(UTC))
    result = await control.run_tool(
        TOOL_NAME,
        args,
        execute,
        approval_resolver=resolver_for(ticket),
    )
    evidence.append(
        write_evidence(
            destination / "approved.json",
            decision="allow",
            tool_name=TOOL_NAME,
            action_identity=result.pre_tool_call_result.action_identity,
            executed=True,
            verified=bool(result.value["verified_absent"]),
            reason="exact_action_approved_and_verified",
            correlation_id=correlation_id,
        )
    )
    return evidence


def main() -> None:
    destination = Path("evidence")
    destination.mkdir(exist_ok=True)
    evidence = asyncio.run(run_demo(destination))
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()