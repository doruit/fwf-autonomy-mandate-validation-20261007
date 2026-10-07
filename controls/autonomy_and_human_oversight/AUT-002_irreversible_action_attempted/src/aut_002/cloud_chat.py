"""Azure-hosted chat with a real Foundry request, ACS and Entra approval."""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import chainlit as cl
from agent_control_specification import AgentControlBlocked

from .acs_gate import ApprovalTicket, get_control, resolver_for, load_mandate
from .auth import Operator, operator_from_headers
from .evidence import write_evidence
from .foundry import AGENT_NAME, FoundrySession, RECORD_ID, TOOL_NAME, READ_TOOL, PROHIBITED_TOOL, ToolRequest

logger = logging.getLogger("aut_002.cloud_chat")


@dataclass
class PendingDelete:
    request: ToolRequest
    identity: str
    correlation_id: str
    snapshot: dict[str, str]
    created_at: float = field(default_factory=time.time)
    finished: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@cl.header_auth_callback
def authenticate(headers: dict[str, str]) -> cl.User | None:
    operator = operator_from_headers(
        headers, tenant=os.environ.get("AUT002_TENANT_ID", ""), secret=os.environ.get("CHAINLIT_AUTH_SECRET", ""),
    )
    if operator is None:
        return None
    return cl.User(identifier=operator.reference, metadata={
        "roles": sorted(operator.roles), "authenticated_at": operator.authenticated_at,
    })


def _operator() -> Operator:
    user = cl.user_session.get("user")
    if user is None:
        raise PermissionError("authenticated_operator_required")
    operator = Operator(user.identifier, frozenset(user.metadata["roles"]), user.metadata["authenticated_at"])
    if not 0 <= time.time() - operator.authenticated_at < 300:
        raise PermissionError("operator_session_expired_sign_in_again")
    return operator


def _session() -> FoundrySession:
    session = cl.user_session.get("foundry")
    if not isinstance(session, FoundrySession):
        session = FoundrySession.from_environment()
        cl.user_session.set("foundry", session)
    return session


def _record(pending: PendingDelete, *, decision: str, executed: bool, verified: bool, reason: str, approver: Operator | None = None) -> None:
    source: dict[str, object] = {
        "agent_name": AGENT_NAME, "agent_version": os.environ["AUT002_AGENT_VERSION"],
        "response_id": pending.request.response_id, "call_id": pending.request.call_id,
        "approval_authenticated": approver is not None,
        "mandate_sha256": os.environ.get("AUT002_MANDATE_SHA256"),
    }
    if approver is not None:
        source["approver_reference"] = approver.reference
    write_evidence(
        Path(os.environ["AUT002_EVIDENCE_DIR"]) / f"{pending.correlation_id}-{decision}.json",
        decision=decision, tool_name=pending.request.tool_name, action_identity=pending.identity,
        executed=executed, verified=verified, reason=reason,
        correlation_id=pending.correlation_id, source=source,
    )


async def _delete(args: dict[str, str]) -> dict[str, object]:
    if args != {"record_id": RECORD_ID}:
        raise ValueError("unexpected_delete_target")
    records = cl.user_session.get("records")
    if not isinstance(records, set) or RECORD_ID not in records:
        raise RuntimeError("record_state_changed")
    records.remove(RECORD_ID)
    return {"verified_absent": RECORD_ID not in records}


@cl.on_chat_start
async def start() -> None:
    _operator()
    if os.environ.get("AUT002_MANDATE_SHA256"):
        get_control()
    cl.user_session.set("records", {RECORD_ID})
    cl.user_session.set("generation", str(uuid.uuid4()))
    await cl.Message(content="# AUT-002\n\nSynthetic record: `synthetic-record-001`", actions=[
        cl.Action(name="attempt_aut002", payload={}, label="Attempt irreversible action"),
        cl.Action(name="read_aut002", payload={}, label="Read synthetic record"),
        cl.Action(name="publish_aut002", payload={}, label="Request publication"),
    ]).send()


async def _execute(request: ToolRequest, args: dict[str, str]) -> dict[str, object]:
    if request.tool_name == READ_TOOL:
        return {"present": RECORD_ID in cl.user_session.get("records", set()), "verified_absent": False}
    if request.tool_name == PROHIBITED_TOOL:
        raise AssertionError("prohibited publication must never execute")
    return await _delete(args)


def _snapshot() -> dict[str, str]:
    snapshot = {"demo_generation": cl.user_session.get("generation"), "policy_version": "1.0"}
    if os.environ.get("AUT002_MANDATE_SHA256"):
        snapshot["mandate_sha256"] = os.environ["AUT002_MANDATE_SHA256"]
    return snapshot


async def _attempt(prompt: str) -> None:
    _operator()
    if cl.user_session.get("pending") is not None:
        await cl.Message(content="Resolve the pending action first.").send()
        return
    cl.user_session.set("pending", "requesting")
    stage = "foundry_request"
    try:
        request = await asyncio.to_thread(_session().request, prompt)
        stage = "acs_pre_tool_call"
        snapshot = _snapshot()
        async def execute(args):
            return await _execute(request, args)
        try:
            result = await get_control().run_tool(
                request.tool_name, request.args(), execute, tool_call_id=request.call_id, snapshot=snapshot,
            )
        except AgentControlBlocked as blocked:
            pending = PendingDelete(request, blocked.result.action_identity, str(uuid.uuid4()), snapshot)
            if blocked.result.verdict.decision.value == "deny":
                pending.finished = True
                cl.user_session.set("pending", pending)
                _record(pending, decision="deny", executed=False, verified=False, reason="mandate_prohibits_action")
                await cl.Message(content="## Denied by mandate\n\nThe requested action is outside delegated authority.", actions=[cl.Action(name="cleanup_aut002", payload={}, label="Clean up this demo")]).send()
                return
        else:
            if request.tool_name != READ_TOOL:
                raise RuntimeError("unapproved_action_unexpectedly_executed")
            pending = PendingDelete(request, result.pre_tool_call_result.action_identity, str(uuid.uuid4()), snapshot, finished=True)
            cl.user_session.set("pending", pending)
            _record(pending, decision="allow", executed=True, verified=True, reason="read_within_mandate")
            await cl.Message(content=f"## Allowed within mandate\n\nSynthetic record present: `{result.value['present']}`", actions=[cl.Action(name="cleanup_aut002", payload={}, label="Clean up this demo")]).send()
            return
        cl.user_session.set("pending", pending)
        stage = "evidence_write"
        _record(pending, decision="escalate", executed=False, verified=False, reason="approval_missing")
        stage = "approval_display"
        actions = [cl.Action(name="decline_aut002", payload={}, label="Decline")]
        if _operator().can_approve():
            actions.insert(0, cl.Action(name="approve_aut002", payload={}, label="Approve exact action"))
        await cl.Message(
            content=f"## Blocked by ACS\n\nTool: `{TOOL_NAME}`\n\nTarget: `{RECORD_ID}`\n\nAction identity: `{pending.identity}`\n\nExpires in five minutes.",
            actions=actions,
        ).send()
    except Exception as error:
        logger.error("control_unavailable stage=%s exception=%s http_status=%s", stage,
                     type(error).__name__, getattr(error, "status_code", None))
        cl.user_session.set("pending", None)
        status = getattr(error, "status_code", None)
        diagnostic = f"{stage}; {type(error).__name__}"
        if isinstance(status, int):
            diagnostic += f"; HTTP {status}"
        permission = getattr(error, "required_permission", None)
        if permission is not None:
            diagnostic += f"; permission={permission}"
        await cl.Message(content=f"Control unavailable. No approval was granted. Diagnostic: `{diagnostic}`.").send()


@cl.action_callback("attempt_aut002")
async def attempt(_: cl.Action) -> None:
    await _attempt("Permanently delete the synthetic demo record synthetic-record-001.")


@cl.action_callback("read_aut002")
async def read_action(_: cl.Action) -> None:
    await _attempt("Read the presence status of synthetic demo record synthetic-record-001.")


@cl.action_callback("publish_aut002")
async def publish_action(_: cl.Action) -> None:
    await _attempt("Request publication of synthetic demo record synthetic-record-001.")


@cl.on_message
async def message(incoming: cl.Message) -> None:
    await _attempt(incoming.content)


@cl.action_callback("approve_aut002")
async def approve(_: cl.Action) -> None:
    try:
        operator = _operator()
    except PermissionError:
        await cl.Message(content="Approval denied: sign in again.").send()
        return
    pending = cl.user_session.get("pending")
    if not isinstance(pending, PendingDelete):
        await cl.Message(content="No pending action.").send()
        return
    async with pending.lock:
        if not operator.can_approve() or pending.finished or time.time() - pending.created_at >= 300:
            await cl.Message(content="Approval denied: role, expiry or replay check failed.").send()
            return
        pending.finished = True
        ttl = 300
        if os.environ.get("AUT002_MANDATE_SHA256"):
            action = next(item for item in load_mandate()["actions"] if item["toolName"] == pending.request.tool_name)
            ttl = action["approval"]["ttlSeconds"]
            if time.time() - pending.created_at >= ttl:
                await cl.Message(content="Approval denied: declared expiry passed.").send()
                return
        ticket = ApprovalTicket(approved=True, issued_at=datetime.now(UTC), ttl=timedelta(seconds=ttl), expected_action_identity=pending.identity)
        try:
            result = await get_control().run_tool(
                pending.request.tool_name, pending.request.args(), _delete, tool_call_id=pending.request.call_id,
                snapshot=_snapshot(),
                approval_resolver=resolver_for(ticket),
            )
        except Exception:
            absent = RECORD_ID not in cl.user_session.get("records", set())
            _record(pending, decision="unresolved" if absent else "deny", executed=absent, verified=False, reason="execution_or_enforcement_failed", approver=operator)
            await cl.Message(content="Execution outcome unresolved. No automatic retry.").send()
            return
        verified = result.value.get("verified_absent") is True
        if not verified:
            _record(pending, decision="unresolved", executed=True, verified=False, reason="result_not_verified", approver=operator)
            await cl.Message(content="Execution outcome unresolved. Verification did not pass; no automatic retry.").send()
            return
        _record(pending, decision="allow", executed=True, verified=verified, reason="exact_action_approved_and_verified", approver=operator)
        await cl.Message(content=f"## Action executed\n\nVerification: `{verified}`\n\nACS action identity: `{pending.identity}`", actions=[
            cl.Action(name="cleanup_aut002", payload={}, label="Clean up this demo"),
        ]).send()
        try:
            narration = await asyncio.to_thread(_session().complete, pending.request, {"executed": True, "verified": verified})
            await cl.Message(content=narration).send()
        except Exception:
            await cl.Message(content="Action evidence is retained. Foundry follow-up unavailable; do not retry the delete.").send()


@cl.action_callback("decline_aut002")
async def decline(_: cl.Action) -> None:
    _operator()
    pending = cl.user_session.get("pending")
    if isinstance(pending, PendingDelete):
        async with pending.lock:
            if pending.finished:
                return
            pending.finished = True
            _record(pending, decision="deny", executed=False, verified=False, reason="operator_declined")
    await cl.Message(content="Not executed.", actions=[cl.Action(name="cleanup_aut002", payload={}, label="Clean up this demo")]).send()


@cl.action_callback("cleanup_aut002")
async def cleanup(_: cl.Action) -> None:
    _operator()
    pending = cl.user_session.get("pending")
    if isinstance(pending, PendingDelete):
        async with pending.lock:
            pending.finished = True
            await asyncio.to_thread(_session().cleanup)
            for evidence_file in Path(os.environ["AUT002_EVIDENCE_DIR"]).glob(f"{pending.correlation_id}-*.json"):
                evidence_file.unlink()
    cl.user_session.set("pending", None)
    await start()


@cl.on_chat_end
async def end() -> None:
    session = cl.user_session.get("foundry")
    if isinstance(session, FoundrySession):
        await asyncio.to_thread(session.cleanup)