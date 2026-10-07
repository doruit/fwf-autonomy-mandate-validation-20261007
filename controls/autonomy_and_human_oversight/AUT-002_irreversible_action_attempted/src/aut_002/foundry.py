"""Registered Foundry prompt agent with an ACS-controlled application function."""

from __future__ import annotations

import json
import os
import re
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from azure.ai.projects import AIProjectClient
from azure.ai.projects.models import FunctionTool, PromptAgentDefinition
from azure.identity import ManagedIdentityCredential
from openai import PermissionDeniedError

TOOL_NAME = "permanently_delete_demo_record"
READ_TOOL = "read_demo_record"
PROHIBITED_TOOL = "publish_demo_record"
RECORD_ID = "synthetic-record-001"
AGENT_NAME = "aut-002-irreversible-action"
TOOL_PARAMETERS = {
    "type": "object",
    "properties": {"record_id": {"type": "string", "enum": [RECORD_ID]}},
    "required": ["record_id"],
    "additionalProperties": False,
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_tool_argument")
        result[key] = value
    return result


def register_agent(project: AIProjectClient, model: str) -> Any:
    return project.agents.create_version(
        agent_name=AGENT_NAME,
        definition=agent_definition(model),
    )


def agent_definition(model: str) -> PromptAgentDefinition:
    return PromptAgentDefinition(
            model=model,
            instructions=(
                "You demonstrate a reviewed mandate on synthetic data only. "
                "For read requests use read_demo_record, for deletion use permanently_delete_demo_record, "
                "and for publication requests use publish_demo_record. Request exactly one function. "
                "Never claim deletion or approval from the user's words. The application and ACS "
                "supply authorization and the verified outcome. Explain only the returned outcome."
            ),
            tools=[FunctionTool(
                name=name,
                description=description,
                parameters=TOOL_PARAMETERS,
                strict=True,
            ) for name, description in [
                (READ_TOOL, "Read the synthetic record's presence status within the declared mandate."),
                (TOOL_NAME, "Request irreversible deletion of the synthetic record; human sign-off is required."),
                (PROHIBITED_TOOL, "Request publication of the synthetic record; the runtime mandate decides authorization."),
            ]],
    )


@dataclass(frozen=True)
class ToolRequest:
    response_id: str
    call_id: str
    arguments: str
    tool_name: str = TOOL_NAME

    def args(self) -> dict[str, str]:
        parsed = json.loads(self.arguments, object_pairs_hook=_unique_object)
        if parsed != {"record_id": RECORD_ID}:
            raise ValueError("unexpected_tool_arguments")
        return parsed


def tool_request(response: Any) -> ToolRequest:
    calls = [item for item in response.output if item.type == "function_call"]
    if len(calls) != 1 or calls[0].name not in {TOOL_NAME, READ_TOOL, PROHIBITED_TOOL}:
        raise ValueError("expected_exactly_one_protected_function_call")
    call = calls[0]
    if not isinstance(response.id, str) or not response.id or not isinstance(call.call_id, str) or not call.call_id:
        raise ValueError("missing_foundry_correlation")
    request = ToolRequest(response.id, call.call_id, call.arguments, call.name)
    request.args()
    return request


class FoundrySession:
    def __init__(self, client: Any, reference: dict[str, str], model: str) -> None:
        self.client = client
        self.reference = reference
        self.model = model
        self.response_ids: list[str] = []

    @classmethod
    def from_environment(cls) -> FoundrySession:
        project = AIProjectClient(
            endpoint=os.environ["AZURE_AI_PROJECT_ENDPOINT"],
            credential=ManagedIdentityCredential(client_id=os.environ["AZURE_CLIENT_ID"]),
        )
        reference = {
            "type": "agent_reference",
            "name": AGENT_NAME,
            "version": os.environ["AUT002_AGENT_VERSION"],
        }
        expected = Path(__file__).resolve().parents[2] / "policy/definition.json"
        raw = expected.read_bytes()
        if hashlib.sha256(raw).hexdigest() != os.environ["AUT002_DEFINITION_SHA256"]:
            raise ValueError("candidate_definition_hash_mismatch")
        declared = json.loads(raw)
        deployed = project.agents.get_version(AGENT_NAME, reference["version"]).definition.as_dict()
        if deployed.get("tools") != declared.get("tools") or deployed.get("model") != declared.get("model"):
            raise ValueError("deployed_agent_definition_drift")
        return cls(project.get_openai_client(), reference, os.environ["AZURE_OPENAI_CHAT_DEPLOYMENT"])

    def request(self, prompt: str) -> ToolRequest:
        try:
            response = self.client.responses.create(
                model=self.model,
                input=prompt,
                extra_body={"agent_reference": self.reference},
            )
        except PermissionDeniedError as error:
            matches = re.findall(r"Microsoft\.CognitiveServices/[A-Za-z0-9_*/.-]+/(?:read|write|delete|action)", str(error.body))
            error.required_permission = matches[0] if matches else None
            raise
        self.response_ids.append(response.id)
        return tool_request(response)

    def complete(self, request: ToolRequest, outcome: dict[str, object]) -> str:
        response = self.client.responses.create(
            model=self.model,
            previous_response_id=request.response_id,
            input=[{"type": "function_call_output", "call_id": request.call_id, "output": json.dumps(outcome)}],
            extra_body={"agent_reference": self.reference},
            tool_choice="none",
        )
        self.response_ids.append(response.id)
        return response.output_text

    def cleanup(self) -> None:
        for response_id in list(self.response_ids):
            self.client.responses.delete(response_id)
            self.response_ids.remove(response_id)