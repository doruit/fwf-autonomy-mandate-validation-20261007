"""Scoped Azure Policy demonstration; tags are not authenticated gate evidence."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys

CONTROL = Path(__file__).resolve().parents[1]
RUNTIME = CONTROL.parent / "AUT-002_irreversible_action_attempted"
sys.path.insert(0, str(RUNTIME / "infra"))
from deploy import DEFAULT_STATE, azure, request, release_binding, save_state

STATE = CONTROL / ".azure/policy-state.json"
CONTROLS = {"AUT-PRE-001": "autonomyBoundaryStatus", "AUT-PRE-002": "humanGatesStatus"}


def target() -> dict:
    state = json.loads(DEFAULT_STATE.read_text())
    context = azure("account", "show")
    if state["tenant_id"] != context["tenantId"] or state["subscription_id"] != context["id"]:
        raise ValueError("Policy context mismatch")
    return state


def update_tags(state: dict, values: dict) -> None:
    resource = azure("webapp", "show", "--ids", state["webAppId"])
    tags = resource.get("tags", {})
    tags.update(values)
    request("PATCH", f"https://management.azure.com{state['webAppId']}?api-version=2024-11-01", {"tags": tags})


def setup(state: dict) -> None:
    binding = release_binding()
    update_tags(state, {name: "complete" for name in CONTROLS.values()} | {"mandateSha256": binding["sha256"]})
    owned = {"webAppId": state["webAppId"], "subscription_id": state["subscription_id"], "tenant_id": state["tenant_id"], "resources": []}
    for identifier, tag in CONTROLS.items():
        name = identifier.lower() + "-mandate-gate"
        definition_id = f"/subscriptions/{state['subscription_id']}/providers/Microsoft.Authorization/policyDefinitions/{name}"
        marker = f"FwF {identifier}; target={state['webAppId']}"
        try:
            existing = request("GET", f"https://management.azure.com{definition_id}?api-version=2021-06-01")
        except RuntimeError as error:
            if "PolicyDefinitionNotFound" not in str(error):
                raise
        else:
            if existing["properties"]["description"] != marker:
                raise ValueError("Policy ownership mismatch")
        request("PUT", f"https://management.azure.com{definition_id}?api-version=2021-06-01", {"properties": {
            "policyType": "Custom", "mode": "Indexed", "displayName": f"{identifier} scoped release status", "description": marker,
            "policyRule": {"if": {"allOf": [{"field": "type", "equals": "Microsoft.Web/sites"},
                                           {"field": "id", "equals": state["webAppId"]},
                                           {"field": f"tags['{tag}']", "notEquals": "complete"}]}, "then": {"effect": "deny"}},
        }})
        assignment_id = f"{state['webAppId']}/providers/Microsoft.Authorization/policyAssignments/{name}"
        owned["resources"].append({"definitionId": definition_id, "assignmentId": assignment_id, "marker": marker})
        save_state(STATE, owned)
        request("PUT", f"https://management.azure.com{assignment_id}?api-version=2024-04-01", {"properties": {
            "displayName": f"{identifier} synthetic mandate gate", "policyDefinitionId": definition_id,
            "enforcementMode": "Default", "description": marker,
        }})
    print("Two scoped Azure Policy assignments installed. Tags are forgeable summaries, not contract validation.")


def prove(state: dict) -> None:
    for identifier, tag in CONTROLS.items():
        try:
            update_tags(state, {tag: "incomplete"})
        except RuntimeError as error:
            if "RequestDisallowedByPolicy" not in str(error):
                raise
            print(f"{identifier}: RequestDisallowedByPolicy verified")
        else:
            update_tags(state, {tag: "complete"})
            raise RuntimeError("Policy denial was not observed; stop and rerun after propagation")
    update_tags(state, {name: "complete" for name in CONTROLS.values()})
    print("Matching ARM request allowed; existing webapp preserved.")


def cleanup(state: dict, confirm: bool) -> None:
    owned = json.loads(STATE.read_text())
    if any(owned[key] != state[key] for key in ["webAppId", "subscription_id", "tenant_id"]):
        raise ValueError("Policy cleanup context mismatch")
    for item in owned["resources"]:
        definition = request("GET", f"https://management.azure.com{item['definitionId']}?api-version=2021-06-01")
        if definition["properties"]["description"] != item["marker"]:
            raise ValueError("Policy cleanup ownership mismatch")
    print("Targets: only the two recorded Policy assignments/definitions; no workload resources.")
    if confirm:
        for item in owned["resources"]:
            request("DELETE", f"https://management.azure.com{item['assignmentId']}?api-version=2024-04-01")
            request("DELETE", f"https://management.azure.com{item['definitionId']}?api-version=2021-06-01")
        STATE.rename(STATE.with_suffix(".cleaned.json"))
        print("Owned Policy resources deleted; reused Foundry/App Service resources were not deleted.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["setup", "prove", "cleanup"])
    parser.add_argument("--confirm", action="store_true")
    arguments = parser.parse_args()
    state = target()
    if arguments.command == "setup":
        setup(state)
    elif arguments.command == "prove":
        prove(state)
    else:
        cleanup(state, arguments.confirm)


if __name__ == "__main__":
    main()