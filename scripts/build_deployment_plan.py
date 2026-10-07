#!/usr/bin/env python3
"""Builds the deployment-plan JSON that policy/governance-contract/deployment_gate.rego
evaluates. This is the small, explicit "trusted pipeline" step: it decides which agents
are expected to be deployed and which controls are mandatory for them, from a
deployment manifest supplied by the pipeline -- never from a workload's own
governance.yaml, which must not get a vote in what is mandatory for it.

The manifest itself is validated BEFORE any contract discovery happens (see
_validate_manifest): a manifest with a missing or empty expectedAgents/requiredControls
list must never silently default to an empty list, because Rego's `some agent in
input.expectedAgents` simply never fires over an empty list -- that would make an
unusable manifest evaluate as ALLOWED instead of failing closed. A malformed manifest is
an execution failure (ManifestValidationError, exit code 2), not a policy denial.

A glob of existing governance.yaml files alone cannot prove every deployable agent is
covered: an agent folder with no contract, or no folder at all, is invisible to a plain
glob. This script discovers every `.fwf/agents/<agent-id>/` folder (whether or not it
has a governance.yaml) and reports on each one explicitly, so the policy layer can
distinguish "not discovered at all" from "folder exists but has no contract" from
"contract exists but is invalid" from "contract is valid but missing a required
control". See docs/governance-contract.md#policy-layer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from validate_governance_contract import (
    ContractReadError,
    parse_contract_bytes,
    read_contract_bytes,
    validate_contract,
    validate_control_entry,
)

_CONTROLS_SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "governance-contract" / "v1alpha1" / "controls"


class ManifestValidationError(Exception):
    """The deployment manifest itself is malformed -- an execution failure
    (exit code 2), distinct from a policy denial (exit 1) or a contract that
    is merely incomplete."""


def _known_control_ids() -> set[str]:
    # path.stem only strips the last suffix ("VAL-PRE-001.schema.json" -> "VAL-PRE-001.schema"),
    # so strip the full ".schema.json" suffix explicitly.
    return {path.name.removesuffix(".schema.json") for path in _CONTROLS_SCHEMA_DIR.glob("*.schema.json")}


def _non_empty_unique_string_list(value: Any, *, field: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, list):
        raise ManifestValidationError(f"'{field}' must be a list, got {type(value).__name__}")
    if not value:
        raise ManifestValidationError(f"'{field}' must not be empty")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"'{field}' contains a non-string or blank entry: {item!r}")
    seen: set[str] = set()
    for item in value:
        if isinstance(item, str) and item in seen:
            errors.append(f"'{field}' contains a duplicate entry: {item!r}")
        if isinstance(item, str):
            seen.add(item)
    if errors:
        raise ManifestValidationError("; ".join(errors))
    return list(value)


def _validate_manifest(manifest: Any, profile: str) -> tuple[list[str], list[str]]:
    if not isinstance(manifest, dict):
        raise ManifestValidationError(f"manifest must be a mapping, got {type(manifest).__name__}")

    if "expectedAgents" not in manifest:
        raise ManifestValidationError("manifest is missing required field 'expectedAgents'")
    expected_agents = _non_empty_unique_string_list(manifest["expectedAgents"], field="expectedAgents")

    profiles = manifest.get("profiles")
    if not isinstance(profiles, dict):
        raise ManifestValidationError(f"manifest is missing required mapping field 'profiles' (got {type(profiles).__name__})")
    if profile not in profiles:
        raise ManifestValidationError(f"profile '{profile}' is not defined in the manifest (known: {sorted(profiles)})")

    profile_body = profiles[profile]
    if not isinstance(profile_body, dict) or "requiredControls" not in profile_body:
        raise ManifestValidationError(f"profile '{profile}' is missing required field 'requiredControls'")
    required_controls = _non_empty_unique_string_list(profile_body["requiredControls"], field=f"profiles.{profile}.requiredControls")

    known_control_ids = _known_control_ids()
    unknown = [control_id for control_id in required_controls if control_id not in known_control_ids]
    if unknown:
        raise ManifestValidationError(
            f"profile '{profile}' requires unknown control ID(s) {unknown} (known controls: {sorted(known_control_ids)})"
        )

    return expected_agents, required_controls


def discover_agent_folders(root: Path) -> list[Path]:
    agents_root = root / ".fwf" / "agents"
    if not agents_root.is_dir():
        return []
    return sorted(path for path in agents_root.iterdir() if path.is_dir())


def _assess_agent(agent_dir: Path, root: Path | None = None) -> dict[str, Any]:
    agent_id = agent_dir.name
    contract_path = agent_dir / "governance.yaml"
    entry: dict[str, Any] = {
        "agentId": agent_id,
        "contractPath": str(contract_path),
        "hasContract": contract_path.is_file(),
    }
    if not entry["hasContract"]:
        return entry

    try:
        raw = read_contract_bytes(contract_path)
    except ContractReadError as exc:
        entry["valid"] = False
        entry["errors"] = [str(exc)]
        entry["controlStatuses"] = {}
        return entry

    # Hash the exact bytes just read and parsed below -- never re-read the file
    # later to produce evidence, which could observe different content than what
    # was actually assessed.
    entry["contentSha256"] = hashlib.sha256(raw).hexdigest()

    try:
        data = parse_contract_bytes(raw, source=str(contract_path))
    except ContractReadError as exc:
        entry["valid"] = False
        entry["errors"] = [str(exc)]
        entry["controlStatuses"] = {}
        return entry

    errors = validate_contract(data, agent_dir_name=agent_id)
    entry["valid"] = not errors
    entry["errors"] = errors

    control_statuses: dict[str, str] = {}
    spec = data.get("spec") or {}
    for control in spec.get("controls") or []:
        if isinstance(control, dict) and isinstance(control.get("id"), str):
            _, control_errors = validate_control_entry(control["id"], data)
            control_statuses[control["id"]] = "complete" if (entry["valid"] and not control_errors) else "incomplete"
    entry["controlStatuses"] = control_statuses
    if entry["valid"]:
        from resolve_autonomy_mandate import resolve_mandate

        try:
            mandate = resolve_mandate(data, agent_dir, root or agent_dir)
        except ContractReadError as error:
            entry["mandate"] = {"errors": [str(error)]}
        else:
            if mandate is not None:
                entry["mandate"] = mandate
    return entry


def build_plan(manifest: dict[str, Any], profile: str, root: Path) -> dict[str, Any]:
    expected_agents, required_controls = _validate_manifest(manifest, profile)
    discovered = [_assess_agent(agent_dir, root) for agent_dir in discover_agent_folders(root)]
    candidates = manifest.get("candidateDefinitions", {})
    if not isinstance(candidates, dict) or any(key not in expected_agents for key in candidates):
        raise ManifestValidationError("candidateDefinitions must map expected agent IDs to local paths")
    for agent in discovered:
        if "mandate" not in agent:
            continue
        from resolve_autonomy_mandate import local_attachment

        candidate_path = candidates.get(agent["agentId"])
        try:
            if not isinstance(candidate_path, str) or not candidate_path:
                raise ContractReadError("built candidate definition is missing")
            path = local_attachment(root, candidate_path, root)
            raw = read_contract_bytes(path)
            candidate = parse_contract_bytes(raw, source="candidate definition")
            if not isinstance(candidate.get("tools"), list) or not candidate["tools"]:
                raise ContractReadError("candidate must expose a nonempty tool definition")
            agent["candidate"] = {"sha256": hashlib.sha256(raw).hexdigest(), "definition": candidate}
        except ContractReadError as error:
            agent.setdefault("mandate", {}).setdefault("errors", []).append(str(error))
    return {
        "policyProfile": profile,
        "requiredControls": required_controls,
        "expectedAgents": expected_agents,
        "discoveredAgents": discovered,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", required=True, type=Path, help="Deployment manifest YAML (profiles + expectedAgents).")
    parser.add_argument("--profile", required=True, help="Which manifest profile's requiredControls to apply.")
    parser.add_argument("--root", type=Path, default=Path("."), help="Workload repository root to discover .fwf/agents/ under.")
    args = parser.parse_args()

    manifest = yaml.safe_load(args.manifest.read_text(encoding="utf-8"))
    try:
        plan = build_plan(manifest, args.profile, args.root)
    except ManifestValidationError as exc:
        print(f"error: invalid deployment manifest: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(plan, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
