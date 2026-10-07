#!/usr/bin/env python3
"""Shared validator for the Forged with Foundry Agent Governance Contract.

Discovers and validates `.fwf/agents/<agent-id>/governance.yaml` contract
instances against the declarative schemas in
`schemas/governance-contract/v1alpha1/`. This script is the only place that
understands contract discovery and JSON Schema validation; individual
controls call it instead of re-implementing structural checks.

This is a Forged with Foundry community pattern; Microsoft Foundry and `azd`
tooling do not discover or enforce this file, and this script never opens a
real Microsoft/vendor `agent.yaml` -- discovery only ever matches the exact
filename `governance.yaml` under `.fwf/agents/<agent-id>/`. See
docs/governance-contract.md for the full architecture.

This script only validates structure (JSON Schema): required fields, types,
conditional requirements, calendar-valid dates, and a small placeholder-text
check. It does not decide which controls are mandatory for a given agent --
that organisational policy decision belongs to the Conftest/Rego layer under
`policy/governance-contract/` (see docs/governance-contract.md#policy-layer).

Exit codes (stable, scripted against): 0 = valid (and, if --enforce, the
requested control's status is 'complete'); 1 = the contract or requested
control was read successfully but denied (structurally incomplete, invalid,
or unsupported); 2 = execution failure -- the contract could not even be
read or parsed (missing file, malformed YAML, wrong top-level shape). A
crashed validator (exit 2) must never be mistaken for a successful negative
test (exit 1); callers that assert "this fixture is correctly denied" must
check for exit code 1 specifically, not merely "non-zero".

Evidence values are never evaluated as shell code and never become shell
variable names: --shell prints only two fixed, internally-generated keys
(CONTROL_ID, CONTROL_STATUS). Any other evidence field (for example
businessCaseId) must be extracted from the default JSON output with an
explicit JSON parser (see any control's demo.sh for the pattern), never by
splitting KEY=VALUE lines. The schema additionally rejects embedded line
breaks in business-identifier fields, so no evidence value can inject a
spoofed shell assignment even if a caller mishandles it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_ROOT = REPO_ROOT / "schemas" / "governance-contract" / "v1alpha1"
CENTRAL_SCHEMA_PATH = SCHEMA_ROOT / "fwf-governance-contract.schema.json"
CONTROLS_SCHEMA_DIR = SCHEMA_ROOT / "controls"
CONTRACT_GLOB = ".fwf/agents/*/governance.yaml"

EXIT_OK = 0
EXIT_DENIED = 1
EXIT_ERROR = 2

# Rejected only on an exact (trimmed, case-insensitive) match, never merely
# "contains" -- legitimate prose that happens to mention "example" or "todo"
# as a normal word must still pass.
_PLACEHOLDER_TOKENS = {
    "todo",
    "tbd",
    "fixme",
    "n/a",
    "na",
    "placeholder",
    "changeme",
    "change me",
    "xxx",
    "tbc",
    "lorem ipsum",
    "test",
    "example",
    "...",
    "???",
}
_PLACEHOLDER_FIELD_PATHS: dict[str, tuple[str, ...]] = {
    "VAL-PRE-001": ("owner", "businessCaseId", "expectedOutcome", "metric.name"),
    "VAL-PRE-002": (),
}


class _DuplicateKeyLoader(yaml.SafeLoader):
    """A YAML loader that rejects duplicate mapping keys instead of silently
    letting the last one win, which would hide a copy-paste mistake."""


def _construct_mapping_no_duplicates(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r} in mapping", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


_DuplicateKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_duplicates
)


def _load_schema(path: Path) -> dict[str, Any]:
    """Load a schema file, assigning it a file:// $id so relative $refs resolve."""
    schema = json.loads(path.read_text(encoding="utf-8"))
    schema.setdefault("$id", path.resolve().as_uri())
    return schema


def _build_registry() -> Registry:
    schema_files = sorted(SCHEMA_ROOT.rglob("*.schema.json"))
    resources = []
    for path in schema_files:
        schema = _load_schema(path)
        resources.append((schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012)))
    return Registry().with_resources(resources)


def _control_schema_path(control_id: str) -> Path:
    return CONTROLS_SCHEMA_DIR / f"{control_id}.schema.json"


def known_control_ids() -> list[str]:
    return sorted(path.name.removesuffix(".schema.json") for path in CONTROLS_SCHEMA_DIR.glob("*.schema.json"))


class ContractReadError(Exception):
    """The contract file could not be read or parsed -- an execution failure
    (exit code 2), distinct from a structurally denied contract (exit 1)."""


def read_contract_bytes(path: Path) -> bytes:
    """Reads a contract file's raw bytes exactly once. Callers that also need a
    content hash (for example scripts/build_deployment_plan.py's evidence trail)
    must hash these same bytes rather than re-reading the file later -- re-reading
    after the fact cannot guarantee the hash matches what was actually parsed and
    validated."""
    if not path.is_file():
        raise ContractReadError(f"{path}: file not found")
    return path.read_bytes()


def parse_contract_bytes(raw: bytes, *, source: str) -> dict[str, Any]:
    try:
        data = yaml.load(raw.decode("utf-8"), Loader=_DuplicateKeyLoader)
    except UnicodeDecodeError as exc:
        raise ContractReadError(f"{source}: not valid UTF-8: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ContractReadError(f"{source}: malformed YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractReadError(f"{source}: contract must be a YAML mapping, not {type(data).__name__}")
    return data


def load_contract(path: Path) -> dict[str, Any]:
    return parse_contract_bytes(read_contract_bytes(path), source=str(path))


def discover_contracts(root: Path) -> list[Path]:
    """Find every .fwf/agents/<agent-id>/governance.yaml under root.

    Only this exact filename under this exact path shape is ever opened; a
    real Microsoft/vendor agent.yaml sitting anywhere nearby is ignored.
    """
    return sorted(root.glob(CONTRACT_GLOB))


def _is_placeholder(value: str) -> bool:
    return value.strip().casefold() in _PLACEHOLDER_TOKENS


def _get_path(data: dict[str, Any], dotted_path: str) -> Any:
    node: Any = data
    for part in dotted_path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _placeholder_errors(control_id: str, evidence: Any) -> list[str]:
    if not isinstance(evidence, dict):
        return []
    errors: list[str] = []
    for field_path in _PLACEHOLDER_FIELD_PATHS.get(control_id, ()):
        value = _get_path(evidence, field_path)
        if isinstance(value, str) and _is_placeholder(value):
            errors.append(f"evidence/{field_path}: '{value}' looks like an unfilled placeholder, not a real value")
    return errors


def _duplicate_ids(controls: list[Any]) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for entry in controls:
        control_id = entry.get("id") if isinstance(entry, dict) else None
        if control_id is None:
            continue
        if control_id in seen:
            duplicates.append(control_id)
        seen.add(control_id)
    return duplicates


def _non_string_id_errors(controls: list[Any]) -> list[str]:
    errors = []
    for index, entry in enumerate(controls):
        if isinstance(entry, dict) and "id" in entry and not isinstance(entry["id"], str):
            errors.append(
                f"spec/controls/{index}/id: must be a string, got {type(entry['id']).__name__} ({entry['id']!r})"
            )
    return errors


def validate_contract(data: dict[str, Any], *, agent_dir_name: str | None = None) -> list[str]:
    """Validate a loaded contract against the central schema plus repo-only checks.

    JSON Schema alone cannot reliably enforce "array items have unique id
    values" across drafts, cannot compare a value to the file path it was
    loaded from, and gives a poor diagnostic for a non-string id (every
    `oneOf` branch just fails) -- all three are checked explicitly here.
    """
    errors: list[str] = []
    registry = _build_registry()
    central_schema = _load_schema(CENTRAL_SCHEMA_PATH)
    validator = Draft202012Validator(central_schema, registry=registry, format_checker=FormatChecker())
    for error in validator.iter_errors(data):
        location = "/".join(str(part) for part in error.path) or "<root>"
        errors.append(f"{location}: {error.message}")

    spec = data.get("spec")
    controls = spec.get("controls") if isinstance(spec, dict) else None
    if isinstance(controls, list):
        errors.extend(_non_string_id_errors(controls))
        for duplicate_id in _duplicate_ids(controls):
            errors.append(f"spec/controls: duplicate control id '{duplicate_id}'")
        for entry in controls:
            if isinstance(entry, dict) and isinstance(entry.get("id"), str):
                errors.extend(_placeholder_errors(entry["id"], entry.get("evidence")))

    metadata = data.get("metadata")
    agent_id = metadata.get("agentId") if isinstance(metadata, dict) else None
    if agent_dir_name is not None and isinstance(agent_id, str) and agent_id != agent_dir_name:
        errors.append(
            f"metadata/agentId: '{agent_id}' does not match the directory it was discovered under "
            f"('{agent_dir_name}') -- the .fwf/agents/<agent-id>/ directory name must equal metadata.agentId"
        )
    return errors


def validate_control_entry(control_id: str, data: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    """Return (entry, errors) for one control id's evidence inside an already-loaded contract."""
    spec = data.get("spec")
    controls = spec.get("controls") if isinstance(spec, dict) else None
    entry = None
    if isinstance(controls, list):
        entry = next((c for c in controls if isinstance(c, dict) and c.get("id") == control_id), None)
    if entry is None:
        return None, [f"control '{control_id}' is not present in this contract"]

    schema_path = _control_schema_path(control_id)
    if not schema_path.is_file():
        return entry, [f"no schema exists for control '{control_id}' -- it has not been onboarded to the FwF contract yet"]

    registry = _build_registry()
    schema = _load_schema(schema_path)
    validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
    errors = []
    for error in validator.iter_errors(entry):
        location = "/".join(str(part) for part in error.path) or "<root>"
        errors.append(f"{location}: {error.message}")
    errors.extend(_placeholder_errors(control_id, entry.get("evidence")))
    return entry, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--contract", type=Path, help="Validate exactly this one governance.yaml file.")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="Discover .fwf/agents/*/governance.yaml under this directory (ignored if --contract is given).",
    )
    parser.add_argument("--control", dest="control_id", help="Also extract and validate one control's evidence.")
    parser.add_argument(
        "--shell",
        action="store_true",
        help=(
            "Print only CONTROL_ID and CONTROL_STATUS as KEY=VALUE lines (both fixed, "
            "internally-generated values). Requires --contract and --control. Never prints "
            "evidence fields -- extract those from the default JSON output instead."
        ),
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit 1 when any discovered contract, or the requested --control, is denied.",
    )
    args = parser.parse_args()

    if args.shell and (args.contract is None or args.control_id is None):
        parser.error("--shell requires both --contract and --control")

    contracts = [args.contract] if args.contract is not None else discover_contracts(args.root)
    if not contracts:
        print(json.dumps({"error": "no governance.yaml contracts found", "root": str(args.root)}))
        return EXIT_ERROR

    any_denied = False
    single_control_result: dict[str, Any] | None = None

    for contract_path in contracts:
        try:
            data = load_contract(contract_path)
        except ContractReadError as exc:
            print(json.dumps({"contract": str(contract_path), "error": str(exc)}), file=sys.stderr)
            return EXIT_ERROR

        envelope_errors = validate_contract(data, agent_dir_name=contract_path.parent.name)
        valid = not envelope_errors
        any_denied = any_denied or not valid
        result: dict[str, Any] = {"contract": str(contract_path), "valid": valid, "errors": envelope_errors}

        if args.control_id:
            entry, entry_errors = validate_control_entry(args.control_id, data)
            status = "complete" if (valid and entry is not None and not entry_errors) else "incomplete"
            result["control"] = {"id": args.control_id, "status": status, "errors": entry_errors, "entry": entry}
            any_denied = any_denied or status != "complete"
            if len(contracts) == 1:
                single_control_result = {"status": status}

        if not args.shell:
            print(json.dumps(result))

    if args.shell and single_control_result is not None:
        print(f"CONTROL_ID={args.control_id}")
        print(f"CONTROL_STATUS={single_control_result['status']}")

    if args.enforce and any_denied:
        return EXIT_DENIED
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
