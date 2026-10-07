"""Resolve a shared mandate attachment once; policy decisions remain in Rego."""

from __future__ import annotations

import hashlib
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from validate_governance_contract import ContractReadError, SCHEMA_ROOT, _load_schema, parse_contract_bytes, read_contract_bytes

AUTONOMY_CONTROLS = {"AUT-PRE-001", "AUT-PRE-002"}


def local_attachment(base: Path, relative: str, root: Path) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or ":" in relative:
        raise ContractReadError("unsafe mandate attachment reference")
    target = (base / path).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ContractReadError("mandate attachment escapes workload root")
    return target


def resolve_mandate(contract: dict, agent_dir: Path, root: Path) -> dict | None:
    entries = [entry for entry in contract["spec"]["controls"] if entry["id"] in AUTONOMY_CONTROLS]
    if not entries:
        return None
    references = [entry["evidence"]["mandate"] for entry in entries]
    if any(reference != references[0] for reference in references):
        raise ContractReadError("autonomy controls refer to different mandate bytes")
    reference = references[0]
    target = local_attachment(agent_dir, reference["path"], root)
    raw = read_contract_bytes(target)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != reference["sha256"]:
        raise ContractReadError("mandate content hash does not match reviewed reference")
    declaration = parse_contract_bytes(raw, source="mandate attachment")
    validator = Draft202012Validator(_load_schema(SCHEMA_ROOT / "autonomy-mandate.schema.json"), format_checker=FormatChecker())
    errors = [f"mandate/{'/'.join(map(str, error.path))}: {error.validator} validation failed" for error in validator.iter_errors(declaration)]
    return {"sha256": digest, "declaration": declaration, "errors": errors}