#!/usr/bin/env python3
"""Builds the compact JSON evidence artifact for one deployment_gate.sh run.

This is evaluation evidence, not proof that the underlying business
assertions in any contract are true, and not a cryptographic deployment
attestation -- it records what the gate checked and what it decided, using
a plain workload-commit + content-hash trail an organisation can correlate
with its own commit signing / branch protection, not a substitute for
those controls. See docs/governance-contract.md#policy-layer.

Contract content hashes are read directly from the plan document (computed
once, while scripts/build_deployment_plan.py read and parsed each contract)
-- this script never reopens a contract file itself, so the recorded hash
always matches exactly the content that was assessed, not whatever happens
to be on disk when evidence is built afterward.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
import uuid
from pathlib import Path


def build_evidence(
    plan: dict,
    conftest_result: object,
    *,
    workload_source_commit: str,
    framework_revision: str,
    outcome: str,
) -> dict:
    contract_hashes = {
        agent["agentId"]: agent["contentSha256"]
        for agent in plan.get("discoveredAgents", [])
        if agent.get("hasContract") and "contentSha256" in agent
    }
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "correlationId": str(uuid.uuid4()),
        "policyVersion": "1.0.0",
        "governanceAction": "release_permitted" if outcome == "allowed" else "release_blocked",
        "actionVerified": True,
        "workloadSourceCommit": workload_source_commit,
        "frameworkRevision": framework_revision,
        "policyProfile": plan.get("policyProfile"),
        "expectedAgents": plan.get("expectedAgents", []),
        "evaluatedControls": plan.get("requiredControls", []),
        "contractHashes": contract_hashes,
        "mandateBindings": {
            agent["agentId"]: {"mandateSha256": agent.get("mandate", {}).get("sha256"),
                               "candidateSha256": agent.get("candidate", {}).get("sha256")}
            for agent in plan.get("discoveredAgents", []) if "mandate" in agent
        },
        "outcome": outcome,
        "conftestResult": conftest_result,
        "disclaimer": (
            "This is evaluation evidence -- it records what the gate checked and "
            "decided, not proof that the underlying business assertions are true, "
            "and not a cryptographic deployment attestation."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--conftest-result", required=True, type=Path)
    parser.add_argument("--workload-source-commit", required=True, help="Commit (or documented non-git/dirty state) of the --root workload, never this framework repo's own commit.")
    parser.add_argument("--framework-revision", required=True, help="This repository's own commit for schemas/governance-contract + policy/governance-contract.")
    parser.add_argument("--outcome", required=True, choices=["allowed", "denied"])
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    conftest_result = json.loads(args.conftest_result.read_text(encoding="utf-8"))
    evidence = build_evidence(
        plan,
        conftest_result,
        workload_source_commit=args.workload_source_commit,
        framework_revision=args.framework_revision,
        outcome=args.outcome,
    )
    print(json.dumps(evidence, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
