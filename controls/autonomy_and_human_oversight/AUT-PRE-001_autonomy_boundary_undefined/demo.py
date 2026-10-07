"""Build the real tool definition and run the shared mandate release gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

CONTROL = Path(__file__).resolve().parent
REPOSITORY = CONTROL.parents[2]
RUNTIME = CONTROL.parent / "AUT-002_irreversible_action_attempted"
sys.path.insert(0, str(RUNTIME))


def build_candidate(root: Path, *, controls: list[str] | None = None) -> dict:
    from src.aut_002.foundry import AGENT_NAME, agent_definition

    identifiers = controls or ["AUT-PRE-001", "AUT-PRE-002"]
    directory = root / ".fwf/agents" / AGENT_NAME
    raw = (directory / "mandate.yaml").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    contract = {
        "apiVersion": "forgedwithfoundry.dev/v1alpha1", "kind": "AgentGovernanceContract",
        "metadata": {"agentId": AGENT_NAME, "description": "Synthetic support-record mandate", "source": "https://github.com/doruit/forged-with-foundry", "license": "MIT"},
        "spec": {"agentRef": {"definition": "definition.json"}, "controls": [{"id": identifier, "version": "1.0.0", "evidence": {
            "mandate": {"path": "mandate.yaml", "sha256": digest}, "reviewRef": "SYNTHETIC-MANDATE-REVIEW-001",
            "reviewedOn": "2026-10-07", "accountableRole": "AI Governance" if identifier == "AUT-PRE-001" else "Business Owner",
        }} for identifier in identifiers]},
    }
    definition = agent_definition("aut-002-gpt-5").as_dict()
    (directory / "governance.yaml").write_text(json.dumps(contract, indent=2) + "\n")
    (root / "definition.json").write_text(json.dumps(definition, indent=2) + "\n")
    manifest = {"expectedAgents": [AGENT_NAME], "candidateDefinitions": {AGENT_NAME: "definition.json"},
                "profiles": {"autonomy-mandate-review": {"requiredControls": identifiers}}}
    (root / "deployment-profile.yaml").write_text(json.dumps(manifest, indent=2) + "\n")
    return {"mandateSha256": digest, "definition": definition, "agentName": AGENT_NAME}


def run_gate(root: Path, *, evidence: Path) -> None:
    environment = {**os.environ, "PATH": f"{Path(sys.executable).parent}:{os.environ['PATH']}"}
    subprocess.run(["bash", str(REPOSITORY / "scripts/deployment_gate.sh"), "--manifest", str(root / "deployment-profile.yaml"),
                    "--profile", "autonomy-mandate-review", "--root", str(root), "--evidence-out", str(evidence)],
                   env=environment, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, default=CONTROL / "candidate")
    parser.add_argument("--build", action="store_true", help="Build the synthetic reviewed sample; never use this to reapprove an altered release")
    parser.add_argument("--evidence", type=Path, default=CONTROL / ".azure/gate-evidence.json")
    arguments = parser.parse_args()
    if arguments.build:
        build_candidate(arguments.candidate)
    arguments.evidence.parent.mkdir(parents=True, exist_ok=True)
    run_gate(arguments.candidate, evidence=arguments.evidence)


if __name__ == "__main__":
    main()