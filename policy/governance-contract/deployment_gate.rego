package main

# Forged with Foundry deployment gate policy: given a deployment plan
# document (built by scripts/build_deployment_plan.py, never authored by a
# workload's own governance.yaml), deny deployment unless every expected
# agent has a structurally valid governance contract declaring every
# control the trusted pipeline's policy profile requires.
#
# This is the organisational POLICY layer: "which agents must be covered,
# and which controls are mandatory for them" is a decision made by whoever
# builds the deployment plan (the trusted pipeline), never by the workload
# repository itself. Field types, required fields, and structural
# conditional requirements (is a value numeric, is a date real, is a
# control version supported) are NOT duplicated here -- those stay in
# JSON Schema (schemas/governance-contract/v1alpha1/), which is what
# `scripts/validate_governance_contract.py` already produced the `valid`
# and `controlStatuses` fields on this input from.
#
# See docs/governance-contract.md#policy-layer.

agent_found(agent) if {
	some discovered in input.discoveredAgents
	discovered.agentId == agent
}

discovered_for(agent) := discovered if {
	some discovered in input.discoveredAgents
	discovered.agentId == agent
}

control_complete(discovered, control_id) if {
	discovered.controlStatuses[control_id] == "complete"
}

# Defense in depth: scripts/build_deployment_plan.py already refuses to build a plan
# from a manifest with a missing or empty expectedAgents/requiredControls list (see its
# ManifestValidationError), but this policy must not itself ALLOW a hand-crafted or
# malformed deployment-plan document that skipped that validation. `some agent in []`
# never fires, so without these two rules an empty or missing list would silently
# evaluate as "nothing to deny" instead of failing closed.
deny contains msg if {
	count(object.get(input, "expectedAgents", [])) == 0
	msg := "deployment plan has no expectedAgents -- refusing to evaluate an empty or missing agent list"
}

deny contains msg if {
	count(object.get(input, "requiredControls", [])) == 0
	msg := "deployment plan has no requiredControls -- refusing to evaluate an empty or missing control list"
}

# An expected agent must have a discovered .fwf/agents/<agent-id>/ folder at all.
deny contains msg if {
	some agent in input.expectedAgents
	not agent_found(agent)
	msg := sprintf(
		"expected agent '%s' has no discovered .fwf/agents/ folder -- it is not covered by any governance contract",
		[agent],
	)
}

# The folder exists, but it never had a governance.yaml file in it.
deny contains msg if {
	some agent in input.expectedAgents
	discovered := discovered_for(agent)
	not discovered.hasContract
	msg := sprintf(
		"expected agent '%s' has a .fwf/agents/ folder but no governance.yaml contract",
		[agent],
	)
}

# The contract exists but failed structural (JSON Schema) validation.
deny contains msg if {
	some agent in input.expectedAgents
	discovered := discovered_for(agent)
	discovered.hasContract
	discovered.valid == false
	msg := sprintf(
		"expected agent '%s' has a governance.yaml contract that fails structural validation",
		[agent],
	)
}

# The contract is structurally valid but omits (or does not complete) a
# control this deployment's policy profile requires. This is the genuine
# policy decision: the required-control set comes from input.requiredControls,
# which is supplied by the trusted pipeline building the deployment plan,
# never read from the workload's own governance.yaml.
deny contains msg if {
	some agent in input.expectedAgents
	discovered := discovered_for(agent)
	discovered.hasContract
	discovered.valid == true
	some required_control in input.requiredControls
	not control_complete(discovered, required_control)
	msg := sprintf(
		"expected agent '%s' does not have a complete '%s' control (required by policy profile '%s')",
		[agent, required_control, input.policyProfile],
	)
}

autonomy_required(control_id) if {
	control_id in input.requiredControls
	control_id in {"AUT-PRE-001", "AUT-PRE-002"}
}

deny contains msg if {
	some control_id in {"AUT-PRE-001", "AUT-PRE-002"}
	autonomy_required(control_id)
	some agent in input.discoveredAgents
	count(object.get(object.get(agent, "mandate", {}), "errors", ["missing source"])) > 0
	msg := sprintf("%s: mandate_or_candidate_unavailable for %s", [control_id, agent.agentId])
}

mandate_ready(agent) if {
	count(agent.mandate.errors) == 0
	agent.mandate.declaration.defaultDecision == "deny"
}

deny contains msg if {
	autonomy_required("AUT-PRE-001")
	some agent in input.discoveredAgents
	mandate_ready(agent)
	agent.mandate.declaration.agentId != agent.agentId
	msg := sprintf("AUT-PRE-001: mandate_agent_mismatch for %s", [agent.agentId])
}

deny contains msg if {
	autonomy_required("AUT-PRE-001")
	some agent in input.discoveredAgents
	mandate_ready(agent)
	declared := {action.toolName | some action in agent.mandate.declaration.actions}
	built := {tool.name | some tool in agent.candidate.definition.tools}
	declared != built
	msg := sprintf("AUT-PRE-001: tool_coverage_mismatch for %s", [agent.agentId])
}

deny contains msg if {
	some control_id in {"AUT-PRE-001", "AUT-PRE-002"}
	autonomy_required(control_id)
	some agent in input.discoveredAgents
	mandate_ready(agent)
	names := [action.toolName | some action in agent.mandate.declaration.actions]
	count(names) != count({name | some name in names})
	msg := sprintf("%s: duplicate_action for %s", [control_id, agent.agentId])
}

deny contains msg if {
	autonomy_required("AUT-PRE-001")
	some agent in input.discoveredAgents
	mandate_ready(agent)
	some action in agent.mandate.declaration.actions
	some tool in agent.candidate.definition.tools
	action.toolName == tool.name
	tool.parameters != {"type": "object", "properties": {"record_id": {"type": "string", "enum": action.targets}}, "required": ["record_id"], "additionalProperties": false}
	msg := sprintf("AUT-PRE-001: tool_scope_mismatch for %s", [action.toolName])
}

deny contains msg if {
	autonomy_required("AUT-PRE-001")
	some agent in input.discoveredAgents
	mandate_ready(agent)
	some action in agent.mandate.declaration.actions
	action.disposition != "approval_required"
	object.get(action, "approval", {}) != {}
	msg := sprintf("AUT-PRE-001: contradictory_permission for %s", [action.toolName])
}

protected_action(action) if {
	action.reversibility == "irreversible"
}

protected_action(action) if {
	some impact in action.impact
	impact in {"financial", "legal"}
}

deny contains msg if {
	autonomy_required("AUT-PRE-002")
	some agent in input.discoveredAgents
	mandate_ready(agent)
	some action in agent.mandate.declaration.actions
	action.disposition == "allowed"
	protected_action(action)
	msg := sprintf("AUT-PRE-002: protected_action_ungated for %s", [action.toolName])
}

valid_human_gate(action) if {
	action.approval.kind == "human_approval"
	action.approval.approverRole == "OpsManager"
	action.approval.ttlSeconds > 0
	action.approval.ttlSeconds <= 300
	{"action_identity", "decision", "executed", "verified"} <= {field | some field in action.approval.evidenceRequired}
}

deny contains msg if {
	autonomy_required("AUT-PRE-002")
	some agent in input.discoveredAgents
	mandate_ready(agent)
	some action in agent.mandate.declaration.actions
	action.disposition == "approval_required"
	not valid_human_gate(action)
	msg := sprintf("AUT-PRE-002: human_gate_incomplete for %s", [action.toolName])
}
