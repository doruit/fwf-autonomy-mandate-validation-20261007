package main

# Rego unit tests for deployment_gate.rego, run with:
#   conftest verify --policy policy/governance-contract
# These are the exact regression scenarios required by the governance
# contract review: missing agent, agent folder without a contract, an
# invalid contract, and a valid contract missing a required control.

_passing_plan := {
	"policyProfile": "core",
	"requiredControls": ["VAL-PRE-001", "VAL-PRE-002"],
	"expectedAgents": ["helpdesk-tier1-triage"],
	"discoveredAgents": [{
		"agentId": "helpdesk-tier1-triage",
		"hasContract": true,
		"valid": true,
		"controlStatuses": {"VAL-PRE-001": "complete", "VAL-PRE-002": "complete"},
	}],
}

test_fully_covered_agent_with_all_required_controls_is_allowed if {
	count(deny) == 0 with input as _passing_plan
}

test_empty_expected_agents_list_denies_instead_of_defaulting_to_allowed if {
	plan := object.union(_passing_plan, {"expectedAgents": []})
	count(deny) == 1 with input as plan
	some msg in deny with input as plan
	contains(msg, "no expectedAgents")
}

test_missing_expected_agents_field_denies_instead_of_defaulting_to_allowed if {
	plan := {k: v | some k, v in _passing_plan; k != "expectedAgents"}
	count(deny) == 1 with input as plan
	some msg in deny with input as plan
	contains(msg, "no expectedAgents")
}

test_empty_required_controls_list_denies_instead_of_defaulting_to_allowed if {
	plan := object.union(_passing_plan, {"requiredControls": []})
	count(deny) == 1 with input as plan
	some msg in deny with input as plan
	contains(msg, "no requiredControls")
}

test_zero_contracts_fails_when_an_agent_is_expected if {
	plan := object.union(_passing_plan, {"discoveredAgents": []})
	count(deny) == 1 with input as plan
	some msg in deny with input as plan
	contains(msg, "no discovered .fwf/agents/ folder")
}

test_two_expected_agents_with_only_one_contract_fails if {
	plan := object.union(_passing_plan, {"expectedAgents": ["helpdesk-tier1-triage", "second-agent"]})
	count(deny) == 1 with input as plan
	some msg in deny with input as plan
	contains(msg, "second-agent")
}

test_deleted_agent_folder_still_fails if {
	# A deleted folder is indistinguishable from "never discovered" to the
	# build script, so this is the same failure mode as the zero-contracts case.
	plan := object.union(_passing_plan, {"discoveredAgents": []})
	count(deny) == 1 with input as plan
}

test_agent_folder_without_a_governance_yaml_fails if {
	plan := object.union(_passing_plan, {"discoveredAgents": [{
		"agentId": "helpdesk-tier1-triage",
		"hasContract": false,
	}]})
	count(deny) == 1 with input as plan
	some msg in deny with input as plan
	contains(msg, "no governance.yaml contract")
}

test_schema_invalid_contract_fails if {
	plan := object.union(_passing_plan, {"discoveredAgents": [{
		"agentId": "helpdesk-tier1-triage",
		"hasContract": true,
		"valid": false,
		"controlStatuses": {},
	}]})
	count(deny) == 1 with input as plan
	some msg in deny with input as plan
	contains(msg, "fails structural validation")
}

test_removing_a_required_control_fails_even_if_contract_is_schema_valid if {
	plan := object.union(_passing_plan, {"discoveredAgents": [{
		"agentId": "helpdesk-tier1-triage",
		"hasContract": true,
		"valid": true,
		"controlStatuses": {"VAL-PRE-001": "complete"},
	}]})
	count(deny) == 1 with input as plan
	some msg in deny with input as plan
	contains(msg, "VAL-PRE-002")
}

test_incomplete_but_present_control_still_fails if {
	plan := object.union(_passing_plan, {"discoveredAgents": [{
		"agentId": "helpdesk-tier1-triage",
		"hasContract": true,
		"valid": true,
		"controlStatuses": {"VAL-PRE-001": "complete", "VAL-PRE-002": "incomplete"},
	}]})
	count(deny) == 1 with input as plan
}

test_a_second_unexpected_agent_present_does_not_affect_the_result if {
	# A workload may implement more agents than the current deployment
	# targets; only expectedAgents are checked.
	plan := object.union(_passing_plan, {"discoveredAgents": array.concat(
		_passing_plan.discoveredAgents,
		[{"agentId": "unrelated-agent", "hasContract": true, "valid": true, "controlStatuses": {}}],
	)})
	count(deny) == 0 with input as plan
}
