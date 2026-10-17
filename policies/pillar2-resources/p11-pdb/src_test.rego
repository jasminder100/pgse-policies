package k8spgsepdb

import future.keywords.contains
import future.keywords.if
import future.keywords.in

workload(kind, lbls) := {"review": {"object": {
	"kind": kind,
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": {"template": {"metadata": {"labels": lbls}, "spec": {"containers": [{"name": "a"}]}}},
}}}

pdb(ns, spec) := {"namespace": {ns: {"policy/v1": {"PodDisruptionBudget": {"p1": {"spec": spec}}}}}}

web := {"app": "web", "tier": "frontend"}

# 1. PDB selecting the pods with minAvailable 1 → allowed
test_matching_pdb_ok if {
	count(violation) == 0 with input as workload("Deployment", web) with data.inventory as pdb("demo", {"minAvailable": 1, "selector": {"matchLabels": {"app": "web"}}})
}

# 2. No PDB at all → flagged
test_no_pdb_flagged if {
	count(violation) == 1 with input as workload("Deployment", web) with data.inventory as {}
}

# 3. PDB selects a DIFFERENT app → flagged
test_pdb_other_app_flagged if {
	count(violation) == 1 with input as workload("Deployment", web) with data.inventory as pdb("demo", {"minAvailable": 1, "selector": {"matchLabels": {"app": "api"}}})
}

# 4. matchExpressions "In" → allowed
test_match_expression_in_ok if {
	count(violation) == 0 with input as workload("Deployment", web) with data.inventory as pdb("demo", {"maxUnavailable": 1, "selector": {"matchExpressions": [{"key": "app", "operator": "In", "values": ["web", "api"]}]}})
}

# 5. matchExpressions "NotIn" excluding our app → flagged
test_match_expression_notin_flagged if {
	count(violation) == 1 with input as workload("Deployment", web) with data.inventory as pdb("demo", {"minAvailable": 1, "selector": {"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["web"]}]}})
}

# 6. Empty selector selects every pod → allowed
test_empty_selector_ok if {
	count(violation) == 0 with input as workload("Deployment", web) with data.inventory as pdb("demo", {"minAvailable": 1, "selector": {}})
}

# 7. minAvailable 0 protects nothing → flagged
test_min_available_zero_flagged if {
	count(violation) == 1 with input as workload("Deployment", web) with data.inventory as pdb("demo", {"minAvailable": 0, "selector": {"matchLabels": {"app": "web"}}})
}

# 8. maxUnavailable 100% protects nothing → flagged
test_max_unavailable_all_flagged if {
	count(violation) == 1 with input as workload("Deployment", web) with data.inventory as pdb("demo", {"maxUnavailable": "100%", "selector": {"matchLabels": {"app": "web"}}})
}

# 9. StatefulSet is checked too → flagged without PDB
test_statefulset_checked if {
	count(violation) == 1 with input as workload("StatefulSet", web) with data.inventory as {}
}

# 10. Matching PDB but in ANOTHER namespace → flagged
test_pdb_other_namespace_flagged if {
	count(violation) == 1 with input as workload("Deployment", web) with data.inventory as pdb("other", {"minAvailable": 1, "selector": {"matchLabels": {"app": "web"}}})
}

# 11. A Job (not long-running) → ignored
test_job_ignored if {
	count(violation) == 0 with input as workload("Job", web) with data.inventory as {}
}

# 12. Valid P11 waiver → exempt
test_valid_waiver_exempts if {
	inv := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P11", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as workload("Deployment", web) with data.inventory as inv
}
