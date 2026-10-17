package k8spgseenvlabel

import future.keywords.contains
import future.keywords.if
import future.keywords.in

obj(kind, ns, lbls) := {"review": {"object": {
	"kind": kind,
	"metadata": {"name": "t", "namespace": ns, "labels": lbls},
	"spec": {},
}}}

ns_inventory(name, env_value) := {"cluster": {"v1": {"Namespace": {name: {"metadata": {"name": name, "labels": {"environment": env_value}}}}}}}

# --- 15a: allowed values ---

# 1. environment=prod → allowed
test_prod_ok if {
	count(violation) == 0 with input as obj("Deployment", "demo", {"environment": "prod"})
}

# 2. Label missing → denied
test_missing_denied if {
	count(violation) == 1 with input as obj("Deployment", "demo", {})
}

# 3. "production" (not in the list) → denied
test_production_spelling_denied if {
	count(violation) == 1 with input as obj("Deployment", "demo", {"environment": "production"})
}

# 4. "Prod" (wrong case) → denied
test_wrong_case_denied if {
	count(violation) == 1 with input as obj("Deployment", "demo", {"environment": "Prod"})
}

# 5. Namespace object with environment=dev → allowed
test_namespace_dev_ok if {
	count(violation) == 0 with input as obj("Namespace", "", {"environment": "dev"})
}

# --- 15b: must match the namespace ---

# 6. prod workload in a prod namespace → allowed
test_matches_namespace_ok if {
	count(violation) == 0 with input as obj("Deployment", "demo", {"environment": "prod"}) with data.inventory as ns_inventory("demo", "prod")
}

# 7. prod workload in a DEV namespace → denied (cross-environment confusion)
test_mismatch_denied if {
	count(violation) == 1 with input as obj("Deployment", "sandbox", {"environment": "prod"}) with data.inventory as ns_inventory("sandbox", "dev")
}

# 8. Namespace not in the cache → only the value check runs, no false alarm
test_unknown_namespace_quiet if {
	count(violation) == 0 with input as obj("Deployment", "other", {"environment": "staging"}) with data.inventory as ns_inventory("demo", "prod")
}

# --- skips and waiver ---

# 9. Pod created by a controller → skipped
test_controller_pod_skipped if {
	inp := {"review": {"object": {
		"kind": "Pod", "metadata": {
			"name": "web-abc", "namespace": "demo",
			"ownerReferences": [{"kind": "ReplicaSet", "name": "web-123"}],
		},
		"spec": {},
	}}}
	count(violation) == 0 with input as inp
}

# 10. Valid P15 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P15", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as obj("Deployment", "demo", {}) with data.inventory as waivers
}
