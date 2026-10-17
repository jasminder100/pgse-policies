package k8spgseownershiplabels

import future.keywords.contains
import future.keywords.if
import future.keywords.in

full := {"owner": "alice", "team": "pgse", "cost-center": "cc-1001"}

obj(kind, lbls) := {"review": {"object": {
	"kind": kind,
	"metadata": {"name": "t", "namespace": "demo", "labels": lbls},
	"spec": {},
}}}

# 1. Deployment with all three labels → allowed
test_all_labels_ok if {
	count(violation) == 0 with input as obj("Deployment", full)
}

# 2. Missing team → 1 violation that names "team"
test_missing_team if {
	vs := violation with input as obj("Deployment", {"owner": "alice", "cost-center": "cc-1001"})
	count(vs) == 1
	some v in vs
	contains(v.msg, "team")
}

# 3. No labels at all → still ONE violation (listing all three)
test_no_labels_one_violation if {
	count(violation) == 1 with input as obj("Deployment", {})
}

# 4. Empty value counts as missing → denied
test_empty_value_denied if {
	count(violation) == 1 with input as obj("Deployment", {"owner": "", "team": "pgse", "cost-center": "cc-1001"})
}

# 5. Namespace without labels → denied
test_namespace_checked if {
	count(violation) == 1 with input as obj("Namespace", {})
}

# 6. Pod created by a ReplicaSet → skipped
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

# 7. Bare Pod (kubectl run) without labels → denied
test_bare_pod_denied if {
	count(violation) == 1 with input as obj("Pod", {})
}

# 8. Constraint requires only "owner" → team/cost-center not needed
test_custom_label_list if {
	inp := object.union(obj("Deployment", {"owner": "alice"}), {"parameters": {"labels": ["owner"]}})
	count(violation) == 0 with input as inp
}

# 9. Valid P14 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P14", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as obj("Deployment", {}) with data.inventory as waivers
}
