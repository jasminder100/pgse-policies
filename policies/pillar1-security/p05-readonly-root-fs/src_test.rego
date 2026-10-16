package k8spgsereadonlyrootfs

import future.keywords.contains
import future.keywords.if
import future.keywords.in

pod(ctrs) := {"review": {"object": {
	"kind": "Pod",
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": {"containers": ctrs},
}}}

# 1. Explicit true → allowed
test_readonly_true_ok if {
	count(violation) == 0 with input as pod([{"name": "a", "securityContext": {"readOnlyRootFilesystem": true}}])
}

# 2. Explicit false → denied
test_readonly_false_denied if {
	count(violation) == 1 with input as pod([{"name": "a", "securityContext": {"readOnlyRootFilesystem": false}}])
}

# 3. Field missing (defaults to writable) → denied
test_missing_field_denied if {
	count(violation) == 1 with input as pod([{"name": "a", "securityContext": {}}])
}

# 4. Two containers, only one read-only → 1 violation
test_one_of_two_writable if {
	count(violation) == 1 with input as pod([
		{"name": "a", "securityContext": {"readOnlyRootFilesystem": true}},
		{"name": "b"},
	])
}

# 5. Deployment: app OK, init container writable → 1 violation
test_init_container_in_deployment if {
	inp := {"review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}, "spec": {"template": {"spec": {
		"containers": [{"name": "app", "securityContext": {"readOnlyRootFilesystem": true}}],
		"initContainers": [{"name": "init"}],
	}}}}}}
	count(violation) == 1 with input as inp
}

# 6. Valid P05 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P05", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as pod([{"name": "a"}]) with data.inventory as waivers
}
