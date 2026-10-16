package k8spgsenoprivilegeescalation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

pod(ctrs) := {"review": {"object": {
	"kind": "Pod",
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": {"containers": ctrs},
}}}

# 1. Explicit false → allowed
test_explicit_false_ok if {
	count(violation) == 0 with input as pod([{"name": "a", "securityContext": {"allowPrivilegeEscalation": false}}])
}

# 2. Explicit true → denied
test_explicit_true_denied if {
	count(violation) == 1 with input as pod([{"name": "a", "securityContext": {"allowPrivilegeEscalation": true}}])
}

# 3. Field missing (defaults to true) → denied
test_missing_field_denied if {
	count(violation) == 1 with input as pod([{"name": "a", "securityContext": {}}])
}

# 4. No securityContext at all → denied
test_no_security_context_denied if {
	count(violation) == 1 with input as pod([{"name": "a"}])
}

# 5. Deployment: app OK, init container escalates → 1 violation
test_init_container_in_deployment if {
	inp := {"review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}, "spec": {"template": {"spec": {
		"containers": [{"name": "app", "securityContext": {"allowPrivilegeEscalation": false}}],
		"initContainers": [{"name": "init", "securityContext": {"allowPrivilegeEscalation": true}}],
	}}}}}}
	count(violation) == 1 with input as inp
}

# 6. Valid P03 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P03", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as pod([{"name": "a"}]) with data.inventory as waivers
}
