package k8spgsenonroot

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Helper: build a Pod with a pod-level securityContext and some containers
pod(psc, ctrs) := {"review": {"object": {
	"kind": "Pod",
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": {"securityContext": psc, "containers": ctrs},
}}}

# 1. Set correctly at POD level → allowed
test_pod_level_ok if {
	count(violation) == 0 with input as pod({"runAsNonRoot": true, "runAsUser": 101}, [{"name": "a"}])
}

# 2. Set correctly at CONTAINER level → allowed
test_container_level_ok if {
	count(violation) == 0 with input as pod({}, [{"name": "a", "securityContext": {"runAsNonRoot": true, "runAsUser": 101}}])
}

# 3. Nothing set at all → both violations
test_nothing_set_denied if {
	count(violation) == 2 with input as pod({}, [{"name": "a"}])
}

# 4. runAsNonRoot true but UID 0 → 1 violation (the UID one)
test_uid_zero_denied if {
	count(violation) == 1 with input as pod({"runAsNonRoot": true, "runAsUser": 0}, [{"name": "a"}])
}

# 5. Pod level OK, but container OVERRIDES runAsUser to 0 → 1 violation
test_container_overrides_uid_to_root if {
	count(violation) == 1 with input as pod({"runAsNonRoot": true, "runAsUser": 101}, [{"name": "a", "securityContext": {"runAsUser": 0}}])
}

# 6. Pod level OK, but container OVERRIDES runAsNonRoot to false → 1 violation
test_container_overrides_nonroot_false if {
	count(violation) == 1 with input as pod({"runAsNonRoot": true, "runAsUser": 101}, [{"name": "a", "securityContext": {"runAsNonRoot": false}}])
}

# 7. Deployment: app container fine, but an INIT container runs as root → 1 violation
test_init_container_root_in_deployment if {
	inp := {"review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}, "spec": {"template": {"spec": {
		"securityContext": {"runAsNonRoot": true, "runAsUser": 101},
		"containers": [{"name": "app"}],
		"initContainers": [{"name": "init", "securityContext": {"runAsUser": 0}}],
	}}}}}}
	count(violation) == 1 with input as inp
}

# 8. A valid P02 waiver for this pod → no violations
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P02", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as pod({}, [{"name": "a"}]) with data.inventory as waivers
}
