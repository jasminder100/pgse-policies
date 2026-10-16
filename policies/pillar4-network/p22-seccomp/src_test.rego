package k8spgseseccomp

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rd := {"seccompProfile": {"type": "RuntimeDefault"}}

pod(psc, ctrs) := {"review": {"object": {
	"kind": "Pod",
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": {"securityContext": psc, "containers": ctrs},
}}}

# 1. RuntimeDefault at pod level → allowed
test_pod_level_ok if {
	count(violation) == 0 with input as pod(rd, [{"name": "a"}])
}

# 2. RuntimeDefault at container level → allowed
test_container_level_ok if {
	count(violation) == 0 with input as pod({}, [{"name": "a", "securityContext": rd}])
}

# 3. Nothing set (= Unconfined) → denied
test_missing_denied if {
	count(violation) == 1 with input as pod({}, [{"name": "a"}])
}

# 4. Explicit Unconfined at pod level → denied
test_unconfined_denied if {
	count(violation) == 1 with input as pod({"seccompProfile": {"type": "Unconfined"}}, [{"name": "a"}])
}

# 5. Pod says RuntimeDefault, container OVERRIDES to Unconfined → denied
test_container_overrides_to_unconfined if {
	count(violation) == 1 with input as pod(rd, [{"name": "a", "securityContext": {"seccompProfile": {"type": "Unconfined"}}}])
}

# 6. Localhost (custom profile) → allowed by default
test_localhost_ok if {
	count(violation) == 0 with input as pod({"seccompProfile": {"type": "Localhost", "localhostProfile": "profiles/app.json"}}, [{"name": "a"}])
}

# 7. Pod-level RuntimeDefault covers init containers too → allowed
test_pod_level_covers_init if {
	inp := {"review": {"object": {"kind": "Pod", "metadata": {"name": "t", "namespace": "demo"}, "spec": {
		"securityContext": rd,
		"containers": [{"name": "a"}],
		"initContainers": [{"name": "init"}],
	}}}}
	count(violation) == 0 with input as inp
}

# 8. Constraint narrows the list to RuntimeDefault only → Localhost now denied
test_param_narrows_list if {
	inp := object.union(pod({"seccompProfile": {"type": "Localhost"}}, [{"name": "a"}]), {"parameters": {"allowedProfileTypes": ["RuntimeDefault"]}})
	count(violation) == 1 with input as inp
}

# 9. Valid P22 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P22", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as pod({}, [{"name": "a"}]) with data.inventory as waivers
}
