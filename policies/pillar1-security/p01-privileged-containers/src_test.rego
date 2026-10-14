package k8spgseprivileged

import future.keywords.contains
import future.keywords.if
import future.keywords.in

pod(ctrs) := {"review": {"object": {"kind": "Pod", "metadata": {"name": "t"}, "spec": {"containers": ctrs}}}}

test_privileged_denied if {
	count(violation) == 1 with input as pod([{"name": "a", "securityContext": {"privileged": true}}])
}

test_not_privileged_allowed if {
	count(violation) == 0 with input as pod([{"name": "a", "securityContext": {"privileged": false}}])
}

test_no_security_context_allowed if {
	count(violation) == 0 with input as pod([{"name": "a"}])
}

test_privileged_init_container_in_deployment_denied if {
	inp := {"review": {"object": {"kind": "Deployment", "metadata": {"name": "d"}, "spec": {"template": {"spec": {
		"containers": [{"name": "app"}],
		"initContainers": [{"name": "init", "securityContext": {"privileged": true}}],
	}}}}}}
	count(violation) == 1 with input as inp
}
