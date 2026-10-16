package k8spgsehostports

import future.keywords.contains
import future.keywords.if
import future.keywords.in

tparams := {"minHostPort": 1024, "sensitivePorts": [2375, 2376, 2379, 2380, 6443, 10250, 10255]}

pod(ports) := {
	"parameters": tparams,
	"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "t", "namespace": "demo"},
		"spec": {"containers": [{"name": "a", "ports": ports}]},
	}},
}

# 1. No hostPort, just containerPort → allowed (port stays inside the pod)
test_container_port_only_ok if {
	count(violation) == 0 with input as pod([{"containerPort": 22}])
}

# 2. hostPort 80 (below 1024) → denied
test_low_host_port_denied if {
	count(violation) == 1 with input as pod([{"containerPort": 80, "hostPort": 80}])
}

# 3. hostPort 8080 (high, not sensitive) → allowed
test_high_host_port_ok if {
	count(violation) == 0 with input as pod([{"containerPort": 8080, "hostPort": 8080}])
}

# 4. hostPort 10250 (kubelet) → denied
test_sensitive_port_denied if {
	count(violation) == 1 with input as pod([{"containerPort": 10250, "hostPort": 10250}])
}

# 5. hostPort 22: below 1024 AND would be sensitive → reported ONCE, not twice
test_no_double_count if {
	inp := object.union(pod([{"containerPort": 22, "hostPort": 22}]), {"parameters": {"minHostPort": 1024, "sensitivePorts": [22]}})
	count(violation) == 1 with input as inp
}

# 6. Two bad host ports on one container → 2 violations
test_two_bad_ports if {
	count(violation) == 2 with input as pod([
		{"containerPort": 443, "hostPort": 443},
		{"containerPort": 6443, "hostPort": 6443},
	])
}

# 7. hostPort 0 means "none" → allowed
test_host_port_zero_ok if {
	count(violation) == 0 with input as pod([{"containerPort": 80, "hostPort": 0}])
}

# 8. Init container in a Deployment binding hostPort 443 → denied
test_init_container_host_port if {
	inp := {"parameters": tparams, "review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}, "spec": {"template": {"spec": {
		"containers": [{"name": "app"}],
		"initContainers": [{"name": "init", "ports": [{"containerPort": 443, "hostPort": 443}]}],
	}}}}}}
	count(violation) == 1 with input as inp
}

# 9. Valid P23 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P23", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as pod([{"containerPort": 80, "hostPort": 80}]) with data.inventory as waivers
}
