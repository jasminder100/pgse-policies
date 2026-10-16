package k8spgsehostnamespaces

import future.keywords.contains
import future.keywords.if
import future.keywords.in

pod(spec) := {"review": {"object": {
	"kind": "Pod",
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": object.union({"containers": [{"name": "a"}]}, spec),
}}}

# 1. None set (safe default) → allowed
test_defaults_ok if {
	count(violation) == 0 with input as pod({})
}

# 2. Explicitly false → allowed
test_explicit_false_ok if {
	count(violation) == 0 with input as pod({"hostNetwork": false, "hostPID": false, "hostIPC": false})
}

# 3. hostNetwork true → 1 violation
test_host_network_denied if {
	count(violation) == 1 with input as pod({"hostNetwork": true})
}

# 4. All three true → 3 violations (one per field)
test_all_three_denied if {
	count(violation) == 3 with input as pod({"hostNetwork": true, "hostPID": true, "hostIPC": true})
}

# 5. Deployment with hostPID → 1 violation
test_deployment_host_pid if {
	inp := {"review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}, "spec": {"template": {"spec": {
		"hostPID": true,
		"containers": [{"name": "app"}],
	}}}}}}
	count(violation) == 1 with input as inp
}

# 6. CronJob (different nesting path) with hostIPC → 1 violation
test_cronjob_host_ipc if {
	inp := {"review": {"object": {"kind": "CronJob", "metadata": {"name": "c", "namespace": "demo"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {
		"hostIPC": true,
		"containers": [{"name": "job"}],
	}}}}}}}}
	count(violation) == 1 with input as inp
}

# 7. Valid P04 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P04", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as pod({"hostNetwork": true}) with data.inventory as waivers
}
