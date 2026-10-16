package k8spgseprobes

import future.keywords.contains
import future.keywords.if
import future.keywords.in

good := {"httpGet": {"path": "/", "port": 8080}}

pod(spec) := {"review": {"object": {
	"kind": "Pod",
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": spec,
}}}

# 1. Both probes present → allowed
test_both_probes_ok if {
	count(violation) == 0 with input as pod({"containers": [{"name": "a", "livenessProbe": good, "readinessProbe": good}]})
}

# 2. Missing liveness → 1 violation
test_missing_liveness if {
	count(violation) == 1 with input as pod({"containers": [{"name": "a", "readinessProbe": good}]})
}

# 3. Missing both → 2 violations
test_missing_both if {
	count(violation) == 2 with input as pod({"containers": [{"name": "a"}]})
}

# 4. Empty probe {} (checks nothing) → 1 violation
test_empty_probe_denied if {
	count(violation) == 1 with input as pod({"containers": [{"name": "a", "livenessProbe": {}, "readinessProbe": good}]})
}

# 5. Probe with only timing settings, no handler → 1 violation
test_probe_without_handler if {
	count(violation) == 1 with input as pod({"containers": [{"name": "a", "livenessProbe": {"periodSeconds": 10}, "readinessProbe": good}]})
}

# 6. tcpSocket and exec are valid handlers too → allowed
test_other_handlers_ok if {
	count(violation) == 0 with input as pod({"containers": [{"name": "a", "livenessProbe": {"tcpSocket": {"port": 8080}}, "readinessProbe": {"exec": {"command": ["true"]}}}]})
}

# 7. Init container without probes is IGNORED → allowed
test_init_container_ignored if {
	count(violation) == 0 with input as pod({
		"containers": [{"name": "a", "livenessProbe": good, "readinessProbe": good}],
		"initContainers": [{"name": "init"}],
	})
}

# 8. Two containers, second missing readiness → 1 violation
test_second_container_missing if {
	count(violation) == 1 with input as pod({"containers": [
		{"name": "a", "livenessProbe": good, "readinessProbe": good},
		{"name": "b", "livenessProbe": good},
	]})
}

# 9. Pod created by a Job → skipped
test_job_pod_skipped if {
	inp := {"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "j", "namespace": "demo", "ownerReferences": [{"kind": "Job", "name": "batch-1"}]},
		"spec": {"containers": [{"name": "a"}]},
	}}}
	count(violation) == 0 with input as inp
}

# 10. Valid P12 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P12", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as pod({"containers": [{"name": "a"}]}) with data.inventory as waivers
}
