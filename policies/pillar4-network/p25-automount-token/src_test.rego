package k8spgseautomounttoken

import future.keywords.contains
import future.keywords.if
import future.keywords.in

pod(spec) := {"review": {"object": {
	"kind": "Pod",
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": object.union({"containers": [{"name": "a"}]}, spec),
}}}

sa(name, fields) := {"review": {"object": object.union(
	{
		"kind": "ServiceAccount",
		"metadata": {"name": name, "namespace": "demo"},
	},
	fields,
)}}

# --- Workloads ---

# 1. Pod with explicit false → allowed
test_pod_false_ok if {
	count(violation) == 0 with input as pod({"automountServiceAccountToken": false})
}

# 2. Pod with field missing (token IS mounted) → denied
test_pod_missing_denied if {
	count(violation) == 1 with input as pod({})
}

# 3. Pod with explicit true → denied
test_pod_true_denied if {
	count(violation) == 1 with input as pod({"automountServiceAccountToken": true})
}

# 4. Deployment with false in its pod template → allowed
test_deployment_false_ok if {
	inp := {"review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}, "spec": {"template": {"spec": {
		"automountServiceAccountToken": false,
		"containers": [{"name": "app"}],
	}}}}}}
	count(violation) == 0 with input as inp
}

# 5. CronJob (deep nesting) missing the field → denied
test_cronjob_missing_denied if {
	inp := {"review": {"object": {"kind": "CronJob", "metadata": {"name": "c", "namespace": "demo"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "job"}]}}}}}}}}
	count(violation) == 1 with input as inp
}

# --- ServiceAccounts ---

# 6. Custom ServiceAccount with false → allowed
test_sa_false_ok if {
	count(violation) == 0 with input as sa("app-sa", {"automountServiceAccountToken": false})
}

# 7. Custom ServiceAccount missing the field → denied
test_sa_missing_denied if {
	count(violation) == 1 with input as sa("app-sa", {})
}

# 8. The auto-created "default" ServiceAccount → skipped
test_default_sa_skipped if {
	count(violation) == 0 with input as sa("default", {})
}

# --- Waiver ---

# 9. Valid P25 waiver (app genuinely needs the API) → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P25", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as pod({}) with data.inventory as waivers
}
