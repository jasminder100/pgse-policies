package k8spgseplaintextsecrets

import future.keywords.contains
import future.keywords.if
import future.keywords.in

ctr_env(env) := {"review": {"object": {
	"kind": "Pod",
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": {"containers": [{"name": "a", "env": env}]},
}}}

# 1. DB_PASSWORD as plain text → denied
test_plain_password_denied if {
	count(violation) == 1 with input as ctr_env([{"name": "DB_PASSWORD", "value": "SuperSecret123"}])
}

# 2. DB_PASSWORD via secretKeyRef → allowed
test_secret_ref_ok if {
	count(violation) == 0 with input as ctr_env([{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db-creds", "key": "password"}}}])
}

# 3. API_KEY as plain text → denied
test_api_key_denied if {
	count(violation) == 1 with input as ctr_env([{"name": "API_KEY", "value": "abc123"}])
}

# 4. MONKEY_MODE: "key" inside a word → NOT flagged (no false positive)
test_monkey_not_flagged if {
	count(violation) == 0 with input as ctr_env([{"name": "MONKEY_MODE", "value": "on"}])
}

# 5. KEYBOARD_LAYOUT → NOT flagged
test_keyboard_not_flagged if {
	count(violation) == 0 with input as ctr_env([{"name": "KEYBOARD_LAYOUT", "value": "us"}])
}

# 6. Ordinary variable → allowed
test_normal_env_ok if {
	count(violation) == 0 with input as ctr_env([{"name": "LOG_LEVEL", "value": "info"}])
}

# 7. Lowercase with dashes (github-token) → denied
test_lowercase_dash_denied if {
	count(violation) == 1 with input as ctr_env([{"name": "github-token", "value": "ghp_xxx"}])
}

# 8. Empty value leaks nothing → allowed
test_empty_value_ok if {
	count(violation) == 0 with input as ctr_env([{"name": "DB_PASSWORD", "value": ""}])
}

# 9. Two plaintext secrets → 2 violations
test_two_secrets if {
	count(violation) == 2 with input as ctr_env([
		{"name": "DB_PASSWORD", "value": "x"},
		{"name": "AUTH_TOKEN", "value": "y"},
		{"name": "LOG_LEVEL", "value": "info"},
	])
}

# 10. The message must NOT contain the secret value
test_message_hides_value if {
	some v in violation with input as ctr_env([{"name": "DB_PASSWORD", "value": "SuperSecret123"}])
	not contains(v.msg, "SuperSecret123")
}

# 11. Init container in a Deployment → checked too
test_init_container_checked if {
	inp := {"review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}, "spec": {"template": {"spec": {
		"containers": [{"name": "app"}],
		"initContainers": [{"name": "init", "env": [{"name": "SECRET", "value": "s"}]}],
	}}}}}}
	count(violation) == 1 with input as inp
}

# 12. Valid P24 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P24", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as ctr_env([{"name": "DB_PASSWORD", "value": "x"}]) with data.inventory as waivers
}
