package k8spgsecapabilities

import future.keywords.contains
import future.keywords.if
import future.keywords.in

params := {"allowedCapabilities": ["NET_BIND_SERVICE"]}

# Helper: a Pod with one container using the given capabilities block
pod(caps) := {
	"parameters": params,
	"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "t", "namespace": "demo"},
		"spec": {"containers": [{"name": "a", "securityContext": {"capabilities": caps}}]},
	}},
}

# 1. Drop ALL, add nothing → allowed
test_drop_all_ok if {
	count(violation) == 0 with input as pod({"drop": ["ALL"]})
}

# 2. No capabilities block at all → 1 violation (doesn't drop ALL)
test_no_caps_denied if {
	inp := {"parameters": params, "review": {"object": {"kind": "Pod", "metadata": {"name": "t", "namespace": "demo"}, "spec": {"containers": [{"name": "a"}]}}}}
	count(violation) == 1 with input as inp
}

# 3. Drops only NET_RAW (not ALL) → 1 violation
test_partial_drop_denied if {
	count(violation) == 1 with input as pod({"drop": ["NET_RAW"]})
}

# 4. Drop ALL + add an allowed capability → allowed
test_add_allowed_ok if {
	count(violation) == 0 with input as pod({"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]})
}

# 5. Drop ALL + add a forbidden capability → 1 violation
test_add_forbidden_denied if {
	count(violation) == 1 with input as pod({"drop": ["ALL"], "add": ["SYS_ADMIN"]})
}

# 6. Drop ALL + add one allowed and two forbidden → 2 violations (one per bad cap)
test_two_forbidden if {
	count(violation) == 2 with input as pod({"drop": ["ALL"], "add": ["NET_BIND_SERVICE", "SYS_ADMIN", "NET_ADMIN"]})
}

# 7. Spelling variants: lowercase "all", "CAP_" prefix → still allowed
test_spelling_variants_ok if {
	count(violation) == 0 with input as pod({"drop": ["all"], "add": ["cap_net_bind_service"]})
}

# 8. Sneaky spelling of a forbidden cap → still caught
test_sneaky_forbidden_caught if {
	count(violation) == 1 with input as pod({"drop": ["ALL"], "add": ["cap_sys_admin"]})
}

# 9. No parameters at all → nothing may be added
test_no_params_nothing_allowed if {
	inp := {"review": {"object": {"kind": "Pod", "metadata": {"name": "t", "namespace": "demo"}, "spec": {"containers": [{"name": "a", "securityContext": {"capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}}}]}}}}
	count(violation) == 1 with input as inp
}

# 10. Valid P06 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P06", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as pod({"add": ["SYS_ADMIN"]}) with data.inventory as waivers
}
