package k8spgsenolatesttag

import future.keywords.contains
import future.keywords.if
import future.keywords.in

pod(img) := {"review": {"object": {"kind": "Pod", "metadata": {"name": "t"}, "spec": {"containers": [{"name": "a", "image": img}]}}}}

test_latest_denied if count(violation) == 1 with input as pod("nginx:latest")

test_no_tag_denied if count(violation) == 1 with input as pod("nginx")

test_registry_port_no_tag_denied if count(violation) == 1 with input as pod("myreg:5000/team/app")

test_pinned_tag_allowed if count(violation) == 0 with input as pod("nginx:1.27.0")

test_ecr_pinned_allowed if count(violation) == 0 with input as pod("123456789012.dkr.ecr.ap-south-1.amazonaws.com/app:v1.2.3")

test_digest_allowed if count(violation) == 0 with input as pod("nginx@sha256:abc123")

# --- waiver tests ---
dep(ns, name) := {"review": {"object": {"kind": "Deployment", "metadata": {"name": name, "namespace": ns}, "spec": {"template": {"spec": {"containers": [{"name": "a", "image": "nginx:latest"}]}}}}}}

waivers(list) := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {w.metadata.name: w | some w in list}}}}

waiver(name, rule, ns, prefix, expires) := {"metadata": {"name": name}, "spec": {"rule": rule, "namespace": ns, "namePrefix": prefix, "expiresAt": expires}}

test_valid_waiver_suppresses if {
	count(violation) == 0 with input as dep("legacy", "old-app")
		with data.inventory as waivers([waiver("w1", "P09", "legacy", "old-", "2099-01-01T00:00:00Z")])
}

test_expired_waiver_ignored if {
	count(violation) == 1 with input as dep("legacy", "old-app")
		with data.inventory as waivers([waiver("w1", "P09", "legacy", "old-", "2020-01-01T00:00:00Z")])
}

test_waiver_for_other_rule_ignored if {
	count(violation) == 1 with input as dep("legacy", "old-app")
		with data.inventory as waivers([waiver("w1", "P08", "legacy", "", "2099-01-01T00:00:00Z")])
}

test_waiver_for_other_namespace_ignored if {
	count(violation) == 1 with input as dep("prod", "old-app")
		with data.inventory as waivers([waiver("w1", "P09", "legacy", "", "2099-01-01T00:00:00Z")])
}

test_waiver_prefix_mismatch_ignored if {
	count(violation) == 1 with input as dep("legacy", "new-app")
		with data.inventory as waivers([waiver("w1", "P09", "legacy", "old-", "2099-01-01T00:00:00Z")])
}

test_generatename_pod_still_checked if {
	inp := {"review": {"namespace": "demo", "object": {"kind": "Pod", "metadata": {"generateName": "web-abc-"}, "spec": {"containers": [{"name": "a", "image": "nginx:latest"}]}}}}
	count(violation) == 1 with input as inp
}
