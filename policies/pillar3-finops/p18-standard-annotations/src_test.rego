package k8spgseannotations

import future.keywords.contains
import future.keywords.if
import future.keywords.in

good := {
	"app.kubernetes.io/managed-by": "github-actions",
	"repository-url": "https://github.com/jasminder100/pgse-sample-app",
}

obj(kind, ann) := {"review": {"object": {
	"kind": kind,
	"metadata": {"name": "t", "namespace": "demo", "annotations": ann},
	"spec": {},
}}}

# 1. Both annotations, https URL → allowed
test_good_ok if {
	count(violation) == 0 with input as obj("Deployment", good)
}

# 2. No annotations → ONE violation listing both
test_none_one_violation if {
	count(violation) == 1 with input as obj("Deployment", {})
}

# 3. Missing repository-url only → 1 violation naming it
test_missing_repo_url if {
	vs := violation with input as obj("Deployment", {"app.kubernetes.io/managed-by": "github-actions"})
	count(vs) == 1
	some v in vs
	contains(v.msg, "repository-url")
}

# 4. http:// (not https) → denied
test_http_url_denied if {
	count(violation) == 1 with input as obj("Deployment", object.union(good, {"repository-url": "http://github.com/x/y"}))
}

# 5. Placeholder text instead of a URL → denied
test_placeholder_url_denied if {
	count(violation) == 1 with input as obj("Deployment", object.union(good, {"repository-url": "TODO"}))
}

# 6. Empty managed-by → denied
test_empty_managed_by_denied if {
	count(violation) == 1 with input as obj("Deployment", object.union(good, {"app.kubernetes.io/managed-by": ""}))
}

# 7. Pod created by a controller → skipped
test_controller_pod_skipped if {
	inp := {"review": {"object": {
		"kind": "Pod", "metadata": {
			"name": "web-abc", "namespace": "demo",
			"ownerReferences": [{"kind": "ReplicaSet", "name": "web-123"}],
		},
		"spec": {},
	}}}
	count(violation) == 0 with input as inp
}

# 8. Valid P18 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P18", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as obj("Deployment", {}) with data.inventory as waivers
}
