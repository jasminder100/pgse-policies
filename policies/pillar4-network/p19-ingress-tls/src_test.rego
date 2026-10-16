package k8spgseingresstls

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_for(h) := {"host": h, "http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "web", "port": {"number": 80}}}}]}}

ingress(spec) := {"review": {"object": {
	"apiVersion": "networking.k8s.io/v1",
	"kind": "Ingress",
	"metadata": {"name": "t", "namespace": "demo"},
	"spec": spec,
}}}

# 1. TLS with a secret, covering the host → allowed
test_tls_ok if {
	count(violation) == 0 with input as ingress({
		"tls": [{"hosts": ["app.example.com"], "secretName": "app-tls"}],
		"rules": [rule_for("app.example.com")],
	})
}

# 2. No tls block → denied
test_no_tls_denied if {
	count(violation) == 1 with input as ingress({"rules": [rule_for("app.example.com")]})
}

# 3. Empty tls list → denied
test_empty_tls_denied if {
	count(violation) == 1 with input as ingress({"tls": [], "rules": [rule_for("app.example.com")]})
}

# 4. tls entry without secretName → denied
test_missing_secret_denied if {
	count(violation) == 1 with input as ingress({
		"tls": [{"hosts": ["app.example.com"]}],
		"rules": [rule_for("app.example.com")],
	})
}

# 5. Two hosts, TLS covers only one → the other is flagged
test_uncovered_host_denied if {
	count(violation) == 1 with input as ingress({
		"tls": [{"hosts": ["app.example.com"], "secretName": "app-tls"}],
		"rules": [rule_for("app.example.com"), rule_for("admin.example.com")],
	})
}

# 6. Wildcard *.example.com covers app.example.com → allowed
test_wildcard_covers_one_level if {
	count(violation) == 0 with input as ingress({
		"tls": [{"hosts": ["*.example.com"], "secretName": "wild-tls"}],
		"rules": [rule_for("app.example.com")],
	})
}

# 7. Wildcard does NOT cover two levels (a.b.example.com) → denied
test_wildcard_not_two_levels if {
	count(violation) == 1 with input as ingress({
		"tls": [{"hosts": ["*.example.com"], "secretName": "wild-tls"}],
		"rules": [rule_for("a.b.example.com")],
	})
}

# 8. Not an Ingress → ignored
test_non_ingress_ignored if {
	count(violation) == 0 with input as {"review": {"object": {"kind": "Pod", "metadata": {"name": "p", "namespace": "demo"}, "spec": {"containers": [{"name": "a"}]}}}}
}

# 9. Valid P19 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P19", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as ingress({"rules": [rule_for("app.example.com")]}) with data.inventory as waivers
}
