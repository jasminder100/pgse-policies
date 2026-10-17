package k8spgsedefaultdeny

import future.keywords.contains
import future.keywords.if
import future.keywords.in

ns_obj(name) := {"review": {"object": {"kind": "Namespace", "metadata": {"name": name}}}}

netpol(ns, spec) := {"namespace": {ns: {"networking.k8s.io/v1": {"NetworkPolicy": {"p1": {"spec": spec}}}}}}

deny_spec := {"podSelector": {}, "policyTypes": ["Ingress"]}

# 1. Proper default-deny ingress → allowed
test_default_deny_ok if {
	count(violation) == 0 with input as ns_obj("demo") with data.inventory as netpol("demo", deny_spec)
}

# 2. No NetworkPolicy at all → flagged
test_none_flagged if {
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as {}
}

# 3. Selects only SOME pods → flagged
test_partial_selector_flagged if {
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as netpol("demo", {"podSelector": {"matchLabels": {"app": "web"}}, "policyTypes": ["Ingress"]})
}

# 4. ingress: [{}] means ALLOW ALL → flagged
test_allow_all_flagged if {
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as netpol("demo", {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{}]})
}

# 5. policyTypes omitted, no rules → Kubernetes treats it as Ingress → allowed
test_policytypes_omitted_ok if {
	count(violation) == 0 with input as ns_obj("demo") with data.inventory as netpol("demo", {"podSelector": {}})
}

# 6. Egress-only policy → incoming still open → flagged
test_egress_only_flagged if {
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as netpol("demo", {"podSelector": {}, "policyTypes": ["Egress"]})
}

# 7. Deny-all for BOTH directions → allowed
test_deny_both_ok if {
	count(violation) == 0 with input as ns_obj("demo") with data.inventory as netpol("demo", {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})
}

# 8. Default-deny exists, but in ANOTHER namespace → flagged
test_other_namespace_flagged if {
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as netpol("other", deny_spec)
}

# 9. Not a Namespace → ignored
test_non_namespace_ignored if {
	count(violation) == 0 with input as {"review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}}}} with data.inventory as {}
}

# 10. Valid P21 waiver → exempt
test_valid_waiver_exempts if {
	inv := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {"rule": "P21", "namespace": "demo", "expiresAt": "2099-01-01T00:00:00Z"}}}}}}
	count(violation) == 0 with input as ns_obj("demo") with data.inventory as inv
}
