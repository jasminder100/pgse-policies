package k8spgsenolbnonprod

import future.keywords.contains
import future.keywords.if
import future.keywords.in

svc(type) := {"review": {"object": {
	"kind": "Service",
	"metadata": {"name": "t", "namespace": "dev-sandbox"},
	"spec": {"type": type, "ports": [{"port": 80}]},
}}}

# 1. LoadBalancer → denied (the constraint limits this to non-prod)
test_loadbalancer_denied if {
	count(violation) == 1 with input as svc("LoadBalancer")
}

# 2. ClusterIP → allowed
test_clusterip_ok if {
	count(violation) == 0 with input as svc("ClusterIP")
}

# 3. No type set (defaults to ClusterIP) → allowed
test_default_type_ok if {
	inp := {"review": {"object": {"kind": "Service", "metadata": {"name": "t", "namespace": "dev-sandbox"}, "spec": {"ports": [{"port": 80}]}}}}
	count(violation) == 0 with input as inp
}

# 4. Not a Service → ignored
test_non_service_ignored if {
	count(violation) == 0 with input as {"review": {"object": {"kind": "Pod", "metadata": {"name": "p", "namespace": "dev-sandbox"}, "spec": {"containers": [{"name": "a"}]}}}}
}

# 5. Valid P20 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P20", "namespace": "dev-sandbox", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as svc("LoadBalancer") with data.inventory as waivers
}
