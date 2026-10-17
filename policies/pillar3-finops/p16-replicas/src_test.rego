package k8spgsereplicas

import future.keywords.contains
import future.keywords.if
import future.keywords.in

tparams := {"minReplicas": 2, "maxReplicasWithoutHpa": 10}

dep(spec) := {
	"parameters": tparams,
	"review": {"object": {
		"kind": "Deployment",
		"metadata": {"name": "web", "namespace": "demo"},
		"spec": spec,
	}},
}

hpa(target, hpa_min) := {"namespace": {"demo": {"autoscaling/v2": {"HorizontalPodAutoscaler": {"h1": {
	"metadata": {"name": "web-hpa"},
	"spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": target}, "minReplicas": hpa_min, "maxReplicas": 20},
}}}}}}

# --- without an HPA ---

# 1. 2 replicas → allowed
test_two_replicas_ok if {
	count(violation) == 0 with input as dep({"replicas": 2}) with data.inventory as {}
}

# 2. 1 replica → flagged
test_one_replica_flagged if {
	count(violation) == 1 with input as dep({"replicas": 1}) with data.inventory as {}
}

# 3. replicas omitted (= 1) → flagged
test_replicas_omitted_flagged if {
	count(violation) == 1 with input as dep({}) with data.inventory as {}
}

# 4. 10 replicas (exactly the max) → allowed
test_at_max_ok if {
	count(violation) == 0 with input as dep({"replicas": 10}) with data.inventory as {}
}

# 5. 20 replicas, no HPA → flagged
test_over_max_no_hpa_flagged if {
	count(violation) == 1 with input as dep({"replicas": 20}) with data.inventory as {}
}

# --- with an HPA ---

# 6. 20 replicas WITH an HPA (min 2) → allowed
test_over_max_with_hpa_ok if {
	count(violation) == 0 with input as dep({"replicas": 20}) with data.inventory as hpa("web", 2)
}

# 7. replicas omitted, HPA min 3 → allowed (the HPA decides the count)
test_omitted_with_hpa_ok if {
	count(violation) == 0 with input as dep({}) with data.inventory as hpa("web", 3)
}

# 8. HPA with minReplicas 1 → flagged (could scale down to a single pod)
test_hpa_min_one_flagged if {
	count(violation) == 1 with input as dep({}) with data.inventory as hpa("web", 1)
}

# 9. HPA targets a DIFFERENT Deployment → treated as no HPA → 20 replicas flagged
test_hpa_other_target_flagged if {
	count(violation) == 1 with input as dep({"replicas": 20}) with data.inventory as hpa("api", 2)
}

# --- parameters, other kinds, waiver ---

# 10. Constraint raises the minimum to 3 → 2 replicas now flagged
test_custom_min if {
	inp := object.union(dep({"replicas": 2}), {"parameters": {"minReplicas": 3, "maxReplicasWithoutHpa": 10}})
	count(violation) == 1 with input as inp with data.inventory as {}
}

# 11. Not a Deployment → ignored
test_statefulset_ignored if {
	inp := {"parameters": tparams, "review": {"object": {"kind": "StatefulSet", "metadata": {"name": "db", "namespace": "demo"}, "spec": {"replicas": 1}}}}
	count(violation) == 0 with input as inp with data.inventory as {}
}

# 12. Valid P16 waiver → exempt
test_valid_waiver_exempts if {
	inv := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P16", "namespace": "demo", "namePrefix": "web",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as dep({"replicas": 1}) with data.inventory as inv
}
