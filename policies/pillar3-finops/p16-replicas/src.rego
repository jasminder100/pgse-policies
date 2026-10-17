package k8spgsereplicas

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P16"

is_deployment if input.review.object.kind == "Deployment"

# Omitted replicas means 1 in Kubernetes
replicas := object.get(input.review.object.spec, "replicas", 1)

# 16a: no HPA → replicas must be at least the minimum
violation contains {"msg": msg} if {
	not waived
	is_deployment
	not has_hpa
	replicas < min_replicas
	msg := sprintf("[P16] Deployment <%v> has %v replica(s); production needs at least %v", [obj_name, replicas, min_replicas])
}

# 16b: HPA present → the HPA must not scale below the minimum
violation contains {"msg": msg} if {
	not waived
	is_deployment
	some h in hpas_for_me
	hpa_min := object.get(h.spec, "minReplicas", 1)
	hpa_min < min_replicas
	msg := sprintf("[P16] HPA <%v> for Deployment <%v> has minReplicas %v; production needs at least %v", [h.metadata.name, obj_name, hpa_min, min_replicas])
}

# 16c: no HPA → replicas must not exceed the maximum
violation contains {"msg": msg} if {
	not waived
	is_deployment
	not has_hpa
	replicas > max_without_hpa
	msg := sprintf("[P16] Deployment <%v> has %v replicas, above %v, with no HorizontalPodAutoscaler; use an HPA for large replica counts", [obj_name, replicas, max_without_hpa])
}

# HPAs in the same namespace that target THIS Deployment by kind + name
hpas_for_me contains h if {
	some h in data.inventory.namespace[obj_namespace]["autoscaling/v2"].HorizontalPodAutoscaler
	h.spec.scaleTargetRef.kind == "Deployment"
	h.spec.scaleTargetRef.name == obj_name
}

has_hpa if count(hpas_for_me) > 0

params := object.get(input, "parameters", {})

min_replicas := object.get(params, "minReplicas", 2)

max_without_hpa := object.get(params, "maxReplicasWithoutHpa", 10)

# --- shared helper: find the pod spec in any workload kind ---
pod_spec := input.review.object.spec if input.review.object.kind == "Pod"
pod_spec := input.review.object.spec.jobTemplate.spec.template.spec if input.review.object.kind == "CronJob"
pod_spec := input.review.object.spec.template.spec if {
	not input.review.object.kind in {"Pod", "CronJob"}
}

containers contains c if some c in pod_spec.containers
containers contains c if some c in pod_spec.initContainers
containers contains c if some c in pod_spec.ephemeralContainers

# --- shared helper: object identity (Pods created by controllers only have generateName at admission) ---
obj_name := n if n := input.review.object.metadata.name

obj_name := n if {
	not input.review.object.metadata.name
	n := input.review.object.metadata.generateName
}

obj_namespace := ns if ns := input.review.object.metadata.namespace

obj_namespace := ns if {
	not input.review.object.metadata.namespace
	ns := input.review.namespace
}

# --- shared helper: time-bound waivers ---
# PolicyWaiver objects (pgse.io/v1alpha1, cluster-scoped) are synced by Gatekeeper into data.inventory.
# A waiver matches when rule + namespace match, the object name starts with namePrefix ("" = whole
# namespace), and expiresAt is still in the future. Once expired, the violation comes back automatically.
waived if {
	some w in data.inventory.cluster["pgse.io/v1alpha1"].PolicyWaiver
	w.spec.rule == rule_id
	w.spec.namespace == obj_namespace
	startswith(obj_name, object.get(w.spec, "namePrefix", ""))
	time.parse_rfc3339_ns(w.spec.expiresAt) > time.now_ns()
}
