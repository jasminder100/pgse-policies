package k8spgseseccomp

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P22"

# Rule 22: every container must run under an allowed seccomp profile.
# Missing = Unconfined (no filter), so it counts as a violation.
violation contains {"msg": msg} if {
	not waived
	some c in containers
	t := effective_type(c)
	not t in allowed_types
	msg := sprintf("[P22] container <%v> in %v <%v> has seccomp profile <%v>; must be one of %v (set securityContext.seccompProfile.type)", [c.name, input.review.object.kind, obj_name, show(t), allowed_types])
}

# Container's seccomp type if set, else the pod's, else null
effective_type(c) := object.get(
	object.get(object.get(c, "securityContext", {}), "seccompProfile", {}), "type",
	object.get(object.get(object.get(pod_spec, "securityContext", {}), "seccompProfile", {}), "type", null),
)

# From the constraint's parameters, with a safe default
allowed_types := object.get(object.get(input, "parameters", {}), "allowedProfileTypes", ["RuntimeDefault", "Localhost"])

# Friendlier message when nothing is set
show(t) := "none (Unconfined)" if t == null
show(t) := t if t != null

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
