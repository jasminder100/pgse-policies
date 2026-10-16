package k8spgsehostports

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P23"

# Rule 23a: no hostPort below the minimum (privileged ports)
violation contains {"msg": msg} if {
	not waived
	some c in containers
	some p in c.ports
	hp := object.get(p, "hostPort", 0)
	hp > 0
	hp < min_port
	msg := sprintf("[P23] container <%v> in %v <%v> binds hostPort %v; host ports below %v are not allowed", [c.name, input.review.object.kind, obj_name, hp, min_port])
}

# Rule 23b: no hostPort on a sensitive admin port (checked only at/above the minimum, to avoid double-counting)
violation contains {"msg": msg} if {
	not waived
	some c in containers
	some p in c.ports
	hp := object.get(p, "hostPort", 0)
	hp >= min_port
	hp in sensitive_ports
	msg := sprintf("[P23] container <%v> in %v <%v> binds hostPort %v, a sensitive administrative port", [c.name, input.review.object.kind, obj_name, hp])
}

params := object.get(input, "parameters", {})

min_port := object.get(params, "minHostPort", 1024)

sensitive_ports := object.get(params, "sensitivePorts", [])

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
