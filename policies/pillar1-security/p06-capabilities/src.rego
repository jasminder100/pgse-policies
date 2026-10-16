package k8spgsecapabilities

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P06"

# Rule 6a: every container must drop ALL capabilities
violation contains {"msg": msg} if {
	not waived
	some c in containers
	not drops_all(c)
	msg := sprintf("[P06] container <%v> in %v <%v> must set securityContext.capabilities.drop: [\"ALL\"]", [c.name, input.review.object.kind, obj_name])
}

# Rule 6b: anything added back must be on the allowed list (from the constraint's parameters)
violation contains {"msg": msg} if {
	not waived
	some c in containers
	some cap in c.securityContext.capabilities.add
	not allowed_cap(cap)
	msg := sprintf("[P06] container <%v> in %v <%v> adds capability <%v>, which is not in the allowed list %v", [c.name, input.review.object.kind, obj_name, cap, allowed_list])
}

drops_all(c) if {
	some d in c.securityContext.capabilities.drop
	normalize(d) == "ALL"
}

allowed_list := object.get(object.get(input, "parameters", {}), "allowedCapabilities", [])

allowed_cap(cap) if {
	some a in allowed_list
	normalize(a) == normalize(cap)
}

# "net_bind_service", "NET_BIND_SERVICE" and "CAP_NET_BIND_SERVICE" all mean the same thing
normalize(x) := trim_prefix(upper(x), "CAP_")

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
