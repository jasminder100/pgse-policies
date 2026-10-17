package k8spgseownershiplabels

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P14"

# Rule 14: owner, team and cost-center labels must be present and non-empty.
# Pods created by a controller are skipped: their labels come from the workload's template.
violation contains {"msg": msg} if {
	not waived
	not controller_pod
	count(missing) > 0
	msg := sprintf("[P14] %v <%v> is missing required labels %v", [input.review.object.kind, obj_name, sort(missing)])
}

labels := object.get(input.review.object.metadata, "labels", {})

missing contains l if {
	some l in required_labels
	object.get(labels, l, "") == ""
}

required_labels := object.get(object.get(input, "parameters", {}), "labels", ["owner", "team", "cost-center"])

controller_pod if {
	input.review.object.kind == "Pod"
	count(object.get(input.review.object.metadata, "ownerReferences", [])) > 0
}

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
