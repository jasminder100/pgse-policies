package k8spgseannotations

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P18"

annotations := object.get(input.review.object.metadata, "annotations", {})

# 18a: required annotations must be present and non-empty
violation contains {"msg": msg} if {
	not waived
	not controller_pod
	count(missing) > 0
	msg := sprintf("[P18] %v <%v> is missing required annotations %v", [input.review.object.kind, obj_name, sort(missing)])
}

# 18b: repository-url must be a real https:// link
violation contains {"msg": msg} if {
	not waived
	not controller_pod
	url := object.get(annotations, "repository-url", "")
	url != ""
	not startswith(url, "https://")
	msg := sprintf("[P18] %v <%v> has repository-url <%v>; it must be an https:// link to the source repository", [input.review.object.kind, obj_name, url])
}

missing contains a if {
	some a in required_annotations
	object.get(annotations, a, "") == ""
}

required_annotations := object.get(
	object.get(input, "parameters", {}), "annotations",
	["app.kubernetes.io/managed-by", "repository-url"],
)

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
