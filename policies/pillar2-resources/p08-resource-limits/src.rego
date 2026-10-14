package k8spgseresourcelimits

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Rule 8: every container must set cpu+memory in BOTH requests and limits
required := [["requests", "cpu"], ["requests", "memory"], ["limits", "cpu"], ["limits", "memory"]]

violation contains {"msg": msg} if {
	some c in containers
	some r in required
	not has_value(c, r[0], r[1])
	msg := sprintf("[P08] container <%v> in %v <%v> is missing resources.%v.%v", [c.name, input.review.object.kind, input.review.object.metadata.name, r[0], r[1]])
}

has_value(c, section, res) if {
	v := c.resources[section][res]
	v != ""
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
