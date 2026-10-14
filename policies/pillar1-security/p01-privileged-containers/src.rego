package k8spgseprivileged

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Rule 1: Prohibit privileged containers (containers, initContainers, ephemeralContainers)
violation contains {"msg": msg} if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("[P01] container <%v> in %v <%v> must not run privileged (securityContext.privileged: true)", [c.name, input.review.object.kind, input.review.object.metadata.name])
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
