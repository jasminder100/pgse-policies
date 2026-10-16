package k8spgseprobes

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P12"

# Rule 12: every long-running container needs a working liveness AND readiness probe.
# Only spec.containers: Kubernetes doesn't allow these probes on init/ephemeral containers.
violation contains {"msg": msg} if {
	not waived
	not job_pod
	some c in pod_spec.containers
	some probe in {"livenessProbe", "readinessProbe"}
	not valid_probe(object.get(c, probe, {}))
	msg := sprintf("[P12] container <%v> in %v <%v> must define a %v with httpGet, tcpSocket, exec or grpc", [c.name, input.review.object.kind, obj_name, probe])
}

# A probe counts only if it actually checks something
valid_probe(p) if {
	some handler in {"httpGet", "tcpSocket", "exec", "grpc"}
	p[handler]
}

# Pods created by a Job run once and exit, so probes don't apply
job_pod if {
	some o in input.review.object.metadata.ownerReferences
	o.kind == "Job"
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
