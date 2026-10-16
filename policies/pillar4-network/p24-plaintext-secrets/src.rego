package k8spgseplaintextsecrets

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P24"

# Rule 24: no inline env values whose NAME looks like a secret.
# valueFrom (secretKeyRef etc.) is fine; the message never prints the value itself.
violation contains {"msg": msg} if {
	not waived
	some c in containers
	some e in c.env
	object.get(e, "value", "") != ""
	looks_secret(e.name)
	msg := sprintf("[P24] container <%v> in %v <%v> sets env <%v> as plain text; use valueFrom.secretKeyRef instead", [c.name, input.review.object.kind, obj_name, e.name])
}

# Keyword must be a WHOLE word, with words split by _ - or .
looks_secret(name) if {
	regex.match(pattern, name)
}

pattern := sprintf("(?i)(^|[_.-])(%s)([_.-]|$)", [concat("|", keywords)])

keywords := object.get(
	object.get(input, "parameters", {}), "secretKeywords",
	["password", "passwd", "pwd", "secret", "token", "key", "apikey", "credential", "credentials"],
)

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
