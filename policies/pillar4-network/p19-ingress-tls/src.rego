package k8spgseingresstls

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P19"

ing := input.review.object if input.review.object.kind == "Ingress"

tls := object.get(ing.spec, "tls", [])

# 19a: no tls block at all → plain HTTP only
violation contains {"msg": msg} if {
	not waived
	count(tls) == 0
	msg := sprintf("[P19] Ingress <%v> has no tls block; HTTP services must be exposed over TLS", [obj_name])
}

# 19b: a tls entry without a certificate Secret
violation contains {"msg": msg} if {
	not waived
	some i, t in tls
	object.get(t, "secretName", "") == ""
	msg := sprintf("[P19] Ingress <%v> tls entry %v has no secretName (no certificate referenced)", [obj_name, i])
}

# 19c: a routed host not covered by any tls.hosts entry → that host is still plain HTTP
violation contains {"msg": msg} if {
	not waived
	count(tls) > 0
	some r in object.get(ing.spec, "rules", [])
	h := r.host
	not covered(h)
	msg := sprintf("[P19] Ingress <%v> routes host <%v> without TLS; add it to a tls.hosts entry", [obj_name, h])
}

# Exact match
covered(h) if {
	some t in tls
	some th in object.get(t, "hosts", [])
	th == h
}

# Wildcard: *.example.com covers app.example.com, but NOT a.b.example.com
covered(h) if {
	some t in tls
	some th in object.get(t, "hosts", [])
	startswith(th, "*.")
	suffix := substring(th, 1, -1)
	endswith(h, suffix)
	not contains(trim_suffix(h, suffix), ".")
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
