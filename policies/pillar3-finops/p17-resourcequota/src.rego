package k8spgseresourcequota

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P17"

# Rule 17: every Namespace needs a ResourceQuota capping BOTH cpu and memory.
# Referential: reads ResourceQuotas from Gatekeeper's synced cache (data.inventory).
# Meant for audit/warn: at creation time a namespace's quota cannot exist yet.
violation contains {"msg": msg} if {
	input.review.object.kind == "Namespace"
	ns := input.review.object.metadata.name
	not ns_waived(ns)
	not has_compute_quota(ns)
	msg := sprintf("[P17] Namespace <%v> has no ResourceQuota limiting both CPU and memory", [ns])
}

has_compute_quota(ns) if {
	some q in data.inventory.namespace[ns].v1.ResourceQuota
	hard := object.get(q.spec, "hard", {})
	limits_any(hard, ["cpu", "requests.cpu", "limits.cpu"])
	limits_any(hard, ["memory", "requests.memory", "limits.memory"])
}

limits_any(hard, keys) if {
	some k in keys
	hard[k]
}

# A Namespace has no namespace of its own, so match the waiver against the Namespace's NAME
ns_waived(ns) if {
	some w in data.inventory.cluster["pgse.io/v1alpha1"].PolicyWaiver
	w.spec.rule == rule_id
	w.spec.namespace == ns
	time.parse_rfc3339_ns(w.spec.expiresAt) > time.now_ns()
}
