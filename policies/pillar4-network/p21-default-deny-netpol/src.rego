package k8spgsedefaultdeny

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P21"

# Rule 21: every Namespace needs a default-deny INGRESS NetworkPolicy.
# Referential: reads NetworkPolicies from Gatekeeper's synced cache. Meant for audit/warn.
violation contains {"msg": msg} if {
	input.review.object.kind == "Namespace"
	ns := input.review.object.metadata.name
	not ns_waived(ns)
	not has_default_deny(ns)
	msg := sprintf("[P21] Namespace <%v> has no default-deny ingress NetworkPolicy (podSelector: {}, policyTypes: [Ingress], no ingress rules)", [ns])
}

has_default_deny(ns) if {
	some p in data.inventory.namespace[ns]["networking.k8s.io/v1"].NetworkPolicy
	selects_all_pods(p.spec)
	governs_ingress(p.spec)
	count(object.get(p.spec, "ingress", [])) == 0
}

# Empty selector ({} or no matchLabels/matchExpressions) selects every pod
selects_all_pods(spec) if {
	sel := object.get(spec, "podSelector", {})
	count(object.get(sel, "matchLabels", {})) == 0
	count(object.get(sel, "matchExpressions", [])) == 0
}

# If policyTypes is omitted, Kubernetes treats the policy as Ingress
governs_ingress(spec) if {
	"Ingress" in object.get(spec, "policyTypes", ["Ingress"])
}

ns_waived(ns) if {
	some w in data.inventory.cluster["pgse.io/v1alpha1"].PolicyWaiver
	w.spec.rule == rule_id
	w.spec.namespace == ns
	time.parse_rfc3339_ns(w.spec.expiresAt) > time.now_ns()
}
