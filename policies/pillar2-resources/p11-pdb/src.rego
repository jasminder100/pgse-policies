package k8spgsepdb

import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

rule_id := "P11"

# Rule 11: production Deployments/StatefulSets need a PDB that selects their pods
# and actually protects them. Referential (PDBs from the synced cache); meant for warn/audit.
violation contains {"msg": msg} if {
	not waived
	input.review.object.kind in {"Deployment", "StatefulSet"}
	pod_labels := object.get(object.get(input.review.object.spec.template, "metadata", {}), "labels", {})
	not has_protecting_pdb(obj_namespace, pod_labels)
	msg := sprintf("[P11] %v <%v> has no PodDisruptionBudget selecting its pods (with minAvailable > 0 or maxUnavailable < 100%%)", [input.review.object.kind, obj_name])
}

has_protecting_pdb(ns, pod_labels) if {
	some p in data.inventory.namespace[ns]["policy/v1"].PodDisruptionBudget
	selector_matches(object.get(p.spec, "selector", {}), pod_labels)
	protects(p.spec)
}

# Kubernetes label-selector semantics. An empty selector {} selects every pod.
selector_matches(sel, labels) if {
	every k, v in object.get(sel, "matchLabels", {}) {
		labels[k] == v
	}
	every e in object.get(sel, "matchExpressions", []) {
		expr_matches(e, labels)
	}
}

expr_matches(e, labels) if {
	e.operator == "In"
	labels[e.key] in e.values
}

expr_matches(e, labels) if {
	e.operator == "NotIn"
	not labels[e.key] in e.values
}

expr_matches(e, labels) if {
	e.operator == "Exists"
	labels[e.key]
}

expr_matches(e, labels) if {
	e.operator == "DoesNotExist"
	not labels[e.key]
}

# A PDB that allows ALL pods to be evicted protects nothing
protects(spec) if {
	m := spec.minAvailable
	not m in {0, "0", "0%"}
}

protects(spec) if {
	u := spec.maxUnavailable
	u != "100%"
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
