package k8spgseallowedregistries

import future.keywords.contains
import future.keywords.if
import future.keywords.in

rule_id := "P10"

# Rule 10: every image must come from an approved registry.
violation contains {"msg": msg} if {
	not waived
	some c in containers
	reg := registry_of(c.image)
	not approved(reg)
	msg := sprintf("[P10] container <%v> in %v <%v> uses image <%v> from registry <%v>; allowed registries: %v", [c.name, input.review.object.kind, obj_name, c.image, reg, allowed_registries])
}

# The first path segment is a registry only if it looks like a host (has "." or ":" or is "localhost").
# Otherwise the image is on Docker Hub (e.g. "nginx", "nginxinc/nginx-unprivileged").
registry_of(image) := reg if {
	parts := split(image, "/")
	count(parts) > 1
	first := parts[0]
	looks_like_host(first)
	reg := lower(first)
}

registry_of(image) := "docker.io" if {
	parts := split(image, "/")
	not looks_like_host_first(parts)
}

looks_like_host_first(parts) if {
	count(parts) > 1
	looks_like_host(parts[0])
}

looks_like_host(s) if contains(s, ".")

looks_like_host(s) if contains(s, ":")

looks_like_host(s) if s == "localhost"

# Whole-host match; "*" matches exactly ONE dot-separated label (so *.azurecr.io ≠ a.b.azurecr.io)
approved(reg) if {
	some pattern in allowed_registries
	glob.match(lower(pattern), ["."], reg)
}

allowed_registries := object.get(object.get(input, "parameters", {}), "allowedRegistries", [])

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
