package k8spgseallowedregistries

import future.keywords.contains
import future.keywords.if
import future.keywords.in

ecr := "563675986491.dkr.ecr.ap-south-1.amazonaws.com"

tparams := {"allowedRegistries": [ecr, "*.azurecr.io"]}

img(image) := {
	"parameters": tparams,
	"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "t", "namespace": "demo"},
		"spec": {"containers": [{"name": "a", "image": image}]},
	}},
}

# 1. Our own ECR → allowed
test_own_ecr_ok if {
	count(violation) == 0 with input as img(concat("", [ecr, "/pgse-sample-app:abc123"]))
}

# 2. Plain "nginx" (Docker Hub, implicit) → denied
test_docker_hub_implicit_denied if {
	count(violation) == 1 with input as img("nginx:1.27")
}

# 3. Docker Hub user image (no dot in first part) → denied
test_docker_hub_user_denied if {
	count(violation) == 1 with input as img("nginxinc/nginx-unprivileged:1.27.0-alpine")
}

# 4. Docker Hub written explicitly → denied
test_docker_hub_explicit_denied if {
	count(violation) == 1 with input as img("docker.io/library/nginx:1.27")
}

# 5. Someone ELSE's ECR account → denied
test_other_ecr_account_denied if {
	count(violation) == 1 with input as img("111122223333.dkr.ecr.ap-south-1.amazonaws.com/app:v1")
}

# 6. Azure Container Registry → allowed
test_acr_ok if {
	count(violation) == 0 with input as img("pgseacr.azurecr.io/app:v1")
}

# 7. Look-alike host that STARTS with our ECR name → denied
test_lookalike_host_denied if {
	count(violation) == 1 with input as img(concat("", [ecr, ".evil.com/app:v1"]))
}

# 8. Our ECR name used as a PATH on another registry → denied
test_registry_in_path_denied if {
	count(violation) == 1 with input as img(concat("", ["evil.com/", ecr, "/app:v1"]))
}

# 9. Wildcard covers one label only: a.b.azurecr.io → denied
test_wildcard_one_level_only if {
	count(violation) == 1 with input as img("a.b.azurecr.io/app:v1")
}

# 10. Uppercase registry host → still matched correctly
test_case_insensitive_ok if {
	count(violation) == 0 with input as img("PGSEACR.AZURECR.IO/app:v1")
}

# 11. No parameters → nothing approved
test_no_params_denies_all if {
	inp := {"review": {"object": {"kind": "Pod", "metadata": {"name": "t", "namespace": "demo"}, "spec": {"containers": [{"name": "a", "image": concat("", [ecr, "/app:v1"])}]}}}}
	count(violation) == 1 with input as inp
}

# 12. Init container from Docker Hub in a Deployment → denied
test_init_container_checked if {
	inp := {"parameters": tparams, "review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}, "spec": {"template": {"spec": {
		"containers": [{"name": "app", "image": concat("", [ecr, "/app:v1"])}],
		"initContainers": [{"name": "init", "image": "busybox:1.36"}],
	}}}}}}
	count(violation) == 1 with input as inp
}

# 13. Valid P10 waiver → exempt
test_valid_waiver_exempts if {
	waivers := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {
		"rule": "P10", "namespace": "demo", "namePrefix": "t",
		"expiresAt": "2099-01-01T00:00:00Z",
	}}}}}}
	count(violation) == 0 with input as img("nginx:1.27") with data.inventory as waivers
}

# --- built-in exception: approved images (allowedImages) ---
pg_params := {"allowedRegistries": ["pgseacr.azurecr.io"], "allowedImages": ["docker.io/library/postgres"]}

pg_input(image, params) := {"parameters": params, "review": {"object": {
	"kind": "Pod", "metadata": {"name": "db", "namespace": "demo"},
	"spec": {"containers": [{"name": "db", "image": image}]}}}}

test_approved_image_short_name_allowed if count(violation) == 0 with input as pg_input("postgres:16.4", pg_params)
test_approved_image_full_name_allowed if count(violation) == 0 with input as pg_input("docker.io/library/postgres:16.4", pg_params)
test_approved_image_index_alias_allowed if count(violation) == 0 with input as pg_input("index.docker.io/library/postgres:16.4", pg_params)
test_approved_image_digest_allowed if count(violation) == 0 with input as pg_input("postgres@sha256:0123abcd", pg_params)
test_approved_image_param_short_form if count(violation) == 0 with input as pg_input("docker.io/library/postgres:16.4", {"allowedRegistries": [], "allowedImages": ["postgres"]})
test_lookalike_user_repo_denied if count(violation) == 1 with input as pg_input("someone/postgres:16.4", pg_params)
test_similar_name_denied if count(violation) == 1 with input as pg_input("postgres-exporter:1.0", pg_params)
test_other_dockerhub_image_denied if count(violation) == 1 with input as pg_input("nginx:1.27", pg_params)
test_postgres_other_registry_denied if count(violation) == 1 with input as pg_input("ghcr.io/library/postgres:16", pg_params)
test_acr_still_allowed if count(violation) == 0 with input as pg_input("pgseacr.azurecr.io/app:v1", pg_params)
test_no_exception_without_param if count(violation) == 1 with input as pg_input("postgres:16.4", {"allowedRegistries": ["pgseacr.azurecr.io"]})
