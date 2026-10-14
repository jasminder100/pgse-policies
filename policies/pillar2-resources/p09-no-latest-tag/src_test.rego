package k8spgsenolatesttag

import future.keywords.contains
import future.keywords.if
import future.keywords.in

pod(img) := {"review": {"object": {"kind": "Pod", "metadata": {"name": "t"}, "spec": {"containers": [{"name": "a", "image": img}]}}}}

test_latest_denied if count(violation) == 1 with input as pod("nginx:latest")

test_no_tag_denied if count(violation) == 1 with input as pod("nginx")

test_registry_port_no_tag_denied if count(violation) == 1 with input as pod("myreg:5000/team/app")

test_pinned_tag_allowed if count(violation) == 0 with input as pod("nginx:1.27.0")

test_ecr_pinned_allowed if count(violation) == 0 with input as pod("123456789012.dkr.ecr.ap-south-1.amazonaws.com/app:v1.2.3")

test_digest_allowed if count(violation) == 0 with input as pod("nginx@sha256:abc123")
