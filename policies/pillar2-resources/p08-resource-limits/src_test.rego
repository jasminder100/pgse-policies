package k8spgseresourcelimits

import future.keywords.contains
import future.keywords.if
import future.keywords.in

pod(ctrs) := {"review": {"object": {"kind": "Pod", "metadata": {"name": "t"}, "spec": {"containers": ctrs}}}}

full := {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"cpu": "200m", "memory": "128Mi"}}

test_full_resources_allowed if {
	count(violation) == 0 with input as pod([{"name": "a", "resources": full}])
}

test_no_resources_gives_four_violations if {
	count(violation) == 4 with input as pod([{"name": "a"}])
}

test_missing_memory_limit_denied if {
	r := {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"cpu": "200m"}}
	count(violation) == 1 with input as pod([{"name": "a", "resources": r}])
}
