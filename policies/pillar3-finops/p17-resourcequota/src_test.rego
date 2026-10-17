package k8spgseresourcequota

import future.keywords.contains
import future.keywords.if
import future.keywords.in

ns_obj(name) := {"review": {"object": {"kind": "Namespace", "metadata": {"name": name}}}}

quota(ns, hard) := {"namespace": {ns: {"v1": {"ResourceQuota": {"compute": {"spec": {"hard": hard}}}}}}}

full_hard := {"requests.cpu": "4", "limits.cpu": "8", "requests.memory": "8Gi", "limits.memory": "16Gi"}

# 1. Namespace with a CPU+memory quota → allowed
test_quota_ok if {
	count(violation) == 0 with input as ns_obj("demo") with data.inventory as quota("demo", full_hard)
}

# 2. Namespace with no quota at all → flagged
test_no_quota_flagged if {
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as {}
}

# 3. Quota limits CPU only → flagged
test_cpu_only_flagged if {
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as quota("demo", {"requests.cpu": "4"})
}

# 4. Quota limits only pod COUNT (no cpu/memory) → flagged
test_pod_count_only_flagged if {
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as quota("demo", {"pods": "20"})
}

# 5. Short keys "cpu"/"memory" also count → allowed
test_short_keys_ok if {
	count(violation) == 0 with input as ns_obj("demo") with data.inventory as quota("demo", {"cpu": "4", "memory": "8Gi"})
}

# 6. Quota exists, but in a DIFFERENT namespace → flagged
test_other_namespace_quota_flagged if {
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as quota("other", full_hard)
}

# 7. Not a Namespace → ignored
test_non_namespace_ignored if {
	count(violation) == 0 with input as {"review": {"object": {"kind": "Deployment", "metadata": {"name": "d", "namespace": "demo"}}}} with data.inventory as {}
}

# 8. Valid P17 waiver for this namespace → exempt
test_valid_waiver_exempts if {
	inv := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {"rule": "P17", "namespace": "demo", "expiresAt": "2099-01-01T00:00:00Z"}}}}}}
	count(violation) == 0 with input as ns_obj("demo") with data.inventory as inv
}

# 9. EXPIRED P17 waiver → flagged again
test_expired_waiver_flagged if {
	inv := {"cluster": {"pgse.io/v1alpha1": {"PolicyWaiver": {"w1": {"spec": {"rule": "P17", "namespace": "demo", "expiresAt": "2020-01-01T00:00:00Z"}}}}}}
	count(violation) == 1 with input as ns_obj("demo") with data.inventory as inv
}
