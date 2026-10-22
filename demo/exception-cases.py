#!/usr/bin/env python3
"""K8s-PGSE exception test cases. Each file is /tmp/exc/<EXPECTED>__<case>.yaml,
where EXPECTED is ALLOW, WARN or DENY. Run with the dry-run loop."""
import copy, os, yaml
base = yaml.safe_load(open(os.path.expanduser("~/pgse-sample-app/k8s/deployment.yaml")))
ACR = base["spec"]["template"]["spec"]["containers"][0]["image"].rsplit(":", 1)[0]
os.makedirs("/tmp/exc", exist_ok=True)

def write(expect, name, obj):
    open(f"/tmp/exc/{expect}__{name}.yaml", "w").write(yaml.safe_dump(obj, sort_keys=False))

def case(expect, name, ns, image=None, no_probes=False, privileged=False,
         sa=None, keep_token=False, no_resources=False, drop_team=False):
    d = copy.deepcopy(base)
    d["metadata"].update(name=name, namespace=ns)
    d["metadata"]["labels"].update(app=name, environment="dev")
    if drop_team: d["metadata"]["labels"].pop("team")
    d["spec"]["replicas"] = 1
    d["spec"]["selector"]["matchLabels"] = {"app": name}
    d["spec"]["template"]["metadata"]["labels"] = {"app": name}
    pod = d["spec"]["template"]["spec"]
    c = pod["containers"][0]
    if image: c["image"] = image
    if no_probes: c.pop("readinessProbe"); c.pop("livenessProbe")
    if privileged: c["securityContext"].update(privileged=True, allowPrivilegeEscalation=True)
    if sa: pod["serviceAccountName"] = sa
    if keep_token: pod.pop("automountServiceAccountToken", None)
    if no_resources: c.pop("resources")
    write(expect, name, d)

def service_account(expect, name, ns):
    write(expect, f"sa-{name}", {"apiVersion": "v1", "kind": "ServiceAccount",
          "metadata": {"name": name, "namespace": ns}, "automountServiceAccountToken": True})

# P10 built-in exception: approved image
case("ALLOW", "01-postgres-approved",  "dev", image="postgres:16.4")
case("DENY",  "02-postgres-latest",    "dev", image="postgres:latest")
case("DENY",  "03-nginx-dockerhub",    "dev", image="nginx:1.27.0")
# P10 waiver PGSE-004 (redis*)
case("ALLOW", "redis-cache",           "dev", image="redis:7.4")
case("DENY",  "04-cache-redis",        "dev", image="redis:7.4")
# Namespace exception: testing relaxes P09, P10, P12 (never security rules)
case("ALLOW", "05-testing-latest",     "testing", image=f"{ACR}:latest")
case("DENY",  "06-testing-dockerhub",  "testing", image="nginx:1.27.0")         # P10 still enforced in testing
case("ALLOW", "07-testing-no-probes",  "testing", no_probes=True)
case("DENY",  "08-testing-privileged", "testing", privileged=True)
case("DENY",  "09-dev-latest",         "dev", image=f"{ACR}:latest")
case("DENY",  "10-dev-no-probes",      "dev", no_probes=True)
# P25 built-in exception: approved service account dev/config-reader
case("ALLOW", "11-approved-sa",        "dev", sa="config-reader", keep_token=True)
case("DENY",  "12-unapproved-sa",      "dev", sa="other-app", keep_token=True)
case("DENY",  "13-default-sa",         "dev", keep_token=True)
service_account("ALLOW", "config-reader", "dev")
service_account("DENY",  "other-app",     "dev")
# P08 waiver PGSE-005 (batch*)
case("ALLOW", "batch-report",          "dev", no_resources=True)
case("DENY",  "14-report-batch",       "dev", no_resources=True)
# P14 waiver PGSE-006 (vendor*) - P14 is a warn rule
case("ALLOW", "vendor-chart",          "dev", drop_team=True)
case("WARN",  "15-chart-vendor",       "dev", drop_team=True)
print(f"{len(os.listdir('/tmp/exc'))} cases written")
