#!/usr/bin/env python3
"""Exception test cases: each file is named <EXPECTED>__<case>.yaml."""
import copy, yaml
base = yaml.safe_load(open("/home/sigmoid/pgse-sample-app/k8s/deployment.yaml"))
ACR = base["spec"]["template"]["spec"]["containers"][0]["image"].rsplit(":", 1)[0]

def case(expect, name, ns, image=None, no_probes=False, privileged=False):
    d = copy.deepcopy(base)
    d["metadata"].update(name=name, namespace=ns)
    d["metadata"]["labels"].update(app=name, environment="dev")
    d["spec"]["replicas"] = 1
    d["spec"]["selector"]["matchLabels"] = {"app": name}
    d["spec"]["template"]["metadata"]["labels"] = {"app": name}
    c = d["spec"]["template"]["spec"]["containers"][0]
    if image: c["image"] = image
    if no_probes: c.pop("readinessProbe"); c.pop("livenessProbe")
    if privileged: c["securityContext"].update(privileged=True, allowPrivilegeEscalation=True)
    open(f"/tmp/exc/{expect}__{name}.yaml", "w").write(yaml.safe_dump(d, sort_keys=False))

# Built-in image exception (P10 allowedImages)
case("ALLOW", "01-postgres-approved",      "dev", image="postgres:16.4")
case("DENY",  "02-postgres-latest",        "dev", image="postgres:latest")       # still must be pinned (P09)
case("DENY",  "03-nginx-dockerhub",        "dev", image="nginx:1.27.0")          # not approved (P10)
# Waiver (PGSE-004: P10, dev, redis*)
case("ALLOW", "redis-cache",               "dev", image="redis:7.4")             # name matches waiver prefix
case("DENY",  "04-cache-redis",            "dev", image="redis:7.4")             # name doesn't match
# Built-in namespace exception (testing: P09, P10, P12 relaxed)
case("ALLOW", "05-testing-latest",         "testing", image=f"{ACR}:latest")
case("ALLOW", "06-testing-dockerhub",      "testing", image="nginx:1.27.0")
case("ALLOW", "07-testing-no-probes",      "testing", no_probes=True)
case("DENY",  "08-testing-privileged",     "testing", privileged=True)           # security rules never relaxed
# Same manifests outside testing
case("DENY",  "09-dev-latest",             "dev", image=f"{ACR}:latest")
case("DENY",  "10-dev-no-probes",          "dev", no_probes=True)
print("cases written")
