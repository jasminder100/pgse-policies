#!/usr/bin/env python3
"""Generates test objects that each violate exactly one K8s-PGSE rule.
Usage: python3 ~/viol.py <base deployment.yaml> warn|deny"""
import copy, sys, yaml

base = yaml.safe_load(open(sys.argv[1]))
mode = sys.argv[2]

def wl(name, ns="dev", env="dev", replicas=0):
    d = copy.deepcopy(base)
    d["metadata"].update(name=name, namespace=ns)
    d["metadata"]["labels"].update(app=name, environment=env)
    d["spec"]["replicas"] = replicas
    d["spec"]["selector"]["matchLabels"] = {"app": name}
    d["spec"]["template"]["metadata"]["labels"] = {"app": name}
    return d
pod = lambda d: d["spec"]["template"]["spec"]
ctr = lambda d: pod(d)["containers"][0]

docs = []
if mode == "warn":
    docs.append({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "sandbox", "labels": {
        "owner": "platform-team", "team": "pgse", "cost-center": "cc-1001", "environment": "dev"}}})  # P17, P21
    d = wl("viol-p15"); d["metadata"]["labels"]["environment"] = "qa"; docs.append(d)   # P15: invalid env value
    d = wl("viol-p18"); d["metadata"]["annotations"] = {}; docs.append(d)               # P18: no annotations
    docs.append(wl("viol-p16", ns="demo", env="prod", replicas=1))                     # P16 + P11 in prod
else:
    d = wl("viol-p01"); ctr(d)["securityContext"].update(privileged=True, allowPrivilegeEscalation=True); docs.append(d)  # P01 + P03
    d = wl("viol-p02"); ctr(d)["securityContext"].update(runAsNonRoot=False, runAsUser=0); docs.append(d)
    d = wl("viol-p04"); pod(d)["hostNetwork"] = True; docs.append(d)
    d = wl("viol-p06"); ctr(d)["securityContext"]["capabilities"]["add"] = ["NET_ADMIN"]; docs.append(d)
    d = wl("viol-p08"); ctr(d).pop("resources"); docs.append(d)
    d = wl("viol-p10"); ctr(d)["image"] = "docker.io/library/nginx:1.27.0"; docs.append(d)
    d = wl("viol-p12"); ctr(d).pop("readinessProbe"); ctr(d).pop("livenessProbe"); docs.append(d)
    d = wl("viol-p22"); pod(d)["securityContext"]["seccompProfile"] = {"type": "Unconfined"}; docs.append(d)
    d = wl("viol-p23"); ctr(d)["ports"][0]["hostPort"] = 8080; docs.append(d)
    d = wl("viol-p24"); ctr(d)["env"] = [{"name": "DB_PASSWORD", "value": "Sup3rS3cret!"}]; docs.append(d)
    d = wl("viol-p25"); pod(d)["automountServiceAccountToken"] = True; docs.append(d)
    docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",                 # P19: no TLS
        "metadata": {"name": "viol-p19", "namespace": "dev",
                     "labels": dict(base["metadata"]["labels"], app="viol-p19", environment="dev"),
                     "annotations": base["metadata"].get("annotations", {})},
        "spec": {"rules": [{"host": "viol.example.com", "http": {"paths": [{"path": "/", "pathType": "Prefix",
            "backend": {"service": {"name": "viol-p19", "port": {"number": 80}}}}]}}]}})

yaml.safe_dump_all(docs, sys.stdout, sort_keys=False)
