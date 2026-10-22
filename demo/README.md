# Demo test scripts

Run against a live cluster (kubectl context = AKS). Nothing here is synced by Argo CD.

## Exception cases (built-in image, built-in namespace, waiver)
    python3 demo/exception-cases.py          # writes /tmp/exc/<EXPECTED>__<case>.yaml
    # then dry-run each through the admission webhook (see the loop in the project notes)

## Violation cases (dashboard: one object per rule)
    python3 demo/violation-cases.py ~/pgse-sample-app/k8s/deployment.yaml warn > /tmp/viol-warn.yaml
    python3 demo/violation-cases.py ~/pgse-sample-app/k8s/deployment.yaml deny > /tmp/viol-deny.yaml

## Current non-compliant items (needs Prometheus port-forward on :9090)
    python3 demo/show-violations.py
