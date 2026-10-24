# Demo test scripts

Run against a live cluster (kubectl context = AKS). Nothing here is synced by Argo CD.

## Exception cases (built-in image, built-in namespace, waiver)
    python3 demo/exception-cases.py          # writes /tmp/exc/<EXPECTED>__<case>.yaml
    # then dry-run each through the admission webhook (run: bash demo/exception-dryrun.sh)

## Violation cases (dashboard: one object per rule)
    helm template pgse-sample-app ~/pgse-sample-app/chart -n demo --show-only templates/deployment.yaml > /tmp/pgse-app-deployment.yaml
    python3 demo/violation-cases.py /tmp/pgse-app-deployment.yaml warn > /tmp/viol-warn.yaml
    python3 demo/violation-cases.py /tmp/pgse-app-deployment.yaml deny > /tmp/viol-deny.yaml

## Current non-compliant items (needs Prometheus port-forward on :9090)
    python3 demo/show-violations.py
