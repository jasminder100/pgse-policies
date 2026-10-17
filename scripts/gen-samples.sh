#!/usr/bin/env bash
# Regenerate every pod-based sample from ONE base file, so they can never drift apart.
# Edit only the base (P08 allowed.yaml), then run: make samples
set -euo pipefail
cd "$(dirname "$0")/.."
P=policies
BASE=$P/pillar2-resources/p08-resource-limits/samples/allowed.yaml
gen() { sed "s/web-ok/$1/g" "$BASE" > "$2"; }

# Allowed samples = base, renamed
gen web-nonroot       $P/pillar1-security/p02-non-root/samples/allowed.yaml
gen web-no-escalate   $P/pillar1-security/p03-no-privilege-escalation/samples/allowed.yaml
gen web-isolated      $P/pillar1-security/p04-host-namespaces/samples/allowed.yaml
gen web-readonly      $P/pillar1-security/p05-readonly-root-fs/samples/allowed.yaml
gen web-pinned        $P/pillar2-resources/p09-no-latest-tag/samples/allowed.yaml
gen web-ecr           $P/pillar2-resources/p10-allowed-registries/samples/allowed.yaml
gen web-probes        $P/pillar2-resources/p12-probes/samples/allowed.yaml
gen web-seccomp       $P/pillar4-network/p22-seccomp/samples/allowed.yaml
gen web-no-hostport   $P/pillar4-network/p23-host-ports/samples/allowed.yaml
gen web-no-token      $P/pillar4-network/p25-automount-token/samples/allowed.yaml

# Allowed samples = base + one extra line
sed -e 's/web-ok/web-unprivileged/g' -e 's/^          securityContext:$/&\n            privileged: false/' \
  "$BASE" > $P/pillar1-security/p01-privileged-containers/samples/allowed.yaml
sed -e 's/web-ok/web-caps-ok/g' -e 's/^              drop: \["ALL"\]$/&\n              add: ["NET_BIND_SERVICE"]/' \
  "$BASE" > $P/pillar1-security/p06-capabilities/samples/allowed.yaml
sed -e 's/web-ok/web-secret-ref/g' \
    -e 's/^          image: .*$/&\n          env:\n            - name: LOG_LEVEL\n              value: info\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef: {name: db-creds, key: password, optional: true}/' \
  "$BASE" > $P/pillar4-network/p24-plaintext-secrets/samples/allowed.yaml
gen web-labelled      $P/pillar3-finops/p14-ownership-labels/samples/allowed.yaml

# Disallowed samples = base with exactly ONE thing broken
sed -e 's/web-ok/web-dockerhub/g' -e 's|image: .*|image: nginxinc/nginx-unprivileged:1.27.0-alpine|' \
  "$BASE" > $P/pillar2-resources/p10-allowed-registries/samples/disallowed.yaml
sed -e 's/web-ok/web-no-probes/g' -e '/Probe:$/,+1d' \
  "$BASE" > $P/pillar2-resources/p12-probes/samples/disallowed.yaml
sed -e 's/web-ok/web-unconfined/g' -e '/seccompProfile:/,+1d' \
  "$BASE" > $P/pillar4-network/p22-seccomp/samples/disallowed.yaml
sed -e 's/web-ok/web-hostport/g' \
    -e 's/^          image: .*$/&\n          ports:\n            - containerPort: 8080\n              hostPort: 80/' \
  "$BASE" > $P/pillar4-network/p23-host-ports/samples/disallowed.yaml
sed -e 's/web-ok/web-plaintext/g' \
    -e 's/^          image: .*$/&\n          env:\n            - name: DB_PASSWORD\n              value: SuperSecret123/' \
  "$BASE" > $P/pillar4-network/p24-plaintext-secrets/samples/disallowed.yaml
sed -e 's/web-ok/web-token/g' -e '/automountServiceAccountToken/d' \
  "$BASE" > $P/pillar4-network/p25-automount-token/samples/disallowed.yaml


echo "regenerated samples from $BASE"
sed -e 's/web-ok/web-unlabelled/g' -e '/^  labels:$/,+4d' \
  "$BASE" > $P/pillar3-finops/p14-ownership-labels/samples/disallowed.yaml
# P15: allowed / bad value / prod workload in a dev namespace
gen web-env-ok $P/pillar3-finops/p15-environment-label/samples/allowed.yaml
sed -e 's/web-ok/web-env-typo/g' -e 's/^    environment: prod$/    environment: production/' \
  "$BASE" > $P/pillar3-finops/p15-environment-label/samples/disallowed.yaml
sed -e 's/web-ok/web-env-mismatch/g' -e 's/^  namespace: demo$/  namespace: dev-sandbox/' \
  "$BASE" > $P/pillar3-finops/p15-environment-label/samples/mismatch.yaml
# P18: allowed / no annotations / http instead of https
gen web-annotated $P/pillar3-finops/p18-standard-annotations/samples/allowed.yaml
sed -e 's/web-ok/web-unannotated/g' -e '/^  annotations:$/,+2d' \
  "$BASE" > $P/pillar3-finops/p18-standard-annotations/samples/disallowed.yaml
sed -e 's/web-ok/web-http-url/g' -e 's|repository-url: https://|repository-url: http://|' \
  "$BASE" > $P/pillar3-finops/p18-standard-annotations/samples/bad-url.yaml
# P11: a prod Deployment, checked against a matching PDB / a useless PDB / none
gen web-pdb $P/pillar2-resources/p11-pdb/samples/deployment.yaml
