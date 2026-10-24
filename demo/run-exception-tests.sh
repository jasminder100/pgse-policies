#!/usr/bin/env bash
# Sends every exception test case through the real admission webhook (--dry-run=server:
# nothing is created) and compares the result with the expected ALLOW / WARN / DENY.
set -uo pipefail
cd "$(dirname "$0")"
rm -rf /tmp/exc && python3 exception-cases.py
pass=0; fail=0
for f in /tmp/exc/*.yaml; do
  b=$(basename "$f" .yaml); expect=${b%%__*}; name=${b#*__}
  out=$(kubectl apply --dry-run=server -f "$f" 2>&1)
  if   echo "$out" | grep -q "denied the request"; then got=DENY
  elif echo "$out" | grep -q "^Warning: \["; then        got=WARN
  else                                                   got=ALLOW
  fi
  rules=$(echo "$out" | grep -o '\[p[0-9][0-9]-[a-z-]*\]' | sort -u | tr '\n' ' ')
  [ "$got" = "$expect" ] && { r=PASS; pass=$((pass+1)); } || { r=FAIL; fail=$((fail+1)); }
  printf '%-5s %-24s expected %-5s got %-5s %s\n' "$r" "$name" "$expect" "$got" "$rules"
done
echo "== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
