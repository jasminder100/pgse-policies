#!/usr/bin/env bash
# Sends every /tmp/exc case through the real Gatekeeper webhook (server dry-run, nothing is created)
# and checks the result against the EXPECTED prefix in the file name.
fail=0
for f in /tmp/exc/*.yaml; do
  n=$(basename "$f"); exp=${n%%__*}
  out=$(kubectl apply --dry-run=server -f "$f" 2>&1); rc=$?
  if [ $rc -ne 0 ]; then got=DENY; elif grep -q '^Warning' <<<"$out"; then got=WARN; else got=ALLOW; fi
  if [ "$got" = "$exp" ]; then s=OK; else s=MISMATCH; fail=1; fi
  printf '%-9s expected %-5s got %-5s %s\n' "$s" "$exp" "$got" "$n"
  [ "$s" = MISMATCH ] && echo "    $out" | head -3
done
exit $fail
