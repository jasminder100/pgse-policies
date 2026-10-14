#!/usr/bin/env python3
"""CI guardrail for waivers/*.yaml: required fields present, not expired, max 90 days ahead."""
import datetime as dt, pathlib, re, sys

MAX_DAYS = 90
REQUIRED = ["rule", "namespace", "expiresAt", "reason", "approvedBy", "ticket"]
now = dt.datetime.now(dt.timezone.utc)
errors = 0

for f in sorted(pathlib.Path(__file__).resolve().parent.parent.glob("waivers/*.yaml")):
    text = f.read_text()
    spec = dict(re.findall(r"^  (\w+):\s*\"?([^\"\n]*)\"?\s*$", text, re.M))
    missing = [k for k in REQUIRED if not spec.get(k)]
    if "kind: PolicyWaiver" not in text or missing:
        print(f"::error file={f.name}::not a valid PolicyWaiver (missing: {', '.join(missing) or 'kind'})"); errors += 1; continue
    try:
        exp = dt.datetime.fromisoformat(spec["expiresAt"].replace("Z", "+00:00"))
    except ValueError:
        print(f"::error file={f.name}::expiresAt is not RFC3339: {spec['expiresAt']}"); errors += 1; continue
    days = (exp - now).days
    if exp <= now:
        print(f"::error file={f.name}::waiver expired on {spec['expiresAt']} - remove it or renew it in a new PR"); errors += 1
    elif days > MAX_DAYS:
        print(f"::error file={f.name}::expires in {days} days; max allowed is {MAX_DAYS}"); errors += 1
    else:
        print(f"OK  {f.name}: {spec['rule']} in {spec['namespace']} until {spec['expiresAt']} ({days} days left, {spec['ticket']})")

sys.exit(1 if errors else 0)
