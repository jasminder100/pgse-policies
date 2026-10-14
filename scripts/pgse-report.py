#!/usr/bin/env python3
"""K8s-PGSE compliance reporter.

Reads Gatekeeper audit results from the cluster (kubectl get constraints -o json),
prints a summary and writes a JSON report.

Usage:
  python3 scripts/pgse-report.py                     # summary + pgse-report-<timestamp>.json
  python3 scripts/pgse-report.py -o report.json      # choose the output file
  python3 scripts/pgse-report.py --input dump.json   # use a saved kubectl dump instead of the cluster
  python3 scripts/pgse-report.py --fail-on-violations  # exit 1 if any violation (for CI/cron)
"""
import argparse, datetime as dt, json, re, subprocess, sys
from collections import Counter

def load(args):
    if args.input:
        with open(args.input) as f:
            return json.load(f)
    try:
        out = subprocess.run(["kubectl", "get", "constraints", "-o", "json"],
                             check=True, capture_output=True, text=True).stdout
    except FileNotFoundError:
        sys.exit("kubectl not found in PATH")
    except subprocess.CalledProcessError as e:
        sys.exit("kubectl failed: " + e.stderr.strip())
    return json.loads(out)

def context():
    try:
        return subprocess.run(["kubectl", "config", "current-context"],
                              capture_output=True, text=True).stdout.strip() or "unknown"
    except FileNotFoundError:
        return "unknown"

def rule_id(name):
    m = re.match(r"p(\d+)", name)
    return f"P{int(m.group(1)):02d}" if m else "-"

def main():
    p = argparse.ArgumentParser(description="K8s-PGSE compliance reporter")
    p.add_argument("-o", "--output")
    p.add_argument("--input")
    p.add_argument("--fail-on-violations", action="store_true")
    args = p.parse_args()

    data = load(args)
    now = dt.datetime.now(dt.timezone.utc)
    rows, by_ns = [], Counter()
    for c in data.get("items", []):
        meta, spec, st = c["metadata"], c.get("spec", {}), c.get("status", {})
        viol = st.get("violations", []) or []
        for v in viol:
            by_ns[v.get("namespace", "<cluster>")] += 1
        rows.append({
            "rule": rule_id(meta["name"]),
            "constraint": meta["name"],
            "kind": c["kind"],
            "enforcementAction": spec.get("enforcementAction", "deny"),
            "totalViolations": st.get("totalViolations", 0) or 0,
            "auditTimestamp": st.get("auditTimestamp"),
            "violations": [{k: v.get(k) for k in ("kind", "namespace", "name", "message")} for v in viol],
        })
    rows.sort(key=lambda r: r["rule"])
    total = sum(r["totalViolations"] for r in rows)
    compliant = sum(1 for r in rows if r["totalViolations"] == 0)
    report = {
        "generatedAt": now.isoformat(timespec="seconds"),
        "cluster": "from-file" if args.input else context(),
        "summary": {
            "constraints": len(rows),
            "compliantConstraints": compliant,
            "totalViolations": total,
            "compliancePercent": round(100 * compliant / len(rows), 1) if rows else 100.0,
            "violationsByNamespace": dict(by_ns.most_common()),
        },
        "constraints": rows,
    }

    print(f"K8s-PGSE compliance report  |  cluster: {report['cluster']}  |  {report['generatedAt']}")
    print("-" * 86)
    print(f"{'RULE':<5} {'CONSTRAINT':<34} {'ACTION':<7} {'VIOLATIONS':>10}  STATUS")
    for r in rows:
        status = "OK" if r["totalViolations"] == 0 else "NON-COMPLIANT"
        print(f"{r['rule']:<5} {r['constraint']:<34} {r['enforcementAction']:<7} {r['totalViolations']:>10}  {status}")
    print("-" * 86)
    s = report["summary"]
    print(f"Constraints: {s['constraints']}  Compliant: {s['compliantConstraints']}  "
          f"Total violations: {s['totalViolations']}  Compliance: {s['compliancePercent']}%")
    if by_ns:
        print("Violations by namespace: " + ", ".join(f"{k}={v}" for k, v in by_ns.most_common()))

    out = args.output or f"pgse-report-{now:%Y%m%d-%H%M%S}.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"JSON report written to {out}")
    if args.fail_on_violations and total:
        sys.exit(1)

if __name__ == "__main__":
    main()
