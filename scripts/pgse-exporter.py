#!/usr/bin/env python3
"""K8s-PGSE compliance exporter: Gatekeeper audit results as Prometheus metrics.

Reads the same data as scripts/pgse-report.py (constraint audit status + PolicyWaivers),
so the Grafana dashboard and the JSON report always agree.

In cluster:  python3 pgse-exporter.py                     serves :9101/metrics
Locally:     python3 pgse-exporter.py --input c.json [--waivers w.json]   prints metrics once
"""
import argparse, datetime as dt, json, re, ssl, sys, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SA = "/var/run/secrets/kubernetes.io/serviceaccount"
API = "https://kubernetes.default.svc"
CACHE_SECONDS = 20

def api_get(path):
    with open(f"{SA}/token") as f:
        token = f.read().strip()
    ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")
    req = urllib.request.Request(API + path, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        return json.load(r)

def fetch_constraints():
    items = []
    for res in api_get("/apis/constraints.gatekeeper.sh/v1beta1").get("resources", []):
        if "/" in res["name"]:          # skip subresources such as <kind>/status
            continue
        for c in api_get(f"/apis/constraints.gatekeeper.sh/v1beta1/{res['name']}").get("items", []):
            c.setdefault("kind", res["kind"])
            items.append(c)
    return items

def fetch_waivers():
    try:
        return api_get("/apis/pgse.io/v1alpha1/policywaivers").get("items", [])
    except Exception:
        return []                        # CRD not installed yet

def rule_id(name):
    m = re.match(r"p(\d+)", name)
    return f"P{int(m.group(1)):02d}" if m else "-"

def esc(v):
    v = "" if v is None else str(v)
    return v.replace("\\", "\\\\").replace("\n", " ").replace('"', '\\"')[:200]

def lbl(**kw):
    return "{" + ",".join(f'{k}="{esc(v)}"' for k, v in kw.items()) + "}"

def render(constraints, waivers, now):
    out = []
    def metric(name, help_, samples):
        out.append(f"# HELP {name} {help_}")
        out.append(f"# TYPE {name} gauge")
        out.extend(f"{name}{l} {v}" for l, v in samples)

    per_rule, items = [], []
    for c in constraints:
        meta, spec, st = c["metadata"], c.get("spec", {}), c.get("status", {}) or {}
        rule, action = rule_id(meta["name"]), spec.get("enforcementAction", "deny")
        per_rule.append((lbl(rule=rule, constraint=meta["name"], action=action),
                         st.get("totalViolations", 0) or 0))
        for v in st.get("violations", []) or []:
            items.append((lbl(rule=rule, constraint=meta["name"],
                              action=v.get("enforcementAction", action),
                              kind=v.get("kind"), namespace=v.get("namespace", "<cluster>"),
                              name=v.get("name"), message=v.get("message")), 1))

    n = len(per_rule)
    compliant = sum(1 for _, t in per_rule if t == 0)
    metric("pgse_constraint_violations", "Audit violations per constraint (exact count).", per_rule)
    metric("pgse_violation", "One series per non-compliant resource (up to 20 per constraint).", items)
    metric("pgse_constraints", "Number of constraints.", [("", n)])
    metric("pgse_compliance_percent", "Share of constraints with zero violations.",
           [("", round(100 * compliant / n, 1) if n else 100.0)])

    ws = []
    for w in waivers:
        sp = w.get("spec", {})
        try:
            exp = dt.datetime.fromisoformat(sp.get("expiresAt", "").replace("Z", "+00:00"))
            active = 1 if exp > now else 0
        except ValueError:
            active = 0
        ws.append((lbl(waiver=w["metadata"]["name"], rule=sp.get("rule"), namespace=sp.get("namespace"),
                       prefix=sp.get("namePrefix") or "*", ticket=sp.get("ticket"),
                       expires=sp.get("expiresAt")), active))
    metric("pgse_waiver_active", "1 if the waiver is active, 0 if expired.", ws)
    return "\n".join(out) + "\n"

class Handler(BaseHTTPRequestHandler):
    cache = (0.0, "")
    def do_GET(self):
        if self.path == "/healthz":
            body = "ok\n"
        elif self.path == "/metrics":
            ts, body = Handler.cache
            if time.time() - ts > CACHE_SECONDS:
                try:
                    body = render(fetch_constraints(), fetch_waivers(), dt.datetime.now(dt.timezone.utc))
                    body += "# TYPE pgse_exporter_up gauge\npgse_exporter_up 1\n"
                    Handler.cache = (time.time(), body)
                except Exception as e:
                    print(f"scrape failed: {e}", file=sys.stderr, flush=True)
                    body = "# TYPE pgse_exporter_up gauge\npgse_exporter_up 0\n"
        else:
            self.send_response(404); self.end_headers(); return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *a):
        pass

def main():
    p = argparse.ArgumentParser(description="K8s-PGSE compliance exporter")
    p.add_argument("--input", help="kubectl get constraints -o json dump (local test mode)")
    p.add_argument("--waivers", help="kubectl get policywaivers -o json dump (local test mode)")
    p.add_argument("--port", type=int, default=9101)
    a = p.parse_args()
    if a.input:
        c = json.load(open(a.input)).get("items", [])
        w = json.load(open(a.waivers)).get("items", []) if a.waivers else []
        sys.stdout.write(render(c, w, dt.datetime.now(dt.timezone.utc)))
        return
    print(f"pgse-exporter listening on :{a.port}", flush=True)
    ThreadingHTTPServer(("", a.port), Handler).serve_forever()

if __name__ == "__main__":
    main()
