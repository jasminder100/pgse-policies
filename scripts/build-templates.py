#!/usr/bin/env python3
"""Copy each policy's src.rego into its template.yaml (under `rego: |`).

src.rego is the single source of truth: it is unit-tested with `opa test`,
and this script embeds it into the Gatekeeper ConstraintTemplate.
Run:  python3 scripts/build-templates.py          (rewrite templates)
      python3 scripts/build-templates.py --check  (fail if any template is stale)
"""
import pathlib, sys

root = pathlib.Path(__file__).resolve().parent.parent / "policies"
check = "--check" in sys.argv
stale = []

for rego in sorted(root.glob("*/*/src.rego")):
    tpl = rego.with_name("template.yaml")
    lines = tpl.read_text().splitlines()
    idx = next(i for i, l in enumerate(lines) if l.strip() == "rego: |")
    indent = " " * (len(lines[idx]) - len(lines[idx].lstrip()) + 2)
    body = [indent + l if l.strip() else "" for l in rego.read_text().rstrip().splitlines()]
    new = "\n".join(lines[: idx + 1] + body) + "\n"
    if tpl.read_text() != new:
        stale.append(str(tpl.relative_to(root.parent)))
        if not check:
            tpl.write_text(new)

if check and stale:
    sys.exit("Stale templates (run make build):\n  " + "\n  ".join(stale))
print(("checked" if check else "built"), "templates;", len(stale), "changed" if not check else "stale")
