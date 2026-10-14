# pgse-policies

Policy-as-code repo for K8s-PGSE: one ConstraintTemplate + one Constraint per rule.

```
policies/<pillar>/pNN-<name>/
  src.rego         Rego logic (source of truth, unit-tested with `opa test`)
  src_test.rego    OPA unit tests
  template.yaml    ConstraintTemplate (rego embedded by `make build`)
  constraint.yaml  Constraint: scope + enforcementAction (deny/warn/dryrun)
  samples/         allowed.yaml / disallowed.yaml manifests
  suite.yaml       gator verify suite (template + constraint vs samples)
```

`make test` = OPA unit tests + gator suites. Edit `src.rego`, never the rego inside `template.yaml`.
