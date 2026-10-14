# K8s-PGSE policy repo
.PHONY: build check opa-test gator-test test

build:            ## embed src.rego into template.yaml
	python3 scripts/build-templates.py

check:            ## fail if a template is out of sync with its src.rego
	python3 scripts/build-templates.py --check

opa-test:         ## Rego unit tests with plain OPA
	opa test policies/ --ignore '*.yaml' -v

gator-test: build ## template + constraint vs sample manifests
	gator verify ./policies/...

test: opa-test gator-test
