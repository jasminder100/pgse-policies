# K8s-PGSE policy repo
.PHONY: build check opa-test gator-test test waivers samples-check samples

build:            ## embed src.rego into template.yaml
	python3 scripts/build-templates.py

check:            ## fail if a template is out of sync with its src.rego
	python3 scripts/build-templates.py --check

opa-test:         ## Rego unit tests with plain OPA
	opa test policies/ --ignore '*.yaml' -v

gator-test: build ## template + constraint vs sample manifests
	gator verify ./policies/...

test: opa-test gator-test waivers samples-check

waivers:          ## waivers/*.yaml: required fields, not expired, max 90 days
	python3 scripts/check-waivers.py
samples-check:    ## every allowed sample must pass EVERY rule, not just its own
	@ARGS=""; for f in $$(find policies -name template.yaml -o -name constraint.yaml | sort); do ARGS="$$ARGS -f $$f"; done; \
	S=""; for f in $$(find policies -name allowed.yaml | sort); do S="$$S -f $$f"; done; \
	OUT=$$(gator test $$ARGS -f namespaces/ -f test-fixtures/ $$S); \
	if [ -n "$$OUT" ]; then echo "$$OUT"; echo "FAIL: an allowed sample breaks another rule"; exit 1; fi; \
	echo "OK: all allowed samples pass all rules"

samples:          ## regenerate pod samples from the P08 base
	./scripts/gen-samples.sh
