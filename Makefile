# TigerGate security regression repository. Every target is local and read-only toward TigerGate.
PY ?= python3 -B

.PHONY: help manifest validate test local-scan verify verify-loc report

help:
	@echo "make manifest                      regenerate expected/*.manifest.json after editing fixtures or scripts/case_catalog.py"
	@echo "make validate                      syntax checks, manifest checks, unit tests, secret self-scan"
	@echo "make test                          verifier unit tests only"
	@echo "make local-scan TIGERGATE_SRC=...  local engine approximation (Semgrep + gitleaks + Trivy + TigerGate post-processing)"
	@echo "make verify FINDINGS='a.json b.json' LABEL=dashboard   compare exported scan results with the manifest"
	@echo "make verify-loc TIGERGATE_LOC=metrics.json [SONAR=measures.json]   compare LOC"
	@echo "make report [COMPARE='reports/dashboard.json reports/cli.json']    write reports/REPORT.md"

manifest:
	$(PY) scripts/build-manifest.py
	$(PY) scripts/verify-loc.py --write-manifest

validate:
	bash scripts/check-repo.sh

test:
	$(PY) -m unittest discover -s scripts -p 'test_*.py'

local-scan:
	@test -n "$(TIGERGATE_SRC)" || (echo "set TIGERGATE_SRC=/path/to/tigergate" && exit 2)
	TIGERGATE_SRC="$(TIGERGATE_SRC)" bash scripts/local-engine-scan.sh

LABEL ?= scan
verify:
	@test -n "$(FINDINGS)" || (echo "set FINDINGS='export1.json export2.json'" && exit 2)
	$(PY) scripts/verify-findings.py $(foreach f,$(FINDINGS),--findings $(f)) --label "$(LABEL)" \
	  --json-out reports/$(LABEL).json --md-out reports/$(LABEL).md

verify-loc:
	$(PY) scripts/verify-loc.py $(if $(TIGERGATE_LOC),--tigergate $(TIGERGATE_LOC)) $(foreach f,$(SONAR),--sonar $(f)) \
	  --json-out reports/loc-$(LABEL).json --md-out reports/loc-$(LABEL).md

report:
	$(PY) scripts/generate-report.py $(if $(COMPARE),--compare $(COMPARE))
