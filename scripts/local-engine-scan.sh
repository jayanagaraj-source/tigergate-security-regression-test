#!/usr/bin/env bash
# Local, non-destructive approximation of a TigerGate scan of this repository, for a first comparison
# before a real Dashboard/CLI scan. It reads a TigerGate checkout and never writes to it, starts no
# service and uploads nothing.
#
#   TIGERGATE_SRC=/path/to/tigergate scripts/local-engine-scan.sh
#
# Steps: build the Semgrep ruleset the backend would serve (backend sast-semgrep-ruleset.ts), take the
# code-scan excludes and excluded upstream rules from the checkout's scanscope package, run Semgrep with
# the catalog plus the default registry packs, run gitleaks with the CLI's allowlist, optionally run Trivy
# for SCA, apply TigerGate's post-processing (tg-postprocess), run both LOC counters (tg-loc), and compare.
#
# Raw engine output (which includes secret values) stays in OUT_DIR, outside the repository. Only the
# comparison reports, which carry fingerprints and never values, are written to reports/.
#
# Environment: TIGERGATE_SRC (required), OUT_DIR (default: a new temp dir), PACK_CACHE (registry pack
# cache, default $OUT_DIR/packs), OFFLINE=1 (catalog rules only, no pack download), SKIP_TRIVY=1.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
: "${TIGERGATE_SRC:?set TIGERGATE_SRC to a TigerGate checkout}"
TG="$(cd "$TIGERGATE_SRC" && pwd)"
OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/tigergate-regression-XXXXXX")}"
PACK_CACHE="${PACK_CACHE:-$OUT_DIR/packs}"
mkdir -p "$OUT_DIR" "$PACK_CACHE" "$REPO/reports"
case "$OUT_DIR" in "$REPO"/*) echo "OUT_DIR must be outside the repository" >&2; exit 2 ;; esac

# The packs a worker enables when the org has no registry configuration (indexer.allSemgrepRulesets
# minus defaultDisabledSemgrepRulesets p/bandit and p/comment).
PACKS="p/default p/owasp-top-ten p/security-audit p/cwe-top-25 p/r2c-security-audit p/trailofbits p/secrets
p/gitleaks p/sql-injection p/xss p/command-injection p/insecure-transport p/jwt p/react p/nodejs p/typescript
p/expressjs p/eslint p/headless-browser p/python p/django p/flask p/golang p/gosec p/java p/findsecbugs
p/csharp p/ruby p/brakeman p/php p/phpcs-security-audit p/rust p/scala p/kotlin p/swift p/docker p/terraform
p/kubernetes p/ci p/github-actions r/ai"

echo "== TigerGate checkout: $TG ($(git -C "$TG" rev-parse --short HEAD), $(git -C "$TG" status --short | wc -l) changed files)"
echo "== output: $OUT_DIR"

# 1. Ruleset, built by the backend's own code.
cat > "$OUT_DIR/build-ruleset.ts" <<EOF
import { getRulesetYaml } from '$TG/backend/src/lib/services/sast-semgrep-ruleset';
import * as fs from 'fs';
fs.writeFileSync('$OUT_DIR/ruleset.yaml', getRulesetYaml());
EOF
(cd "$TG/backend" && ./node_modules/.bin/tsx "$OUT_DIR/build-ruleset.ts" >/dev/null)

# 2. Go helpers, built against the checkout's packages.
build_postprocess() {
  local d="$OUT_DIR/build/tg-postprocess"
  mkdir -p "$d" && cp "$REPO/scripts/tools/tg-postprocess/main.go" "$d/"
  cat > "$d/go.mod" <<EOF
module tgregression/postprocess

go 1.21

require (
	github.com/tigergate/pkg/findingfold v0.0.0
	github.com/tigergate/pkg/scanscope v0.0.0
)

replace github.com/tigergate/pkg/findingfold => $TG/workers/pkg/findingfold

replace github.com/tigergate/pkg/scanscope => $TG/workers/pkg/scanscope
EOF
  (cd "$d" && GOFLAGS=-mod=mod go build -o "$OUT_DIR/tg-postprocess" .)
}
build_loc() { # $1 name, $2 loc.go path
  local d="$OUT_DIR/build/tg-loc-$1"
  mkdir -p "$d" && cp "$REPO/scripts/tools/tg-loc/main.go" "$d/"
  sed '1s/^package .*/package main/' "$2" > "$d/loc.go"
  printf 'module tgregression/loc%s\n\ngo 1.21\n' "$1" > "$d/go.mod"
  (cd "$d" && go build -o "$OUT_DIR/tg-loc-$1" .)
}
build_postprocess
build_loc worker "$TG/workers/code-reviewer/internal/quality/loc.go"
build_loc cli "$TG/tools/tigergate-cli/internal/scanner/loc.go"

# 3. Semgrep with the shared excludes and excluded upstream rules.
"$OUT_DIR/tg-postprocess" -print-scope > "$OUT_DIR/scope.json"
mapfile -t SCOPE_ARGS < <(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
for e in d["excludes"]: print("--exclude"); print(e)
for r in d["excluded_rules"]: print("--exclude-rule"); print(r)' "$OUT_DIR/scope.json")
CONFIGS=(--config "$OUT_DIR/ruleset.yaml")
if [ "${OFFLINE:-0}" != "1" ]; then
  for p in $PACKS; do
    f="$PACK_CACHE/$(echo "$p" | tr '/' '-').yaml"
    [ -s "$f" ] || curl -fsS -m 120 -o "$f" "https://semgrep.dev/c/$p"
    CONFIGS+=(--config "$f")
  done
fi
echo "== semgrep $(semgrep --version) with ${#CONFIGS[@]} config args"
(cd "$REPO" && semgrep scan --json --quiet --no-rewrite-rule-ids --metrics off --timeout 30 --jobs 2 \
  --max-memory 1500 --dataflow-traces "${CONFIGS[@]}" "${SCOPE_ARGS[@]}" --output "$OUT_DIR/semgrep.json" . ) || true

# 4. gitleaks with the CLI's allowlist (secretScanAllowlist + the fixture-directory allowlist).
python3 - "$TG/tools/tigergate-cli/internal/scanner/secrets_allowlist.go" "$OUT_DIR/gitleaks.toml" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
allow = re.search(r"const secretScanAllowlist = `(.*?)`", src, re.S).group(1)
fixture = r"^(?:\./)?(?:[^/]+/)*(?:testcerts|testingcert|testing|testdata|fixtures)/"
open(sys.argv[2], "w").write("[extend]\nuseDefault = true\n" + allow + "\n[[allowlists]]\n"
    "description = \"TigerGate: test fixture directories and Go test files\"\n"
    "paths = ['''" + fixture + "''', '''(^|/)[^/]*_test\\.go$''']\n")
PY
(cd "$REPO" && gitleaks dir . --config "$OUT_DIR/gitleaks.toml" --report-format json \
  --report-path "$OUT_DIR/gitleaks.json" --no-banner --exit-code 0 --log-level error)

# 5. Trivy SCA from the repository root, so its targets are repository-relative paths (needs its
#    vulnerability database; skipped on failure).
TRIVY=()
if [ "${SKIP_TRIVY:-0}" != "1" ] && command -v trivy >/dev/null; then
  if (cd "$REPO" && trivy fs --quiet --scanners vuln --format json --output "$OUT_DIR/trivy.json" .); then
    TRIVY=(--findings "$OUT_DIR/trivy.json")
  else
    echo "== trivy failed: SCA cases stay Unverified"
  fi
fi

# 6. TigerGate post-processing, then LOC.
"$OUT_DIR/tg-postprocess" -semgrep "$OUT_DIR/semgrep.json" -gitleaks "$OUT_DIR/gitleaks.json" -root "$REPO" -out "$OUT_DIR"
"$OUT_DIR/tg-loc-worker" "$REPO" > "$OUT_DIR/loc-worker.json"
"$OUT_DIR/tg-loc-cli" "$REPO" > "$OUT_DIR/loc-cli.json"

# 7. Compare.
cd "$REPO"
python3 -B scripts/verify-findings.py --label "local engines, raw (pre post-processing)" \
  --findings "$OUT_DIR/semgrep.json" --findings "$OUT_DIR/gitleaks.json" "${TRIVY[@]}" \
  --json-out reports/local-engine-raw.json --md-out reports/local-engine-raw.md > /dev/null
python3 -B scripts/verify-findings.py --label "local engines + TigerGate post-processing" \
  --findings "$OUT_DIR/sast.processed.json" --findings "$OUT_DIR/secrets.processed.json" "${TRIVY[@]}" \
  --json-out reports/local-engine-processed.json --md-out reports/local-engine-processed.md > /dev/null
python3 -B scripts/verify-loc.py --tigergate "$OUT_DIR/loc-worker.json" --label "worker counter (local build)" \
  --compare-cli "$OUT_DIR/loc-cli.json" --json-out reports/loc-local.json --md-out reports/loc-local.md > /dev/null
python3 -B scripts/generate-report.py
echo "== reports written to $REPO/reports; raw engine output kept in $OUT_DIR"
