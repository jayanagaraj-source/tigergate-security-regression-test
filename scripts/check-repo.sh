#!/usr/bin/env bash
# Local validation: fixture syntax, manifest consistency, verifier unit tests, and a secret self-scan
# proving that every detected secret is a seed-derived synthetic value inside the secret fixtures (so the
# manifests, scripts and reports create no detections). Needs python3; node, gcc/g++, gofmt, php, javac
# and gitleaks are used when installed and reported as skipped otherwise.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
ok() { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }
skip() { printf '  skip  %s\n' "$1"; }

echo "== fixture syntax"
mapfile -t JS < <(find cases loc -type f \( -name '*.js' -o -name '*.mjs' \) | sort)
if command -v node >/dev/null; then
  n=0; for f in "${JS[@]}"; do node --check "$f" 2>/dev/null || { bad "node --check $f"; n=1; }; done
  [ $n = 0 ] && ok "JavaScript: ${#JS[@]} files parse"
  mapfile -t TS < <(find cases loc -type f -name '*.ts' | sort)
  tsdir=$(mktemp -d)
  n=0; for f in "${TS[@]}"; do
    node --no-warnings -e 'const fs=require("fs");fs.writeFileSync(process.argv[2],require("module").stripTypeScriptTypes(fs.readFileSync(process.argv[1],"utf8")))' "$f" "$tsdir/x.mjs" 2>/dev/null \
      && node --check "$tsdir/x.mjs" 2>/dev/null || { bad "TypeScript (type-stripped) syntax $f"; n=1; }
  done; rm -rf "$tsdir"
  [ $n = 0 ] && ok "TypeScript: ${#TS[@]} files parse after type stripping (no type check)"
else skip "node not installed"; fi
python3 -B - <<'PY' && ok "Python and JSON parse" || bad "Python/JSON parse"
import ast, json, pathlib, sys
err = 0
for p in sorted(pathlib.Path(".").rglob("*")):
    if ".git" in p.parts or not p.is_file():
        continue
    try:
        if p.suffix == ".py":
            ast.parse(p.read_text(encoding="utf-8"), str(p))
        elif p.suffix == ".json":
            json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print("   ", p, e); err = 1
sys.exit(err)
PY
if command -v gcc >/dev/null; then
  gcc -fsyntax-only -Wno-format-security cases/sast/cpp/format-string/*.c && g++ -fsyntax-only -Wno-format-security cases/sast/cpp/format-string/*.cpp \
    && ok "C/C++ compile (syntax only)" || bad "C/C++ syntax"
else skip "gcc not installed"; fi
if command -v gofmt >/dev/null; then
  out=$(gofmt -l -e cases loc scripts/tools 2>&1); [ -z "$out" ] && ok "Go: gofmt clean" || bad "Go: $out"
else skip "gofmt not installed"; fi
if command -v php >/dev/null; then
  n=0; for f in $(find cases -name '*.php'); do php -l "$f" >/dev/null || { bad "php -l $f"; n=1; }; done; [ $n = 0 ] && ok "PHP lint"
else skip "php not installed (Semgrep parse errors in the local scan are the PHP syntax check)"; fi
if command -v javac >/dev/null; then skip "javac present but servlet/encoder jars are not: Java is checked by Semgrep parsing"
else skip "javac not installed (Semgrep parse errors in the local scan are the Java syntax check)"; fi
if python3 -c "import yaml" 2>/dev/null; then
  python3 -B -c "
import yaml,pathlib,sys
bad=[p for p in pathlib.Path('.').rglob('*.y*ml') if '.git' not in p.parts and not list(yaml.safe_load_all(p.read_text()))]
sys.exit(1 if bad else 0)" && ok "YAML parses" || bad "YAML parse"
else skip "PyYAML not installed"; fi

echo "== manifests"
python3 -B scripts/build-manifest.py --check >/dev/null && ok "case manifests current, IDs unique, every marker resolved" || bad "case manifests (run make manifest)"
python3 -B scripts/verify-loc.py --check >/dev/null && ok "LOC manifest current, hand counts agree with the reference counter" || bad "LOC manifest"

echo "== verifier unit tests"
python3 -B -m unittest discover -s scripts -p 'test_*.py' >/dev/null 2>&1 && ok "unit tests pass" || bad "unit tests (python3 -B -m unittest discover -s scripts -p 'test_*.py')"

echo "== secret self-scan"
if command -v gitleaks >/dev/null; then
  tmp=$(mktemp -d)
  gitleaks dir . --report-format json --report-path "$tmp/g.json" --no-banner --exit-code 0 --log-level error
  python3 -B - "$tmp/g.json" <<'PY' && ok "every detection is a synthetic fixture value in an allowed path" || bad "secret self-scan"
import json, sys
sys.path.insert(0, "scripts")
import synthetic_secrets as s
findings = json.load(open(sys.argv[1]))
err = 0
for f in findings:
    path = f["File"].lstrip("./")
    if not path.startswith(s.ALLOWED_PREFIXES):
        print("    detection outside the secret fixtures: %s:%s %s" % (path, f["StartLine"], f["RuleID"])); err = 1
    elif not s.is_synthetic(f["Secret"]):
        print("    value at %s:%s is not a documented synthetic value" % (path, f["StartLine"])); err = 1
print("    %d engine detections checked" % len(findings))
sys.exit(err)
PY
  rm -rf "$tmp"
else skip "gitleaks not installed"; fi

echo "== git"
git status --short | awk 'END { printf "  info  %d paths not committed (nothing is committed by these scripts)\n", NR }'
exit $fail
