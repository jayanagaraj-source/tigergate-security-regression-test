# tigergate-security-regression-test

Regression repository for 13 TigerGate fixes: LOC counting, SAST false positives and false negatives,
and duplicate/false-positive secret findings. It holds intentionally vulnerable and safe **fixtures**, a
machine-readable oracle of what a correct scan reports, and scripts that compare a real scan with that
oracle. Nothing here is an application: no server is started, no database or external API is contacted,
and every credential-shaped value is synthetic.

Use it on every TigerGate release: scan it with the Dashboard and the CLI, export the results, run the
verifier and read the report. A scan that ran is not a pass; only the per-case outcomes count.

## What is covered

The expectations were derived from the TigerGate working tree on 2026-10-27 (branch
`codequality-FP,LOC`, HEAD `4a974ee2b` plus uncommitted changes) and from the vulnerability semantics of
each fixture. They were not tuned to scanner output.

| # | Fix | Implementation under test | Fixtures |
|---|---|---|---|
| 1 | LOC: Terraform/XML, Python docstrings, non-code files | `quality/loc.go`, CLI `scanner/loc.go`: `.tf`/`.xml` counted, docstrings as comments, README/Makefile/`*.gradle.kts`/Compose/Spring YAML not counted | `loc/terraform`, `loc/xml`, `loc/python`, `loc/build-files`, `loc/config`, `loc/app`, `loc/edge` |
| 2 | LOC: lockfiles, generated code, minified JS | lockfile names, `*.min.js`, generated-code markers in the first 30 lines | `loc/excluded-files`, `loc/generated-code`, `loc/minified` |
| 3 | Path-traversal FPs | `TG-TAINT-JS-PATH-TRAVERSAL`; `gitlab.eslint.detect-non-literal-fs-filename` excluded | `cases/sast/javascript/path-traversal` (incl. the 18/14 legacy corpus) |
| 4 | Duplicate secrets | `scanscope.SecretDeduper`, `SecretLog`, `RepeatsStoredSecret` (SAST `generic.secrets.*` copies) | `cases/secrets/duplicate-detection` |
| 5 | Secret FPs | `SuppressSecret`, `SuppressSecretCopy` (AWS doc keys, translation labels, placeholder tokens, service-account marker, GCP `private_key_id`) | `cases/secrets/true-positive`, `false-positive`, `edge` |
| 6 | JS XSS | `TG-TAINT-JS-XSS`: Buffer bodies excluded, `res.type(html)`/`status().send` sinks added | `cases/sast/javascript/xss`, `cases/sast/typescript/xss` |
| 7 | PHP SQL/XPath | `TG-TAINT-PHP-SQL-INJECTION` (typed `->query()` receivers), new `TG-TAINT-PHP-XPATH-INJECTION` | `cases/sast/php` |
| 8 | Python SQL taint | `TG-TAINT-PY-SQL-INJECTION` with `int()`/`float()` sanitizers | `cases/sast/python/sql-injection/flask_views.py` |
| 9 | Java XSS | `JAVA-011`: numeric and fully escaped operands excluded | `cases/sast/java/xss` |
| 10 | C/C++ format string | `CPP-002` (+`snprintf`/`sprintf`), `CPP-027` (`syslog`/`vsyslog`) | `cases/sast/cpp/format-string` |
| 11 | JS format string / log injection | new `TG-TAINT-JS-FORMAT-STRING`, `TG-TAINT-JS-LOG-INJECTION`; upstream `javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring` | `cases/sast/javascript/format-string`, `log-injection`, `cases/sast/typescript/format-string` |
| 12 | Zip slip | new `TG-TAINT-JS-ZIP-SLIP`, `TG-JS-ZIP-SLIP-ENTRIES-LOOP`, `TG-JS-TAR-PRESERVE-PATHS`; `GO-034`; registry `tarfile-extractall-traversal` | `cases/sast/*/zip-slip` |
| 13 | Python inline SQL | `TG-SQL-INJECTION-PY-INLINE` numeric exclusions | `cases/sast/python/sql-injection/inline_*.py` |

**`unsafe-formatstring` status.** The upstream rule is *not* in `scanscope.ExcludedUpstreamRules`. Its
catalog entry in `sast-rules.yaml` has no patterns, so it is not compiled into the served ruleset, but
the rule itself arrives through the `p/default` registry pack, which the worker enables by default. It
treats any concatenation or template literal passed as a `console.*`/`util.format` format as tainted,
so the Juice Shop `server.ts:157` shape (`console.error('Error in timed startup function: ' + name, err)`,
case `JS-FMT-TN-003`) is still reported unless that pack is disabled.

## Layout

```text
cases/                 SAST and secret fixtures (positives and negatives side by side, one marker per case)
  sast/<language>/<family>/
  secrets/{true-positive,false-positive,duplicate-detection,edge}/
loc/                   LOC fixtures: counted, excluded and edge files
expected/              the oracle (generated; never contains a secret value)
  findings.manifest.json   every case; sast/secrets/sca.manifest.json are per finding type
  loc.manifest.json        expected code lines per file and language
  rule-classes.json        rule ID -> vulnerability class, from rule metadata (CWE)
scripts/
  case_catalog.py          authoring source for the case manifests
  build-manifest.py        resolves each case's line from its marker, checks consistency
  verify-findings.py       compares exported findings with the manifest
  verify-loc.py            reference LOC counter, LOC manifest, LOC comparison
  generate-report.py       reports/REPORT.md, incl. Dashboard-vs-CLI consistency
  local-engine-scan.sh     local approximation of a TigerGate scan (see below)
  check-repo.sh            syntax checks, manifest checks, unit tests, secret self-scan
  synthetic_secrets.py     regenerates every synthetic secret from its seed
  tools/                   Go helpers built against a TigerGate checkout by local-engine-scan.sh
reports/               comparison reports (fingerprints only, no values)
```

### Why not `tests/` and `*-expected.json`

TigerGate deliberately excludes test code from scanning: `scanscope.CodeScanExcludes` drops `test/`,
`tests/`, `__tests__/`, `spec/`, `e2e/` and test-named files (`*_test.*`, `test_*.py`, `*Test.java`, ...)
from SAST, and `SuppressSecret` drops secrets under those paths, under `fixtures/`, `testdata/` and
`mocks/`, and in `*-expected.json` files. Fixtures under the suggested `tests/` tree would have been invisible,
and oracle files named `*-expected.json` would be quietly exempt from secret scanning. So fixtures live
under `cases/`, no fixture path uses an excluded directory or test-style name, and the manifests are
named `*.manifest.json`. The self-scan checks that they really produce no detections, without relying on
any exemption. The one test-named file, `scripts/test_verify_findings.py`, is the verifier's own unit
test, and it is meant to be excluded.

## How cases work

Each case is one sink line ending in a comment that carries its ID, e.g.

```js
res.type("html").send(req.query.html); // JS-XSS-TP-003
```

Data files that cannot hold comments (JSON, YAML, PEM) use an `anchor` text instead. IDs follow
`<LANG>-<FAMILY>-<TP|TN|GAP|EDGE>-NNN`. The legacy path-traversal corpus keeps its original `TG-PATH-*` IDs
and line numbers. It was copied verbatim from `Demo/no-lang/tigergate-test-path-traversal`.

`scripts/case_catalog.py` describes each case: expected outcome, class, accepted rule IDs, CWE and
status. `make manifest` writes the line numbers into the manifests. `expected_span` extends a case to the
line where its statement's brackets close (multi-line calls), or to the line that builds the value when
the marker appears twice (a query assembled in a variable). Example entry:

```json
{
  "test_id": "PHP-XPATH-TP-001",
  "issue": "php-sql-xpath",
  "language": "php",
  "file": "cases/sast/php/xpath-injection/lookup.php",
  "expected": "detected",
  "finding_type": "sast",
  "expected_class": "xpath-injection",
  "expected_rule_ids": ["TG-TAINT-PHP-XPATH-INJECTION"],
  "expected_cwe": ["CWE-643"],
  "expected_line": 8,
  "expected_span": [8, 8],
  "expected_count": 1,
  "status": "supported",
  "forbidden_classes": ["sql-injection"]
}
```

- `expected`: `detected`, `not_detected` or `context_dependent`.
- `status`: `supported` cases are counted. `known_gap` cases are documented analyzer limitations: they are
  reported with what was observed, but never counted as a pass or a failure. `context_dependent` cases are
  observed only.
- `expected_rule_ids` lists the rule(s) the fix is about. A different rule of the same class on the same
  line still counts as a TP, flagged *alternate rule*. A rule of another class never counts as proof.
- `forbidden_classes` marks misclassification. Example: XPath reported as SQL injection.
- `allowed_other_classes` lists classes that may legitimately also fire on that line. Example: a request
  value used as a format string is also log injection.
- `duplicate_of` marks a repeat the implemented policy collapses (the same secret value in two files is
  one leak). A finding there is a Duplicate, not an FP.

Secrets are matched by file, line and class. The manifests store no secret value, and the reports store
at most a 16-hex SHA-256 prefix. Every synthetic value is derived from
`sha256("tigergate-regression:<seed>")` (`scripts/synthetic_secrets.py`). None can be validated against a
provider, offline or online. AWS key IDs are standalone (no secret-key pair); there are no provider tokens
with valid checksums.

## Scanning

### Dashboard

1. Get approval, then create a remote repository and push this one (nothing has been committed or
   pushed yet).
2. Connect the repository in TigerGate. **Code Security → Repositories → tigergate-security-regression-test**, then run a **full** scan at the pushed commit.
3. Export the stored findings for that commit. On the local stack, run read-only:

```sh
docker exec -i tigergate-postgres psql -U tigergate -d tigergate -At -c "
  SET default_transaction_read_only=on;
  SELECT coalesce(json_agg(t), '[]') FROM (
    SELECT i.file_path, coalesce(i.start_line, i.line_start) AS start_line, coalesce(i.end_line, i.line_end) AS end_line,
           i.rule_id, i.cwe_ids, i.issue_type, i.category, s.scan_type, s.scan_tool
    FROM sast_issues i JOIN sast_scans s ON s.id = i.scan_id
    WHERE s.provider_repo_name = 'tigergate-security-regression-test' AND s.commit_sha = '<SHA>'
      AND s.scan_type IN ('full-scan', 'secret')) t;" > reports/dashboard-export.json
```

   If the export repeats a commit across several scans, keep only the latest `full-scan` and `secret`
   scan IDs.

### CLI

The CLI uploads its results; it writes no local result file. Flags as defined in
`tools/tigergate-cli/cmd/main.go`:

```sh
docker run --rm -v "$PWD:/workspace" -e TIGERGATE_API_KEY="$TIGERGATE_API_KEY" \
  tigergate/tigergate-cli:latest scan --type all --scan-scope full --quality-gate=false \
  --repo <owner>/tigergate-security-regression-test
# self-hosted / local stack: add --api-url <url>/api/ci (or set TIGERGATE_API_URL)
```

The local image `tigergate/tigergate-cli:fp-fix` was built on 2026-10-23 19:38, before HEAD `4a974ee2b`
and before the uncommitted fixes. Rebuild the image from the tree under test, or CLI results will not
reflect the fixes. The CLI image declares `SEMGREP_VERSION=1.37.0`; the local run below used Semgrep
1.168.0. CLI scans are stored with `scan_type = 'ci'` and `scan_tool = 'tigergate-cli'`. Export them with
the query above, using `s.scan_type = 'ci'`, into `reports/cli-export.json`.

### Compare

```sh
make verify FINDINGS=reports/dashboard-export.json LABEL=dashboard
make verify FINDINGS=reports/cli-export.json LABEL=cli
make report COMPARE='reports/dashboard.json reports/cli.json'   # Dashboard vs CLI case outcomes
```

`verify-findings.py` also reads SARIF, Semgrep JSON, gitleaks JSON, Trivy JSON and CSV/TSV with the same
columns. Pass every export of one scan together, so its SAST, secret and SCA findings are all counted. A
finding type with no export leaves its cases **Unverified**.

### Reading the results

| Outcome | Meaning |
|---|---|
| TP | expected vulnerability found by a rule of the expected class |
| FP | a safe case was flagged in its class (the report says whether the target rule or another rule did it) |
| FN | expected vulnerability not found, or fewer findings than `expected_count` |
| TN | safe case not flagged |
| Duplicate | more findings of the class than `expected_count` on one case, or a finding on a `duplicate_of` repeat |
| Misclassified | only a `forbidden_classes` rule fired (e.g. XPath reported as SQL injection) |
| Unverified | no export covered that finding type |
| Known gap | documented limitation; observed result shown, never counted |
| Unattributed | a finding on no case line: review each as a possible FP |

An issue is PASS only with no FP, FN, Duplicate or Misclassified case. Precision and recall are given
only over verified, supported cases. For secrets, a SAST catalog rule (e.g. `PY-101`, `JS-121`) that
repeats a detected secret is listed as *cross-engine overlap*. On a negative secret case, any finding is
an FP.

## LOC and SonarCloud

`expected/loc.manifest.json` gives code lines (SonarCloud's *ncloc* meaning: lines with at least one
character that is neither whitespace nor comment; docstrings are documentation) for every file. The 34
files in `loc/` are hand-verified (`HAND_COUNTS` in `verify-loc.py`). The rest come from the reference
counter, which uses Python `tokenize`/`ast`, so it is independent of TigerGate's prefix-based counter.

```sh
# TigerGate: export code_quality_metrics.metrics_json for the scan, read-only
docker exec -i tigergate-postgres psql -U tigergate -d tigergate -At -c "SET default_transaction_read_only=on;
  SELECT metrics_json FROM code_quality_metrics WHERE repository_name LIKE '%tigergate-security-regression-test'
  AND commit_sha = '<SHA>' ORDER BY created_at DESC LIMIT 1;" > reports/metrics.json
make verify-loc TIGERGATE_LOC=reports/metrics.json LABEL=dashboard

# SonarCloud, after analysing the same commit
curl -su "$SONAR_TOKEN:" "https://sonarcloud.io/api/measures/component?component=<key>&metricKeys=ncloc,ncloc_language_distribution" > reports/sonar-measures.json
curl -su "$SONAR_TOKEN:" "https://sonarcloud.io/api/measures/component_tree?component=<key>&metricKeys=ncloc&qualifiers=FIL&ps=500" > reports/sonar-files.json
make verify-loc TIGERGATE_LOC=reports/metrics.json SONAR='reports/sonar-measures.json reports/sonar-files.json' LABEL=sonar
```

Until a SonarCloud analysis of the same commit is supplied, every SonarCloud value is **pending**. None
has been invented. Expected divergences:

- `loc/edge/inline-block-comment.js`: TigerGate counts a line that begins with `/* c */` and then has code as a comment. Expected 3, TigerGate model 2.
- SonarCloud does not exclude generated files by header (except C# `<auto-generated>`), may exclude minified files by line length (`legacy-bundle.js`), and its YAML/Docker counting depends on the analyzers enabled.

## Local engine approximation

```sh
make local-scan TIGERGATE_SRC=/path/to/tigergate
```

This builds the Semgrep ruleset with the backend's own `sast-semgrep-ruleset.ts` and takes the excludes
and excluded upstream rules from the checkout's `scanscope`. It runs Semgrep with the catalog plus the 41
default registry packs, gitleaks with the CLI's allowlist, and Trivy. Then it applies TigerGate's post-processing:

- exact dedupe and `findingfold.Cluster`;
- the secret-copy split (`SuppressSecretCopy` / `RepeatsStoredSecret`);
- `SuppressSecret` and `SecretDeduper`;
- both LOC counters (worker and CLI).

The Go helpers are compiled against the checkout with `replace` directives, so this is TigerGate's own
logic, not a re-implementation. It does not write to the checkout, start services or upload anything.
Raw output stays in a temp directory outside this repository. It is still an approximation: the org
ruleset may differ, the CLI's block-comment allowlist and the worker's dedupe severity ranking are not
reproduced, and the CLI ships a different Semgrep. Treat a real Dashboard/CLI scan as the result.

`reports/local-engine-raw.*` is the engine output before post-processing.
`reports/local-engine-processed.*` is after it, and is the closer approximation of what the platform stores.

## Validation

```sh
make validate   # syntax (node, type-stripped TS, Python, C/C++, Go, JSON, YAML), manifests, unit tests, secret self-scan
```

PHP and Java have no local toolchain here, so the Semgrep parse step (0 parse errors on all PHP and
Java fixtures) is their syntax check.

## Known gaps and limitations

Recorded as `known_gap` and never counted:

- `TG-TAINT-PHP-SQL-INJECTION` / `TG-TAINT-PHP-XPATH-INJECTION` have no sanitizers: an `(int)` cast is still reported (`PHP-SQL-TN-005`, `PHP-XPATH-TN-004`).
- A `->query()` receiver with no visible type is treated as a database by design (`PHP-QRY-TN-007`).
- `TG-SQL-INJECTION-PY-INLINE` reads call text:
  - it cannot see through numeric helpers (`PY-SQLI-GAP-003`) or several `int()` variables (`PY-SQLI-GAP-002`);
  - it trusts shadowed `int`/`float` (`PY-SQLI-GAP-001`, `PY-SQLI-GAP-004`).
- `JAVA-011` needs a concatenation (`JAVA-XSS-GAP-002`). The writer-in-a-variable case (`JAVA-XSS-GAP-001`) was predicted as a gap, but `JAVA-011` reported it locally; promote it after a real scan confirms that.
- `CPP-002` matches the one-argument form only (`CPP-FMT-GAP-001`).
- `TG-TAINT-JS-LOG-INJECTION` models `console.*` only, not pino/winston (`JS-LOG-TP-012`).
- `Number()` and `path.basename` are not modelled sanitizers (`JS-XSS-TN-012`, `JS-ZIP-TN-009`).
- Python `tarfile` with `filter="data"` is still reported by the registry rule (`PY-ZIP-TN-002`).
- No Java zip-slip rule exists (`JAVA-ZIP-GAP-001`). The generic `JAVA-016` path rule reported it locally.
- The verification scripts produce a few unattributed findings of their own. Example: the `r/ai` hooks rule treats any `json.load` result as hook input. They are listed under the tooling paths in each report.

## Adding a regression case

1. Add the fixture line in the right `cases/` file, ending with a new unique ID comment. Keep same-class
   sinks at least five lines apart: `findingfold` merges same-class findings within three lines.
2. Add the case to `scripts/case_catalog.py`. Give it the expected outcome, status and accepted rule IDs, and
   take those IDs from `backend/data/*.yaml` or the registry pack, never invent them.
3. Run `make manifest` and then `make validate`. For a new secret, add its seed to `scripts/synthetic_secrets.py`.
4. Do not change an expectation because a scan disagrees. A disagreement is a finding to report.
