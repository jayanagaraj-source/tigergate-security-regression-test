# TigerGate security regression report

Generated 2026-10-27 07:35 UTC. Expected results: `expected/`. A scan that ran is not a pass: only the outcomes below count.

## Case inventory (342 cases)

| Issue | Positive | Negative | Known gaps | Context-dependent | Expected findings | LOC files counted / excluded | Languages |
|---|---:|---:|---:|---:|---:|---:|---|
| 1. LOC: Terraform/XML counting, Python docstrings, excluded non-code files | 0 | 0 | 0 | 0 | 0 | 9 / 5 | dockerfile, java, javascript, python, terraform, xml, yaml |
| 2. LOC: lockfiles, generated code, minified JavaScript | 2 | 0 | 0 | 0 | 2 | 4 / 16 | javascript, secrets, typescript |
| 3. Path-traversal false positives | 30 | 23 | 0 | 5 | 30 | - | javascript, typescript |
| 4. Duplicate secret findings | 10 | 1 | 0 | 0 | 11 | - | secrets |
| 5. Secret false positives | 7 | 16 | 0 | 0 | 7 | - | secrets |
| 6. JavaScript XSS false positives and missed XSS | 16 | 15 | 1 | 0 | 16 | - | javascript, typescript |
| 7. PHP SQL injection misclassification and XPath detection | 21 | 13 | 3 | 0 | 21 | - | php |
| 8. Python SQL taint false positives | 10 | 10 | 0 | 0 | 10 | - | python |
| 9. Java XSS JAVA-011 | 10 | 12 | 2 | 0 | 10 | - | java |
| 10. C/C++ format string CPP-002 | 10 | 12 | 1 | 0 | 10 | - | c, cpp |
| 11. JavaScript unsafe-formatstring and log injection | 26 | 25 | 1 | 0 | 26 | - | javascript, typescript |
| 12. Zip-slip detection | 18 | 15 | 3 | 0 | 18 | - | go, java, javascript, python, typescript |
| 13. Python inline SQL injection false positives | 10 | 10 | 4 | 0 | 10 | - | python |

## local engines + TigerGate post-processing (`local-engine-processed.json`)

Finding types verified: sast, sca, secret

| Issue | TP | FP | FN | TN | Duplicates | Misclassified | Unverified | Known gaps | Precision | Recall | Status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 2. LOC: lockfiles, generated code, minified JavaScript | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1.000 | 1.000 | PASS |
| 3. Path-traversal false positives | 30 | 5 | 0 | 18 | 1 | 0 | 0 | 0 | 0.857 | 1.000 | FAIL |
| 4. Duplicate secret findings | 10 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 1.000 | 1.000 | FAIL |
| 5. Secret false positives | 6 | 4 | 1 | 12 | 0 | 0 | 0 | 0 | 0.600 | 0.857 | FAIL |
| 6. JavaScript XSS false positives and missed XSS | 16 | 6 | 0 | 9 | 0 | 0 | 0 | 1 | 0.727 | 1.000 | FAIL |
| 7. PHP SQL injection misclassification and XPath detection | 21 | 1 | 0 | 12 | 0 | 0 | 0 | 3 | 0.955 | 1.000 | FAIL |
| 8. Python SQL taint false positives | 10 | 7 | 0 | 3 | 0 | 0 | 0 | 0 | 0.588 | 1.000 | FAIL |
| 9. Java XSS JAVA-011 | 10 | 3 | 0 | 9 | 0 | 0 | 0 | 2 | 0.769 | 1.000 | FAIL |
| 10. C/C++ format string CPP-002 | 10 | 1 | 0 | 11 | 0 | 0 | 0 | 1 | 0.909 | 1.000 | FAIL |
| 11. JavaScript unsafe-formatstring and log injection | 26 | 3 | 0 | 22 | 0 | 0 | 0 | 1 | 0.897 | 1.000 | FAIL |
| 12. Zip-slip detection | 18 | 1 | 0 | 14 | 9 | 0 | 0 | 3 | 0.947 | 1.000 | FAIL |
| 13. Python inline SQL injection false positives | 10 | 8 | 0 | 2 | 0 | 0 | 0 | 4 | 0.556 | 1.000 | FAIL |

Unattributed findings: 36. Details: `local-engine-processed.md`.

## local engines, raw (pre post-processing) (`local-engine-raw.json`)

Finding types verified: sast, sca, secret

| Issue | TP | FP | FN | TN | Duplicates | Misclassified | Unverified | Known gaps | Precision | Recall | Status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 2. LOC: lockfiles, generated code, minified JavaScript | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1.000 | 1.000 | PASS |
| 3. Path-traversal false positives | 30 | 5 | 0 | 18 | 25 | 0 | 0 | 0 | 0.857 | 1.000 | FAIL |
| 4. Duplicate secret findings | 10 | 0 | 0 | 0 | 20 | 0 | 0 | 0 | 1.000 | 1.000 | FAIL |
| 5. Secret false positives | 7 | 9 | 0 | 7 | 8 | 0 | 0 | 0 | 0.438 | 1.000 | FAIL |
| 6. JavaScript XSS false positives and missed XSS | 16 | 6 | 0 | 9 | 15 | 0 | 0 | 1 | 0.727 | 1.000 | FAIL |
| 7. PHP SQL injection misclassification and XPath detection | 21 | 1 | 0 | 12 | 18 | 0 | 0 | 3 | 0.955 | 1.000 | FAIL |
| 8. Python SQL taint false positives | 10 | 7 | 0 | 3 | 48 | 0 | 0 | 0 | 0.588 | 1.000 | FAIL |
| 9. Java XSS JAVA-011 | 10 | 10 | 0 | 2 | 29 | 0 | 0 | 2 | 0.500 | 1.000 | FAIL |
| 10. C/C++ format string CPP-002 | 10 | 1 | 0 | 11 | 1 | 0 | 0 | 1 | 0.909 | 1.000 | FAIL |
| 11. JavaScript unsafe-formatstring and log injection | 26 | 3 | 0 | 22 | 2 | 0 | 0 | 1 | 0.897 | 1.000 | FAIL |
| 12. Zip-slip detection | 18 | 1 | 0 | 14 | 19 | 0 | 0 | 3 | 0.947 | 1.000 | FAIL |
| 13. Python inline SQL injection false positives | 10 | 8 | 0 | 2 | 14 | 0 | 0 | 4 | 0.556 | 1.000 | FAIL |

Unattributed findings: 63. Details: `local-engine-raw.md`.

## LOC (`loc-local.json`)

- worker counter (local build): expected 4000, actual 3999 (**differs**)
- CLI counter: expected 4000, actual 3999 (**differs**)
- Worker and CLI counters identical: True
- SonarCloud: pending

## LOC (`local-engine-processed.json`)

- SonarCloud: compared

## LOC (`local-engine-raw.json`)

- SonarCloud: compared
