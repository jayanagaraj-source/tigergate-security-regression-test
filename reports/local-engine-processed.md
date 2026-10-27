# TigerGate regression comparison: local engines + TigerGate post-processing

Exports: `sast.processed.json`, `secrets.processed.json`, `trivy.json`

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

Precision and recall are computed only over supported, verified cases; known gaps are excluded.

| Issue | FP by the target rule(s) | FP by other rules | TP by an alternate rule only | Cross-engine overlap |
|---|---:|---:|---:|---:|
| 2. LOC: lockfiles, generated code, minified JavaScript | 0 | 0 | 0 | 0 |
| 3. Path-traversal false positives | 0 | 5 | 0 | 0 |
| 4. Duplicate secret findings | 0 | 0 | 0 | 5 |
| 5. Secret false positives | 0 | 4 | 1 | 3 |
| 6. JavaScript XSS false positives and missed XSS | 0 | 6 | 0 | 0 |
| 7. PHP SQL injection misclassification and XPath detection | 0 | 1 | 0 | 0 |
| 8. Python SQL taint false positives | 0 | 7 | 0 | 0 |
| 9. Java XSS JAVA-011 | 0 | 3 | 1 | 0 |
| 10. C/C++ format string CPP-002 | 0 | 1 | 1 | 0 |
| 11. JavaScript unsafe-formatstring and log injection | 1 | 2 | 0 | 0 |
| 12. Zip-slip detection | 0 | 1 | 0 | 0 |
| 13. Python inline SQL injection false positives | 0 | 8 | 3 | 0 |

## Cases needing attention (51)

| Case | Outcome | Location | In-class rules | Notes |
|---|---|---|---|---|
| TG-PATH-TP-013 | TP | `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/file-write.js:18` | TG-TAINT-JS-PATH-TRAVERSAL, javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal | duplicates: 1 |
| TG-PATH-SAFE-005 | FP | `cases/sast/javascript/path-traversal/legacy-corpus/safe/validated-id.js:15` | javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal | other rule |
| TG-PATH-SAFE-013 | FP | `cases/sast/javascript/path-traversal/legacy-corpus/safe/validated-id.js:28` | javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal | other rule |
| JS-PT-TN-002 | FP | `cases/sast/javascript/path-traversal/resolve-normalize.js:64` | javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal | other rule |
| JS-PT-TN-003 | FP | `cases/sast/javascript/path-traversal/resolve-normalize.js:69` | javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal | other rule |
| JS-PT-TN-004 | FP | `cases/sast/javascript/path-traversal/resolve-normalize.js:75` | javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal | other rule |
| JS-XSS-TN-001 | FP | `cases/sast/javascript/xss/safe.js:12` | javascript.express.security.audit.xss.direct-response-write.direct-response-write | other rule |
| JS-XSS-TN-003 | FP | `cases/sast/javascript/xss/safe.js:20` | javascript.express.security.audit.xss.direct-response-write.direct-response-write | other rule |
| JS-XSS-TN-004 | FP | `cases/sast/javascript/xss/safe.js:24` | javascript.express.security.injection.raw-html-format.raw-html-format | other rule |
| JS-XSS-TN-005 | FP | `cases/sast/javascript/xss/safe.js:28` | javascript.express.security.injection.raw-html-format.raw-html-format | other rule |
| TS-XSS-TN-001 | FP | `cases/sast/typescript/xss/handlers.ts:22` | javascript.express.security.audit.xss.direct-response-write.direct-response-write | other rule |
| TS-XSS-TN-002 | FP | `cases/sast/typescript/xss/handlers.ts:26` | javascript.express.security.injection.raw-html-format.raw-html-format | other rule |
| PHP-SQL-TN-004 | FP | `cases/sast/php/sql-injection/queries.php:84` | TG-SQL-INJECTION-PHP | other rule |
| PY-SQLT-TN-001 | FP | `cases/sast/python/sql-injection/flask_views.py:88` | python.django.security.injection.tainted-sql-string.tainted-sql-string | other rule |
| PY-SQLT-TN-002 | FP | `cases/sast/python/sql-injection/flask_views.py:95` | python.django.security.injection.tainted-sql-string.tainted-sql-string | other rule |
| PY-SQLT-TN-003 | FP | `cases/sast/python/sql-injection/flask_views.py:102` | python.django.security.injection.tainted-sql-string.tainted-sql-string | other rule |
| PY-SQLT-TN-007 | FP | `cases/sast/python/sql-injection/flask_views.py:131` | python.django.security.injection.tainted-sql-string.tainted-sql-string | other rule |
| PY-SQLT-TN-008 | FP | `cases/sast/python/sql-injection/flask_views.py:138` | python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query | other rule |
| PY-SQLT-TN-009 | FP | `cases/sast/python/sql-injection/flask_views.py:145` | python.django.security.injection.tainted-sql-string.tainted-sql-string | other rule |
| PY-SQLT-TN-010 | FP | `cases/sast/python/sql-injection/flask_views.py:152` | python.django.security.injection.tainted-sql-string.tainted-sql-string | other rule |
| PY-SQLI-TN-001 | FP | `cases/sast/python/sql-injection/inline_numeric.py:5` | python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query | other rule |
| PY-SQLI-TN-002 | FP | `cases/sast/python/sql-injection/inline_numeric.py:9` | python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query | other rule |
| PY-SQLI-TN-003 | FP | `cases/sast/python/sql-injection/inline_numeric.py:13` | python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query | other rule |
| PY-SQLI-TN-004 | FP | `cases/sast/python/sql-injection/inline_numeric.py:17` | python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query | other rule |
| PY-SQLI-TN-005 | FP | `cases/sast/python/sql-injection/inline_numeric.py:21` | python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query | other rule |
| PY-SQLI-TN-006 | FP | `cases/sast/python/sql-injection/inline_numeric.py:25` | python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query | other rule |
| PY-SQLI-TN-007 | FP | `cases/sast/python/sql-injection/inline_numeric.py:29` | python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query | other rule |
| PY-SQLI-TN-008 | FP | `cases/sast/python/sql-injection/inline_numeric.py:34` | python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query | other rule |
| JAVA-XSS-TN-007 | FP | `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:47` | gitlab.find_sec_bugs.XSS_SERVLET-2.XSS_SERVLET_PARAMETER-1 | other rule |
| JAVA-XSS-TN-008 | FP | `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:51` | gitlab.find_sec_bugs.XSS_SERVLET-2.XSS_SERVLET_PARAMETER-1 | other rule |
| JAVA-XSS-TN-009 | FP | `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:55` | gitlab.find_sec_bugs.XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER-1 | other rule |
| CPP-FMT-TN-001 | FP | `cases/sast/cpp/format-string/format_safe.c:10` | c.lang.security.insecure-use-printf-fn.insecure-use-printf-fn | other rule |
| JS-FMT-TN-003 | FP | `cases/sast/javascript/format-string/trusted-formats.js:27` | javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring | other rule |
| JS-FMT-TN-004 | FP | `cases/sast/javascript/format-string/trusted-formats.js:35` | javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring | other rule |
| JS-FMT-TN-005 | FP | `cases/sast/javascript/format-string/trusted-formats.js:41` | TG-TAINT-JS-FORMAT-STRING | target rule |
| JS-ZIP-TP-001 | TP | `cases/sast/javascript/zip-slip/extract-unsafe.js:13` | TG-TAINT-JS-ZIP-SLIP, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | duplicates: 1 |
| JS-ZIP-TP-002 | TP | `cases/sast/javascript/zip-slip/extract-unsafe.js:21` | TG-TAINT-JS-ZIP-SLIP, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | duplicates: 1 |
| JS-ZIP-TP-005 | TP | `cases/sast/javascript/zip-slip/extract-unsafe.js:43` | TG-TAINT-JS-ZIP-SLIP, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | duplicates: 1 |
| JS-ZIP-TP-006 | TP | `cases/sast/javascript/zip-slip/extract-unsafe.js:51` | TG-TAINT-JS-ZIP-SLIP, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | duplicates: 1 |
| JS-ZIP-TP-007 | TP | `cases/sast/javascript/zip-slip/extract-unsafe.js:58` | TG-TAINT-JS-ZIP-SLIP, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | duplicates: 1 |
| JS-ZIP-TP-008 | TP | `cases/sast/javascript/zip-slip/extract-unsafe.js:67` | TG-TAINT-JS-ZIP-SLIP, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | duplicates: 1 |
| JS-ZIP-TP-011 | TP | `cases/sast/javascript/zip-slip/extract-unsafe.js:82` | TG-TAINT-JS-ZIP-SLIP, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | duplicates: 1 |
| JS-ZIP-TP-013 | TP | `cases/sast/javascript/zip-slip/extract-unsafe.js:98` | TG-TAINT-JS-ZIP-SLIP, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | duplicates: 1 |
| JS-ZIP-TN-010 | FP | `cases/sast/javascript/zip-slip/extract-safe.js:88` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | other rule |
| TS-ZIP-TP-002 | TP | `cases/sast/typescript/zip-slip/extract.ts:19` | TG-TAINT-JS-ZIP-SLIP, javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | duplicates: 1 |
| SEC-FP-001 | FP | `cases/secrets/false-positive/aws_docs_example.py:3` | PY-101 | other rule |
| SEC-FP-002 | FP | `cases/secrets/false-positive/aws_docs_example.py:4` | PY-101 | other rule |
| SEC-FP-006 | FP | `cases/secrets/false-positive/placeholders.py:4` | PY-101 | other rule |
| SEC-FP-014 | FP | `cases/secrets/false-positive/wallet.js:4` | JS-121 | other rule |
| SEC-EDGE-002 | FN | `cases/secrets/edge/locales/fr/keys.json:2` | - | - |
| SEC-DUP-004B | Duplicate | `cases/secrets/duplicate-detection/identical-b/settings.py:3` | PY-101 | duplicates: 1 |

## Known gaps (15, not counted)

| Case | Expected | Observed | Location |
|---|---|---|---|
| JS-XSS-TN-012 | not_detected | detected | `cases/sast/javascript/xss/safe.js:57` |
| PHP-SQL-TN-005 | not_detected | detected | `cases/sast/php/sql-injection/queries.php:89` |
| PHP-XPATH-TN-004 | not_detected | detected | `cases/sast/php/xpath-injection/lookup.php:86` |
| PHP-QRY-TN-007 | not_detected | detected | `cases/sast/php/query-methods/clients.php:47` |
| PY-SQLI-GAP-002 | not_detected | detected | `cases/sast/python/sql-injection/inline_numeric.py:48` |
| PY-SQLI-GAP-003 | not_detected | detected | `cases/sast/python/sql-injection/inline_numeric.py:56` |
| PY-SQLI-GAP-001 | detected | detected | `cases/sast/python/sql-injection/inline_shadowed.py:18` |
| PY-SQLI-GAP-004 | detected | detected | `cases/sast/python/sql-injection/inline_shadowed.py:22` |
| JAVA-XSS-GAP-001 | detected | detected | `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:59` |
| JAVA-XSS-GAP-002 | detected | detected | `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:63` |
| CPP-FMT-GAP-001 | detected | detected | `cases/sast/cpp/format-string/format_unsafe.c:50` |
| JS-LOG-TP-012 | detected | not detected | `cases/sast/javascript/log-injection/log-sinks.js:65` |
| JS-ZIP-TN-009 | not_detected | detected | `cases/sast/javascript/zip-slip/extract-safe.js:81` |
| PY-ZIP-TN-002 | not_detected | detected | `cases/sast/python/zip-slip/archives.py:17` |
| JAVA-ZIP-GAP-001 | detected | detected | `cases/sast/java/zip-slip/src/main/java/com/example/regression/ZipImporter.java:16` |

## Detected only by an alternate rule of the same class (6)

- PY-SQLI-TP-009 `cases/sast/python/sql-injection/inline_queries.py:43`: TG-SQL-INJECTION-PY
- PY-SQLI-GAP-001 `cases/sast/python/sql-injection/inline_shadowed.py:18`: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
- PY-SQLI-GAP-004 `cases/sast/python/sql-injection/inline_shadowed.py:22`: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
- JAVA-XSS-GAP-002 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:63`: gitlab.find_sec_bugs.XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER-1
- CPP-FMT-GAP-001 `cases/sast/cpp/format-string/format_unsafe.c:50`: c.lang.security.insecure-use-printf-fn.insecure-use-printf-fn
- SEC-EDGE-001 `cases/secrets/edge/commented_key.py:3`: generic.secrets.security.detected-generic-api-key.detected-generic-api-key

## Other-class findings on case lines (52, review)

- TG-PATH-TP-002 `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/path-join.js:13`: javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-TP-003 `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/template-literal.js:9`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-TP-007 `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/helper-function.js:14`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-TP-008 `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/weak-validation.js:11`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-TP-009 `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/weak-validation.js:20`: javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-TP-012 `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/typescript-paths.ts:15`: javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-EDGE-005 `cases/sast/javascript/path-traversal/legacy-corpus/edge-cases/encoded-input.js:21`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-EDGE-007 `cases/sast/javascript/path-traversal/legacy-corpus/edge-cases/symlink-containment.js:37`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-SAFE-002 `cases/sast/javascript/path-traversal/legacy-corpus/safe/static-config.js:14`: JS-048 (other)
- TG-PATH-SAFE-004 `cases/sast/javascript/path-traversal/legacy-corpus/safe/strict-allowlist.js:20`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-SAFE-005 `cases/sast/javascript/path-traversal/legacy-corpus/safe/validated-id.js:15`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-SAFE-006 `cases/sast/javascript/path-traversal/legacy-corpus/safe/path-containment.js:20`: javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-SAFE-007 `cases/sast/javascript/path-traversal/legacy-corpus/safe/safe-helper.js:12`: JS-048 (other)
- TG-PATH-SAFE-010 `cases/sast/javascript/path-traversal/legacy-corpus/safe/typescript-safe.ts:23`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-SAFE-012 `cases/sast/javascript/path-traversal/legacy-corpus/safe/static-config.js:18`: JS-048 (other)
- TG-PATH-SAFE-013 `cases/sast/javascript/path-traversal/legacy-corpus/safe/validated-id.js:28`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-EDGE-001 `cases/sast/javascript/path-traversal/legacy-corpus/edge-cases/basename.js:15`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-EDGE-004 `cases/sast/javascript/path-traversal/legacy-corpus/edge-cases/symlink-containment.js:32`: javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- TG-PATH-EDGE-006 `cases/sast/javascript/path-traversal/legacy-corpus/edge-cases/encoded-input.js:29`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- JS-PT-TP-001 `cases/sast/javascript/path-traversal/resolve-normalize.js:16`: javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- JS-PT-TP-008 `cases/sast/javascript/path-traversal/resolve-normalize.js:38`: JS-048 (other)
- JS-PT-TP-009 `cases/sast/javascript/path-traversal/resolve-normalize.js:44`: javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- JS-PT-TP-010 `cases/sast/javascript/path-traversal/resolve-normalize.js:51`: javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- JS-PT-TN-002 `cases/sast/javascript/path-traversal/resolve-normalize.js:64`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- JS-PT-TN-003 `cases/sast/javascript/path-traversal/resolve-normalize.js:69`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- JS-PT-TN-004 `cases/sast/javascript/path-traversal/resolve-normalize.js:75`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- JS-PT-TN-006 `cases/sast/javascript/path-traversal/resolve-normalize.js:80`: JS-048 (other), javascript.express.security.audit.xss.direct-response-write.direct-response-write (xss)
- JS-PT-TP-003 `cases/sast/javascript/path-traversal/esm-imports.mjs:10`: TG-TAINT-JS-XSS (xss)
- JS-PT-TN-005 `cases/sast/javascript/path-traversal/esm-imports.mjs:22`: TG-TAINT-JS-XSS (xss)
- JS-XSS-TP-004 `cases/sast/javascript/xss/vulnerable.js:22`: JS-048 (other)
- JS-XSS-TN-001 `cases/sast/javascript/xss/safe.js:12`: JS-048 (other)
- JS-XSS-TN-002 `cases/sast/javascript/xss/safe.js:16`: JS-048 (other)
- TS-XSS-TN-001 `cases/sast/typescript/xss/handlers.ts:22`: JS-048 (other)
- JAVA-XSS-TP-001 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:13`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TP-002 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:18`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TP-004 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:27`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TP-006 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:36`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TP-007 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:40`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TP-008 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:45`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TP-009 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:50`: gitlab.find_sec_bugs.COOKIE_USAGE-1 (other)
- JAVA-XSS-TP-010 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:54`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-GAP-001 `cases/sast/java/xss/src/main/java/com/example/regression/ReflectingServlet.java:59`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-001 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:17`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-002 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:22`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-003 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:27`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-004 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:32`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-005 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:38`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-006 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:43`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-007 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:47`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-008 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:51`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-009 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:55`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)
- JAVA-XSS-TN-012 `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:68`: gitlab.find_sec_bugs.SERVLET_PARAMETER-1.SERVLET_CONTENT_TYPE-1.SERVLET_SERVER_NAME-1.SERVLET_SESSION_ID-1.SERVLET_QUERY_STRING-1.SERVLET_HEADER-1.SERVLET_HEADER_REFERER-1.SERVLET_HEADER_USER_AGENT-1 (other)

## SAST catalog rules also reporting a secret line (8, cross-engine overlap)

- SEC-TP-001: PY-101
- SEC-TP-002: PY-101
- SEC-TP-003: JS-121
- SEC-DUP-002: JS-121, JS-121
- SEC-DUP-003A: PY-101
- SEC-DUP-003B: PY-101
- SEC-DUP-004A: PY-101
- SEC-DUP-005A: JS-121

## Unattributed findings (36): possible false positives

| Location | Rule | Class | Type |
|---|---|---|---|
| `cases/sast/go/zip-slip/untar.go:25` | go.lang.security.decompression_bomb.potential-dos-via-decompression-bomb | other | sast |
| `cases/sast/go/zip-slip/untar.go:46` | go.lang.security.decompression_bomb.potential-dos-via-decompression-bomb | other | sast |
| `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:16` | gitlab.find_sec_bugs.XSS_SERVLET-2.XSS_SERVLET_PARAMETER-1 | xss | sast |
| `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:21` | gitlab.find_sec_bugs.XSS_SERVLET-2.XSS_SERVLET_PARAMETER-1 | xss | sast |
| `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:26` | gitlab.find_sec_bugs.XSS_SERVLET-2.XSS_SERVLET_PARAMETER-1 | xss | sast |
| `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:31` | gitlab.find_sec_bugs.XSS_SERVLET-2.XSS_SERVLET_PARAMETER-1 | xss | sast |
| `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:36` | gitlab.find_sec_bugs.XSS_SERVLET-2.XSS_SERVLET_PARAMETER-1 | xss | sast |
| `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:42` | gitlab.find_sec_bugs.XSS_SERVLET-2.XSS_SERVLET_PARAMETER-1 | xss | sast |
| `cases/sast/java/xss/src/main/java/com/example/regression/EncodedOutputServlet.java:67` | gitlab.find_sec_bugs.XSS_SERVLET-2.XSS_SERVLET_PARAMETER-1 | xss | sast |
| `cases/sast/javascript/format-string/request-formats.js:11` | JS-067 | other | sast |
| `cases/sast/javascript/log-injection/log-sinks.js:11` | JS-067 | other | sast |
| `cases/sast/javascript/path-traversal/legacy-corpus/edge-cases/symlink-containment.js:28` | javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/path-traversal/legacy-corpus/safe/path-containment.js:13` | javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/async-filesystem.js:12` | TG-TAINT-JS-XSS | xss | sast |
| `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/helper-function.js:9` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/path-traversal/legacy-corpus/vulnerable/weak-validation.js:16` | javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:14` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:14` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:24` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:24` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:33` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:43` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:43` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:53` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:53` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:64` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-safe.js:64` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/javascript/zip-slip/extract-unsafe.js:89` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/php/xpath-injection/lookup.php:30` | PHP-030 | other | sast |
| `cases/sast/typescript/zip-slip/extract.ts:30` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/typescript/zip-slip/extract.ts:40` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `cases/sast/typescript/zip-slip/extract.ts:40` | javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal | path-traversal | sast |
| `scripts/generate-report.py:90` | ai.ai-best-practices.hooks-path-traversal.hooks-path-traversal-python.hooks-path-traversal-python | path-traversal | sast |
| `scripts/verify-findings.py:426` | ai.ai-best-practices.hooks-path-traversal.hooks-path-traversal-python.hooks-path-traversal-python | path-traversal | sast |
| `scripts/verify-loc.py:256` | ai.ai-best-practices.hooks-path-traversal.hooks-path-traversal-python.hooks-path-traversal-python | path-traversal | sast |
| `scripts/verify-loc.py:269` | ai.ai-best-practices.hooks-path-traversal.hooks-path-traversal-python.hooks-path-traversal-python | path-traversal | sast |
