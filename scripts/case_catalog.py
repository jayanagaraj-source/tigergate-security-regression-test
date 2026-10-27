"""Authoring source for the expected-findings manifests.

Edit this file, then run `make manifest` (scripts/build-manifest.py) to regenerate expected/*.manifest.json.
Line numbers are never written here: the builder finds each case's marker (its ID in a trailing comment
on the sink line) or its `anchor` text, so moving code cannot silently desynchronise the oracle.

Expectations come from the vulnerability semantics of each fixture and the rules as implemented in the
TigerGate working tree analysed on 2026-10-27 (branch codequality-FP,LOC, HEAD 4a974ee2b + uncommitted
changes). They were not adjusted to match scanner output.

Case fields
  id            unique case ID (also the marker text in the fixture)
  expected      "detected" | "not_detected" | "context_dependent"
  status        "supported" (counted) | "known_gap" (documented analyzer limitation, reported separately,
                never counted as a pass) | "context_dependent" (verdict depends on deployment; observed only)
  count         findings expected for the case (default 1; two distinct secrets on one line = 2)
  duplicate_of  for a repeat that the implemented policy collapses: a finding here is a Duplicate, not an FP
"""

# Issue keys, in the order of the 13 fixes under test.
ISSUES = {
    "loc-alignment": "1. LOC: Terraform/XML counting, Python docstrings, excluded non-code files",
    "loc-exclusions": "2. LOC: lockfiles, generated code, minified JavaScript",
    "path-traversal": "3. Path-traversal false positives",
    "secret-duplicates": "4. Duplicate secret findings",
    "secret-false-positives": "5. Secret false positives",
    "js-xss": "6. JavaScript XSS false positives and missed XSS",
    "php-sql-xpath": "7. PHP SQL injection misclassification and XPath detection",
    "python-sql-taint": "8. Python SQL taint false positives",
    "java-xss": "9. Java XSS JAVA-011",
    "cpp-format-string": "10. C/C++ format string CPP-002",
    "js-format-string-log-injection": "11. JavaScript unsafe-formatstring and log injection",
    "zip-slip": "12. Zip-slip detection",
    "python-inline-sql": "13. Python inline SQL injection false positives",
}

UPSTREAM_FORMATSTRING = "javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring"

# Secret-engine rule IDs: gitleaks (CLI, and the platform worker when gitleaks is installed) and Trivy
# (the worker's fallback engine). Either engine's ID satisfies a case.
SECRET_RULES = {
    "generic": ["generic-api-key"],
    "aws-key-id": ["aws-access-token", "aws-access-key-id"],
    "jwt": ["jwt", "jwt-token"],
    "private-key": ["private-key"],
}

GROUPS = []


def group(issue, language, file, cls, rules, cases, finding_type="sast", cwe=None, allowed_other=(),
          forbidden=(), note=""):
    GROUPS.append({
        "issue": issue, "language": language, "file": file, "class": cls, "rules": list(rules),
        "finding_type": finding_type, "cwe": cwe or [], "allowed_other_classes": list(allowed_other),
        "forbidden_classes": list(forbidden), "note": note, "cases": cases,
    })


def tp(cid, desc, **kw):
    return dict(id=cid, expected="detected", status="supported", description=desc, **kw)


def tn(cid, desc, **kw):
    return dict(id=cid, expected="not_detected", status="supported", description=desc, **kw)


def gap(cid, expected, desc, **kw):
    return dict(id=cid, expected=expected, status="known_gap", description=desc, **kw)


def ctx(cid, desc, **kw):
    return dict(id=cid, expected="context_dependent", status="context_dependent", description=desc, **kw)


# --------------------------------------------------------------------------------------------- issue 3
PT = "cases/sast/javascript/path-traversal/"
LEG = PT + "legacy-corpus/"
PT_RULE = ["TG-TAINT-JS-PATH-TRAVERSAL"]
PT_CWE = ["CWE-22"]

# Legacy corpus copied verbatim from Demo/no-lang/tigergate-test-path-traversal (16 TP + 2 TP edge = 18
# positives, 14 safe). Its lines are the original ones; `line` pins them and the builder verifies the
# legacy marker is on that line.
_legacy = [
    ("TG-PATH-TP-001", "vulnerable/direct-input.js", 10, "d", "req.query.filename reaches fs.readFile unvalidated"),
    ("TG-PATH-TP-002", "vulnerable/path-join.js", 13, "d", "path.join keeps '../' segments"),
    ("TG-PATH-TP-003", "vulnerable/template-literal.js", 9, "d", "route parameter interpolated into a path"),
    ("TG-PATH-TP-004", "vulnerable/file-write.js", 9, "d", "arbitrary file write"),
    ("TG-PATH-TP-005", "vulnerable/file-delete.js", 9, "d", "arbitrary file deletion"),
    ("TG-PATH-TP-006", "vulnerable/file-stream.js", 9, "d", "read stream on a request path"),
    ("TG-PATH-TP-007", "vulnerable/helper-function.js", 14, "d", "taint through a helper building the path"),
    ("TG-PATH-TP-008", "vulnerable/weak-validation.js", 11, "d", "replace('../','') strips one occurrence only"),
    ("TG-PATH-TP-009", "vulnerable/weak-validation.js", 20, "d", "startsWith(base) without a separator"),
    ("TG-PATH-TP-010", "vulnerable/async-filesystem.js", 9, "d", "fs.promises read of a request path"),
    ("TG-PATH-TP-011", "vulnerable/express-download.js", 8, "d", "res.download of a request path"),
    ("TG-PATH-TP-012", "vulnerable/typescript-paths.ts", 15, "d", "typed Express query value to readFileSync"),
    ("TG-PATH-TP-013", "vulnerable/file-write.js", 18, "d", "rename with attacker-controlled source and destination"),
    ("TG-PATH-TP-014", "vulnerable/file-write.js", 23, "d", "copy with attacker-controlled source"),
    ("TG-PATH-TP-015", "vulnerable/file-delete.js", 16, "d", "recursive delete of a request path"),
    ("TG-PATH-TP-016", "vulnerable/async-filesystem.js", 16, "d", "fs.promises open of a request path"),
    ("TG-PATH-EDGE-005", "edge-cases/encoded-input.js", 21, "d", "check before decodeURIComponent lets %2e%2e%2f through"),
    ("TG-PATH-EDGE-007", "edge-cases/symlink-containment.js", 37, "d", "path.normalize keeps leading '..' with no containment"),
    ("TG-PATH-SAFE-001", "safe/constant-path.js", 6, "n", "string-literal path"),
    ("TG-PATH-SAFE-002", "safe/static-config.js", 14, "n", "path from a hardcoded config object"),
    ("TG-PATH-SAFE-003", "safe/generated-filename.js", 9, "n", "server-generated filename"),
    ("TG-PATH-SAFE-004", "safe/strict-allowlist.js", 20, "n", "request selects from a fixed allowlist"),
    ("TG-PATH-SAFE-005", "safe/validated-id.js", 15, "n", "^[0-9]{1,10}$ guard"),
    ("TG-PATH-SAFE-006", "safe/path-containment.js", 20, "n", "resolve + relative containment check"),
    ("TG-PATH-SAFE-007", "safe/safe-helper.js", 12, "n", "helper returns a literal-only path"),
    ("TG-PATH-SAFE-008", "safe/safe-stream.js", 7, "n", "stream on a module constant"),
    ("TG-PATH-SAFE-009", "safe/safe-async.js", 9, "n", "server-generated path"),
    ("TG-PATH-SAFE-010", "safe/typescript-safe.ts", 23, "n", "type guard over a const allowlist"),
    ("TG-PATH-SAFE-011", "safe/constant-path.js", 12, "n", "concatenation of literals"),
    ("TG-PATH-SAFE-012", "safe/static-config.js", 18, "n", "Object.freeze constant map"),
    ("TG-PATH-SAFE-013", "safe/validated-id.js", 28, "n", "^[a-z0-9_-]{1,64}\\.txt$ guard"),
    ("TG-PATH-SAFE-014", "safe/safe-helper.js", 17, "n", "template literal of a module constant"),
    ("TG-PATH-EDGE-001", "edge-cases/basename.js", 15, "c", "basename: no traversal on POSIX, no authorization guarantee"),
    ("TG-PATH-EDGE-002", "edge-cases/cli-argument.js", 13, "c", "CLI argument: trusted only when the CLI runs as its user"),
    ("TG-PATH-EDGE-003", "edge-cases/environment-path.js", 10, "c", "environment path: trusted only if operator-set"),
    ("TG-PATH-EDGE-004", "edge-cases/symlink-containment.js", 32, "c", "lexical check passes for an escaping symlink"),
    ("TG-PATH-EDGE-006", "edge-cases/encoded-input.js", 29, "c", "'..\\\\' escapes on Windows only"),
]
for cid, f, line, kind, desc in _legacy:
    mk = {"d": tp, "n": tn, "c": ctx}[kind]
    group("path-traversal", "typescript" if f.endswith(".ts") else "javascript", LEG + f, "path-traversal",
          PT_RULE, [mk(cid, desc, line=line, legacy=True)], cwe=PT_CWE,
          note="Legacy 18/14 regression corpus (verbatim copy).")

group("path-traversal", "javascript", PT + "resolve-normalize.js", "path-traversal", PT_RULE, [
    tp("JS-PT-TP-001", "path.resolve(BASE, request value) with no containment check"),
    tp("JS-PT-TP-002", "path.normalize of a route parameter"),
    tp("JS-PT-TP-005", "fs.promises.writeFile on a request path"),
    tp("JS-PT-TP-006", "res.sendFile of a request path without a root option"),
    tp("JS-PT-TP-007", "fs.copyFile destination from the request"),
    tp("JS-PT-TP-008", "destructured require('fs') readFileSync on a request path"),
    tp("JS-PT-TP-009", "path.resolve(path.join(...)) is not containment"),
    tp("JS-PT-TP-010", "relative check without the isAbsolute half"),
    tp("JS-PT-TP-011", "request header to createReadStream"),
    tn("JS-PT-TN-001", "res.sendFile with a root option"),
    tn("JS-PT-TN-002", "parseInt-coerced value"),
    tn("JS-PT-TN-003", "request value only indexes a server-side map"),
    tn("JS-PT-TN-004", "anchored filename regex guard that returns"),
    tn("JS-PT-TN-006", "Number()-coerced value"),
    tn("JS-PT-TN-007", "constant template path"),
    tn("JS-PT-TN-008", "res.download with a root option"),
    tn("JS-PT-TN-009", "readFile method of an unrelated object"),
], cwe=PT_CWE)
group("path-traversal", "javascript", PT + "esm-imports.mjs", "path-traversal", PT_RULE, [
    tp("JS-PT-TP-003", "named import readFile from node:fs/promises"),
    tp("JS-PT-TP-004", "aliased import rm as remove from node:fs/promises"),
    tn("JS-PT-TN-005", "complete path.relative containment check with a named import"),
], cwe=PT_CWE)
group("path-traversal", "javascript", "cases/sast/javascript/xss/vulnerable.js", "path-traversal", PT_RULE, [
    tp("JS-PT-TP-021", "request path read with an encoding (sits in the XSS fixture)"),
], cwe=PT_CWE, allowed_other=["xss"])

# --------------------------------------------------------------------------------------------- issue 6
XSS_RULE = ["TG-TAINT-JS-XSS"]
group("js-xss", "javascript", "cases/sast/javascript/xss/vulnerable.js", "xss", XSS_RULE, [
    tp("JS-XSS-TP-001", "template literal HTML in res.send"),
    tp("JS-XSS-TP-002", "concatenated HTML through a variable"),
    tp("JS-XSS-TP-003", "res.type('html').send (previously missed sink)"),
    tp("JS-XSS-TP-004", "HTML-typed response of a file read: a Buffer renders as HTML", ),
    tp("JS-XSS-TP-005", "res.set Content-Type text/html then res.send"),
    tp("JS-XSS-TP-006", "res.status().send (previously missed sink)"),
    tp("JS-XSS-TP-007", "res.contentType('text/html').send"),
    tp("JS-XSS-TP-008", "res.setHeader text/html then res.end"),
    tp("JS-XSS-TP-009", "res.write of request HTML"),
    tp("JS-XSS-TP-010", "file read with an encoding, sent through a variable (string, not Buffer)"),
    tp("JS-XSS-TP-011", "res.type('html').status().send"),
    tp("JS-XSS-TP-012", "cookie value reflected into HTML"),
    tp("JS-XSS-TP-013", "res.status().type('html').send of a header value"),
], cwe=["CWE-79"], allowed_other=["path-traversal"])
group("js-xss", "javascript", "cases/sast/javascript/xss/safe.js", "xss", XSS_RULE, [
    tn("JS-XSS-TN-001", "binary file response: inline fs.readFileSync Buffer (original FP)"),
    tn("JS-XSS-TN-002", "binary file response via res.status().send"),
    tn("JS-XSS-TN-003", "binary file response via await fs.promises.readFile"),
    tn("JS-XSS-TN-004", "escape-html"),
    tn("JS-XSS-TN-005", "he.encode"),
    tn("JS-XSS-TN-006", "static HTML"),
    tn("JS-XSS-TN-007", "res.json"),
    tn("JS-XSS-TN-008", "object body (JSON)"),
    tn("JS-XSS-TN-009", "res.type('text/plain').send"),
    tn("JS-XSS-TN-010", "handler sets text/plain"),
    tn("JS-XSS-TN-011", "DOMPurify.sanitize"),
    gap("JS-XSS-TN-012", "not_detected", "Number() output is safe, but Number is not a modelled XSS sanitizer"),
    tn("JS-XSS-TN-013", "application/json typed JSON.stringify"),
], cwe=["CWE-79"])
group("js-xss", "typescript", "cases/sast/typescript/xss/handlers.ts", "xss", XSS_RULE, [
    tp("TS-XSS-TP-001", "typed handler, template literal HTML"),
    tp("TS-XSS-TP-002", "typed handler, res.type('html').send"),
    tp("TS-XSS-TP-003", "typed handler, res.status().send"),
    tn("TS-XSS-TN-001", "typed handler, binary asset response"),
    tn("TS-XSS-TN-002", "typed handler, escape-html"),
    tn("TS-XSS-TN-003", "typed handler, static HTML"),
], cwe=["CWE-79"])

# --------------------------------------------------------------------------------------------- issue 7
PHP = "cases/sast/php/"
group("php-sql-xpath", "php", PHP + "sql-injection/queries.php", "sql-injection", ["TG-TAINT-PHP-SQL-INJECTION"], [
    tp("PHP-SQL-TP-001", "mysqli_query with $_GET concatenation"),
    tp("PHP-SQL-TP-002", "new PDO()->query with $_POST"),
    tp("PHP-SQL-TP-003", "PDO-typed parameter ->query"),
    tp("PHP-SQL-TP-004", "new mysqli()->query with $_REQUEST"),
    tp("PHP-SQL-TP-005", "untyped framework handle $this->db->query"),
    tp("PHP-SQL-TP-006", "PDO->exec with $_POST"),
    tp("PHP-SQL-TP-007", "Doctrine Connection-typed parameter with $_COOKIE"),
    tp("PHP-SQL-TP-008", "nullable ?PDO parameter"),
    tp("PHP-SQL-TP-009", "SQL built in a variable"),
    tp("PHP-SQL-TP-010", "superglobal interpolated in a double-quoted string"),
    tn("PHP-SQL-TN-001", "PDO prepared statement with bound parameters"),
    tn("PHP-SQL-TN-002", "static query"),
    tn("PHP-SQL-TN-003", "mysqli prepared statement with bind_param"),
    tn("PHP-SQL-TN-004", "server-side constant table name"),
    gap("PHP-SQL-TN-005", "not_detected", "(int) cast is safe, but the rule has no sanitizers"),
], cwe=["CWE-89"], forbidden=["xpath-injection"])
group("php-sql-xpath", "php", PHP + "xpath-injection/lookup.php", "xpath-injection", ["TG-TAINT-PHP-XPATH-INJECTION"], [
    tp("PHP-XPATH-TP-001", "DOMXPath::query with $_GET"),
    tp("PHP-XPATH-TP-002", "DOMXPath::evaluate with $_POST"),
    tp("PHP-XPATH-TP-003", "DOMXPath-typed parameter"),
    tp("PHP-XPATH-TP-004", "SimpleXMLElement::xpath"),
    tp("PHP-XPATH-TP-005", "simplexml_load_string()->xpath with $_COOKIE"),
    tp("PHP-XPATH-TP-006", "simplexml_load_file()->xpath"),
    tp("PHP-XPATH-TP-007", "expression built in a variable"),
    tp("PHP-XPATH-TP-008", "superglobal interpolated in the expression"),
    tp("PHP-XPATH-TP-009", "nullable ?DOMXPath parameter"),
    tp("PHP-XPATH-TP-010", "fully qualified new \\DOMXPath"),
    tn("PHP-XPATH-TN-001", "static XPath expression"),
    tn("PHP-XPATH-TN-002", "server-side constant field"),
    tn("PHP-XPATH-TN-003", "static SimpleXML xpath"),
    gap("PHP-XPATH-TN-004", "not_detected", "(int) cast is safe, but the rule has no sanitizers"),
], cwe=["CWE-643"], forbidden=["sql-injection"])
group("php-sql-xpath", "php", PHP + "query-methods/clients.php", "sql-injection", ["TG-TAINT-PHP-SQL-INJECTION"], [
    tn("PHP-QRY-TN-001", "SearchClient-typed ->query is not SQL"),
    tn("PHP-QRY-TN-002", "new SolrClient()->query is not SQL"),
    tn("PHP-QRY-TN-003", "new GraphQLClient()->query is not SQL"),
    tn("PHP-QRY-TN-004", "GraphQL\\Client-typed ->query is not SQL"),
    tn("PHP-QRY-TN-005", "new ElasticClient()->query is not SQL"),
    tn("PHP-QRY-TN-006", "Uri-typed ->query is not SQL"),
    gap("PHP-QRY-TN-007", "not_detected",
        "receiver from a container factory has no visible type; the rule treats unknown receivers as databases by design"),
], cwe=["CWE-89"])
group("php-sql-xpath", "php", PHP + "query-methods/clients.php", "xpath-injection", ["TG-TAINT-PHP-XPATH-INJECTION"], [
    tp("PHP-QRY-XPATH-001", "DOMXPath::query beside search clients: XPath, never SQL"),
], cwe=["CWE-643"], forbidden=["sql-injection"])

# --------------------------------------------------------------------------------------------- issue 8
PY = "cases/sast/python/sql-injection/"
group("python-sql-taint", "python", PY + "flask_views.py", "sql-injection", ["TG-TAINT-PY-SQL-INJECTION"], [
    tp("PY-SQLT-TP-001", "f-string with request.args"),
    tp("PY-SQLT-TP-002", "concatenation with request.form"),
    tp("PY-SQLT-TP-003", "% formatting with request.args"),
    tp("PY-SQLT-TP-004", ".format() with request.cookies"),
    tp("PY-SQLT-TP-005", "query assembled in a variable"),
    tp("PY-SQLT-TP-006", "route parameter"),
    tp("PY-SQLT-TP-007", "int() on one value does not clear the other (f-string)"),
    tp("PY-SQLT-TP-008", "int() on one value does not clear the other (concatenation)"),
    tp("PY-SQLT-TP-009", "executemany with concatenated text"),
    tp("PY-SQLT-TP-010", "% tuple mixing int() and a raw value"),
    tn("PY-SQLT-TN-001", "str(int(...)) concatenation"),
    tn("PY-SQLT-TN-002", "% float(...)"),
    tn("PY-SQLT-TN-003", "f-string {int(...)}"),
    tn("PY-SQLT-TN-004", "parameterized ? query"),
    tn("PY-SQLT-TN-005", "parameterized query with a list"),
    tn("PY-SQLT-TN-006", "static query"),
    tn("PY-SQLT-TN-007", "int() result held in a variable"),
    tn("PY-SQLT-TN-008", "trusted module constant table name"),
    tn("PY-SQLT-TN-009", ".format(float(...))"),
    tn("PY-SQLT-TN-010", "%d % int(...)"),
], cwe=["CWE-89"],
    note="TG-SQL-INJECTION-PY-INLINE is also a sql-injection rule; a negative must be quiet for both.")

# --------------------------------------------------------------------------------------------- issue 13
INLINE = ["TG-SQL-INJECTION-PY-INLINE"]
group("python-inline-sql", "python", PY + "inline_queries.py", "sql-injection", INLINE, [
    tp("PY-SQLI-TP-001", "unsafe f-string"),
    tp("PY-SQLI-TP-002", "unsafe concatenation"),
    tp("PY-SQLI-TP-003", "unsafe .format()"),
    tp("PY-SQLI-TP-004", "unsafe % formatting"),
    tp("PY-SQLI-TP-005", "f-string mixing {int(...)} and a raw placeholder"),
    tp("PY-SQLI-TP-006", "concatenation mixing str(int(...)) and a raw value"),
    tp("PY-SQLI-TP-007", "db.raw concatenation"),
    tp("PY-SQLI-TP-008", "executemany f-string with a table name"),
    tp("PY-SQLI-TP-009", "f-string assigned to a variable first"),
    tp("PY-SQLI-TP-010", "concatenation mixing str(float(...)) and a raw value"),
], cwe=["CWE-89"])
group("python-inline-sql", "python", PY + "inline_numeric.py", "sql-injection", INLINE, [
    tn("PY-SQLI-TN-001", "f-string {int(...)}"),
    tn("PY-SQLI-TN-002", "f-string {float(...)}"),
    tn("PY-SQLI-TN-003", "str(int(...)) concatenation"),
    tn("PY-SQLI-TN-004", "str(float(...)) concatenation with a literal tail"),
    tn("PY-SQLI-TN-005", "%d % int(...)"),
    tn("PY-SQLI-TN-006", ".format(float(...))"),
    tn("PY-SQLI-TN-007", "two numeric placeholders, both int(...)"),
    tn("PY-SQLI-TN-008", "one placeholder holding a variable assigned from int()"),
    tn("PY-SQLI-TN-009", "parameterized query"),
    tn("PY-SQLI-TN-010", "static query"),
    gap("PY-SQLI-GAP-002", "not_detected",
        "several placeholders holding int() variables: the multi-placeholder branch reads the text only"),
    gap("PY-SQLI-GAP-003", "not_detected", "helper returning int(): the rule cannot see through the call"),
], cwe=["CWE-89"])
group("python-inline-sql", "python", PY + "inline_shadowed.py", "sql-injection", INLINE, [
    gap("PY-SQLI-GAP-001", "detected", "shadowed int() returns raw input; the rule trusts the name"),
    gap("PY-SQLI-GAP-004", "detected", "shadowed float() returns raw input; the rule trusts the name"),
], cwe=["CWE-89"])

# --------------------------------------------------------------------------------------------- issue 9
JX = "cases/sast/java/xss/src/main/java/com/example/regression/"
group("java-xss", "java", JX + "ReflectingServlet.java", "xss", ["JAVA-011"], [
    tp("JAVA-XSS-TP-001", "getParameter concatenated into println"),
    tp("JAVA-XSS-TP-002", "parameter through a variable into write"),
    tp("JAVA-XSS-TP-003", "Referer header into print"),
    tp("JAVA-XSS-TP-004", "partial escape (< and > only) stays reported"),
    tp("JAVA-XSS-TP-005", "query string into append"),
    tp("JAVA-XSS-TP-006", "escape chain with & last double-decodes: not a complete escape"),
    tp("JAVA-XSS-TP-007", "getOutputStream().print"),
    tp("JAVA-XSS-TP-008", "parameter variable concatenated after text"),
    tp("JAVA-XSS-TP-009", "cookie value"),
    tp("JAVA-XSS-TP-010", "parameter first, literal second"),
    gap("JAVA-XSS-GAP-001", "detected", "writer held in a variable: JAVA-011 needs resp.getWriter() inline"),
    gap("JAVA-XSS-GAP-002", "detected", "no concatenation: JAVA-011 only matches $X + $Y"),
], cwe=["CWE-79"])
group("java-xss", "java", JX + "EncodedOutputServlet.java", "xss", ["JAVA-011"], [
    tn("JAVA-XSS-TN-001", "int from Integer.parseInt"),
    tn("JAVA-XSS-TN-002", "long between literals"),
    tn("JAVA-XSS-TN-003", "double"),
    tn("JAVA-XSS-TN-004", "boolean"),
    tn("JAVA-XSS-TN-005", "complete escape chain through a variable"),
    tn("JAVA-XSS-TN-006", "complete escape chain inline plus an extra replace"),
    tn("JAVA-XSS-TN-007", "OWASP Encode.forHtml"),
    tn("JAVA-XSS-TN-008", "StringEscapeUtils.escapeHtml4"),
    tn("JAVA-XSS-TN-009", "Spring HtmlUtils.htmlEscape"),
    tn("JAVA-XSS-TN-010", "three literals"),
    tn("JAVA-XSS-TN-011", "static final String constant"),
    tn("JAVA-XSS-TN-012", "short"),
], cwe=["CWE-79"])

# --------------------------------------------------------------------------------------------- issue 10
CF = "cases/sast/cpp/format-string/"
group("cpp-format-string", "c", CF + "format_unsafe.c", "format-string", ["CPP-002"], [
    tp("CPP-FMT-TP-001", "printf(argv[1])"),
    tp("CPP-FMT-TP-002", "fprintf(stderr, user_msg)"),
    tp("CPP-FMT-TP-003", "snprintf with a non-literal format (newly covered)"),
    tp("CPP-FMT-TP-004", "sprintf with a non-literal format (newly covered)"),
    tp("CPP-FMT-TP-007", "printf(getenv(...))"),
    tp("CPP-FMT-TP-008", "fprintf of a line read with fgets"),
    tp("CPP-FMT-TP-009", "snprintf of an array element"),
    gap("CPP-FMT-GAP-001", "detected", "non-literal format with further arguments: CPP-002 matches the one-argument form"),
], cwe=["CWE-134"])
group("cpp-format-string", "c", CF + "format_unsafe.c", "format-string", ["CPP-027"], [
    tp("CPP-FMT-TP-005", "syslog(priority, msg)"),
    tp("CPP-FMT-TP-006", "vsyslog(priority, fmt, ap)"),
], cwe=["CWE-134"])
group("cpp-format-string", "c", CF + "format_safe.c", "format-string", ["CPP-002", "CPP-027"], [
    tn("CPP-FMT-TN-001", "printf(\"%s\", argv[1])"),
    tn("CPP-FMT-TN-002", "fprintf with a literal format"),
    tn("CPP-FMT-TN-003", "snprintf with a literal format"),
    tn("CPP-FMT-TN-004", "sprintf(\"%d\")"),
    tn("CPP-FMT-TN-005", "printf literal"),
    tn("CPP-FMT-TN-006", "fprintf(stderr, \"\\n\")"),
    tn("CPP-FMT-TN-007", "syslog with a literal format"),
    tn("CPP-FMT-TN-008", "snprintf with several arguments and a literal format"),
    tn("CPP-FMT-TN-009", "puts is not a format function"),
    tn("CPP-FMT-TN-010", "macro expanding to a literal format"),
], cwe=["CWE-134"])
group("cpp-format-string", "cpp", CF + "report.cpp", "format-string", ["CPP-002"], [
    tp("CPP-FMT-TP-010", "printf(std::string::c_str()) in C++"),
    tn("CPP-FMT-TN-011", "printf with a literal format in C++"),
    tn("CPP-FMT-TN-012", "snprintf with a literal format in C++"),
], cwe=["CWE-134"])

# --------------------------------------------------------------------------------------------- issue 11
FMT = ["TG-TAINT-JS-FORMAT-STRING"]
LOG = ["TG-TAINT-JS-LOG-INJECTION"]
JF = "cases/sast/javascript/format-string/"
group("js-format-string-log-injection", "javascript", JF + "request-formats.js", "format-string", FMT, [
    tp("JS-FMT-TP-001", "query value as console.log format with an argument"),
    tp("JS-FMT-TP-002", "body template to util.format"),
    tp("JS-FMT-TP-003", "header value as console.error format"),
    tp("JS-FMT-TP-004", "uploaded file name (multer req.file) as format"),
    tp("JS-FMT-TP-005", "ws server message as format"),
    tp("JS-FMT-TP-006", "net server socket data as format"),
    tp("JS-FMT-TP-007", "util.formatWithOptions with a request format"),
    tp("JS-FMT-TP-008", "template literal embedding a request value as format"),
    tp("JS-FMT-TP-009", "route parameter through a variable"),
    tp("JS-FMT-TP-010", "socket.io event payload as format"),
    tp("JS-FMT-TP-011", "request value concatenated into the format"),
], cwe=["CWE-134"], allowed_other=["log-injection"])
group("js-format-string-log-injection", "javascript", JF + "trusted-formats.js", "format-string", FMT, [
    tn("JS-FMT-TN-001", "constant format, request values as arguments"),
    tn("JS-FMT-TN-002", "one argument only: no specifier is applied"),
    tn("JS-FMT-TN-003", "OWASP Juice Shop server.ts:157 - internal name concatenated into console.error"),
    tn("JS-FMT-TN-004", "internal constant list value concatenated"),
    tn("JS-FMT-TN-005", "database-derived template: unknown origin, not a modelled source"),
    tn("JS-FMT-TN-006", "file-derived template: unknown origin, not a modelled source"),
    tn("JS-FMT-TN-007", "% escaped with replace(/%/g, '%%')"),
    tn("JS-FMT-TN-008", "% escaped with replaceAll('%', '%%')"),
    tn("JS-FMT-TN-009", "IPC process message: not a server socket"),
    tn("JS-FMT-TN-010", "previously stored user input from the ORM: unknown origin by policy"),
    tn("JS-FMT-TN-011", "util.format with a constant format"),
], cwe=["CWE-134"], allowed_other=["log-injection"],
    note=("The upstream " + UPSTREAM_FORMATSTRING + " (registry pack p/default) is not in "
          "scanscope.ExcludedUpstreamRules; it treats any concatenation as a source, so TN-003/TN-004 "
          "are where an incomplete exclusion shows."))
group("js-format-string-log-injection", "javascript", JF + "trusted-formats.js", "log-injection", LOG, [
    tp("JS-LOG-TP-011", "request path logged as an argument of a constant format"),
    tp("JS-LOG-TP-006", "single-argument console.log of a request value"),
], cwe=["CWE-117"], allowed_other=["format-string"])
JL = "cases/sast/javascript/log-injection/log-sinks.js"
group("js-format-string-log-injection", "javascript", JL, "log-injection", LOG, [
    tp("JS-LOG-TP-001", "login name concatenated into the log"),
    tp("JS-LOG-TP-002", "template literal with a query value"),
    tp("JS-LOG-TP-003", "uploaded file name"),
    tp("JS-LOG-TP-004", "ws server message"),
    tp("JS-LOG-TP-005", "User-Agent header alone"),
    tp("JS-LOG-TP-007", "route parameter through a variable"),
    tp("JS-LOG-TP-008", "replace that strips '<' but leaves CR/LF"),
    tp("JS-LOG-TP-009", "cookie value"),
    tp("JS-LOG-TP-010", "socket.io event payload"),
    gap("JS-LOG-TP-012", "detected", "pino logger: only console.* is a modelled sink"),
    tn("JS-LOG-TN-001", "JSON.stringify escapes CR/LF"),
    tn("JS-LOG-TN-002", "CR/LF removed"),
    tn("JS-LOG-TN-003", "encodeURIComponent"),
    tn("JS-LOG-TN-004", "parseInt"),
    tn("JS-LOG-TN-005", "object argument (inspected, newlines escaped)"),
    tn("JS-LOG-TN-006", "array argument"),
    tn("JS-LOG-TN-007", "static message"),
    tn("JS-LOG-TN-008", "util.inspect"),
    tn("JS-LOG-TN-009", "internal parameter"),
    tn("JS-LOG-TN-010", "Number()"),
    tn("JS-LOG-TN-011", "IPC message: not a server socket"),
    tn("JS-LOG-TN-012", "control characters replaced"),
], cwe=["CWE-117"], allowed_other=["format-string"])
TF = "cases/sast/typescript/format-string/logging.ts"
group("js-format-string-log-injection", "typescript", TF, "format-string", FMT, [
    tp("TS-FMT-TP-001", "typed handler, request value as console.log format"),
    tp("TS-FMT-TP-002", "typed handler, util.format template from the body"),
    tn("TS-FMT-TN-001", "typed handler, constant format"),
], cwe=["CWE-134"], allowed_other=["log-injection"])
group("js-format-string-log-injection", "typescript", TF, "log-injection", LOG, [
    tp("TS-LOG-TP-001", "typed handler, request value logged raw"),
    tp("TS-LOG-TP-002", "typed handler, concatenated request value"),
    tn("TS-LOG-TN-001", "typed handler, JSON.stringify"),
], cwe=["CWE-117"], allowed_other=["format-string"])

# --------------------------------------------------------------------------------------------- issue 12
ZT = ["TG-TAINT-JS-ZIP-SLIP"]
ZL = ["TG-JS-ZIP-SLIP-ENTRIES-LOOP"]
ZR = ["TG-JS-TAR-PRESERVE-PATHS"]
ZU = "cases/sast/javascript/zip-slip/extract-unsafe.js"
ZS = "cases/sast/javascript/zip-slip/extract-safe.js"
for cid, rules, desc in [
    ("JS-ZIP-TP-001", ZT, "JSZip forEach relativePath"),
    ("JS-ZIP-TP-002", ZT, "Object.keys(zip.files) loop"),
    ("JS-ZIP-TP-003", ZL, "Object.entries(zip.files) loop, name used directly"),
    ("JS-ZIP-TP-004", ZL, "Object.entries(zip.files) loop, one variable hop"),
    ("JS-ZIP-TP-005", ZT, "unzipper.Open directory.files entry path"),
    ("JS-ZIP-TP-006", ZT, "unzipper.Parse 'entry' event path"),
    ("JS-ZIP-TP-007", ZT, "yauzl 'entry' event fileName"),
    ("JS-ZIP-TP-008", ZT, "adm-zip entryName"),
    ("JS-ZIP-TP-009", ZR, "tar.x with preservePaths: true"),
    ("JS-ZIP-TP-010", ZR, "tar.extract with preservePaths: true"),
    ("JS-ZIP-TP-011", ZT, "absolute entry name through path.resolve"),
    ("JS-ZIP-TP-012", ZT, "startsWith(dest) without a separator is not containment"),
    ("JS-ZIP-TP-013", ZT, "Object.values(zip.files) entry.name"),
]:
    group("zip-slip", "javascript", ZU, "path-traversal", rules, [tp(cid, desc)], cwe=PT_CWE)
group("zip-slip", "javascript", ZS, "path-traversal", ZT + ZL + ZR, [
    tn("JS-ZIP-TN-001", "JSZip forEach with path.relative containment"),
    tn("JS-ZIP-TN-002", "Object.keys loop with startsWith(dest + path.sep)"),
    tn("JS-ZIP-TN-003", "Object.entries loop with path.relative containment"),
    tn("JS-ZIP-TN-004", "adm-zip with path.relative containment"),
    tn("JS-ZIP-TN-005", "yauzl with path.relative containment"),
    tn("JS-ZIP-TN-006", "unzipper.Open with startsWith(dest + path.sep)"),
    tn("JS-ZIP-TN-007", "tar.x default (node-tar strips / and ..)"),
    tn("JS-ZIP-TN-008", "tar.x with preservePaths: false"),
    gap("JS-ZIP-TN-009", "not_detected", "path.basename removes directories, but is not a modelled sanitizer"),
    tn("JS-ZIP-TN-010", "server-generated file name"),
    tn("JS-ZIP-TN-011", "adm-zip extractAllTo (library-side containment)"),
], cwe=PT_CWE)
ZTS = "cases/sast/typescript/zip-slip/extract.ts"
for cid, rules, desc in [("TS-ZIP-TP-001", ZL, "typed Object.entries loop with a typed variable hop"),
                         ("TS-ZIP-TP-002", ZT, "typed adm-zip entryName"),
                         ("TS-ZIP-TP-003", ZR, "tar.x with preservePaths: true")]:
    group("zip-slip", "typescript", ZTS, "path-traversal", rules, [tp(cid, desc)], cwe=PT_CWE)
group("zip-slip", "typescript", ZTS, "path-traversal", ZT + ZL + ZR, [
    tn("TS-ZIP-TN-001", "typed Object.entries loop with containment"),
    tn("TS-ZIP-TN-002", "typed adm-zip with startsWith(dest + path.sep)"),
    tn("TS-ZIP-TN-003", "tar.x default"),
], cwe=PT_CWE)
group("zip-slip", "python", "cases/sast/python/zip-slip/archives.py", "path-traversal",
      ["trailofbits.python.tarfile-extractall-traversal.tarfile-extractall-traversal"], [
    tp("PY-ZIP-TP-001", "tarfile extractall without members"),
    tn("PY-ZIP-TN-001", "extractall with a filtered members list"),
    gap("PY-ZIP-TN-002", "not_detected", "filter='data' (Python 3.12) is safe, but the registry rule only knows members="),
], cwe=PT_CWE, note="Registry rule from p/trailofbits; no TigerGate catalog rule covers Python archives.")
group("zip-slip", "go", "cases/sast/go/zip-slip/untar.go", "path-traversal", ["GO-034"], [
    tp("GO-ZIP-TP-001", "filepath.Join(dest, header.Name) without a prefix check"),
    tn("GO-ZIP-TN-001", "HasPrefix containment check inside the loop"),
], cwe=PT_CWE)
group("zip-slip", "java", "cases/sast/java/zip-slip/src/main/java/com/example/regression/ZipImporter.java",
      "path-traversal", [], [
    gap("JAVA-ZIP-GAP-001", "detected", "ZipEntry.getName into new File(dest, name): no Java zip-slip rule exists"),
], cwe=PT_CWE, note="Coverage gap, not a regression: no catalog rule targets Java archive extraction.")

# --------------------------------------------------------------------------------------------- issues 4/5
S = "cases/secrets/"
SEC_CWE = ["CWE-798"]
G, AWS, JWT, PK = SECRET_RULES["generic"], SECRET_RULES["aws-key-id"], SECRET_RULES["jwt"], SECRET_RULES["private-key"]


def secret(issue, file, rules, cases):
    group(issue, "secrets", file, "hardcoded-secret", rules, cases, finding_type="secret", cwe=SEC_CWE)


secret("secret-false-positives", S + "true-positive/billing_client.py", G,
       [tp("SEC-TP-001", "synthetic high-entropy API key assignment")])
secret("secret-false-positives", S + "true-positive/aws_profile.py", AWS,
       [tp("SEC-TP-002", "synthetic AWS access key ID (no account, not an EXAMPLE key)")])
secret("secret-false-positives", S + "true-positive/session.js", JWT,
       [tp("SEC-TP-003", "synthetic HS256 JWT with a random signature")])
secret("secret-false-positives", S + "true-positive/keys/deploy-signing.pem", PK,
       [tp("SEC-TP-004", "synthetic PEM private key block (random body, not a key)", anchor="-----BEGIN PRIVATE KEY-----")])
secret("secret-false-positives", S + "true-positive/gcp-service-account.json", PK,
       [tp("SEC-TP-005", "private_key in a service-account file", anchor="\"private_key\":")])
secret("secret-false-positives", S + "true-positive/gcp-service-account.json", G + ["gcp-service-account"], [
    tn("SEC-FP-011", "service-account type marker beside a real key", anchor="\"type\": \"service_account\""),
    tn("SEC-FP-012", "private_key_id (40 hex) names the key, it is not the key", anchor="\"private_key_id\":"),
])
secret("secret-false-positives", S + "false-positive/aws_docs_example.py", AWS + ["aws-secret-access-key", "generic-api-key"], [
    tn("SEC-FP-001", "AWS documentation example access key ID"),
    tn("SEC-FP-002", "AWS documentation example secret access key"),
])
secret("secret-false-positives", S + "false-positive/locales/de/messages.json", G, [
    tn("SEC-FP-003", "translation label under a password key", anchor="BTN_RESET_PASSWORD"),
    tn("SEC-FP-015", "translation label with spaces under a token key", anchor="LABEL_API_TOKEN"),
    tn("SEC-FP-016", "translation label under a secret key", anchor="HINT_SECRET_QUESTION"),
])
secret("secret-false-positives", S + "false-positive/placeholders.py", G + ["github-pat"], [
    tn("SEC-FP-006", "ghp_ followed by 36 x: placeholder token"),
    tn("SEC-FP-007", "your-api-key-here placeholder"),
    tn("SEC-FP-008", "changeme placeholder"),
    tn("SEC-FP-009", "${AUTH_TOKEN} environment reference"),
    tn("SEC-FP-010", "os.environ lookup"),
])
secret("secret-false-positives", S + "false-positive/service-account-template.json", G + ["gcp-service-account"], [
    tn("SEC-FP-004", "service-account type marker without key material", anchor="\"type\": \"service_account\""),
    tn("SEC-FP-005", "GCP private_key_id field", anchor="\"private_key_id\":"),
])
secret("secret-false-positives", S + "false-positive/wallet.js", G, [
    tn("SEC-FP-013", "public Ethereum address in a key-named variable"),
    tn("SEC-FP-014", "low-entropy repeated character value"),
])
secret("secret-false-positives", S + "edge/commented_key.py", G, [
    tp("SEC-EDGE-001", "credential in a commented-out line: the secret engine skips comments, the SAST copy keeps it",
       anchor="# LEGACY_API_KEY"),
])
secret("secret-false-positives", S + "edge/locales/fr/keys.json", G, [
    tp("SEC-EDGE-002", "digit-bearing single token in a locale file: kept by the SAST-copy filter", anchor="API_KEY_PREVIEW"),
])
secret("secret-duplicates", S + "duplicate-detection/multi_rule.js", AWS,
       [tp("SEC-DUP-001", "one AWS key ID matched by the secret engine and several SAST secret packs: one finding")])
secret("secret-duplicates", S + "duplicate-detection/same_line.js", G,
       [tp("SEC-DUP-002", "two distinct secrets on one line: two findings", count=2)])
secret("secret-duplicates", S + "duplicate-detection/nearby.py", G, [
    tp("SEC-DUP-003A", "first of two distinct keys on adjacent lines"),
    tp("SEC-DUP-003B", "second of two distinct keys on adjacent lines"),
])
secret("secret-duplicates", S + "duplicate-detection/identical-a/settings.py", G,
       [tp("SEC-DUP-004A", "identical value in two files: reported once, at the first path")])
secret("secret-duplicates", S + "duplicate-detection/identical-b/settings.py", G,
       [tn("SEC-DUP-004B", "identical value repeated: collapsed into SEC-DUP-004A by SecretDeduper",
           duplicate_of="SEC-DUP-004A")])
secret("secret-duplicates", S + "duplicate-detection/mixed_types.js", G,
       [tp("SEC-DUP-005A", "generic API key beside an AWS key ID")])
secret("secret-duplicates", S + "duplicate-detection/mixed_types.js", AWS,
       [tp("SEC-DUP-005B", "AWS key ID beside a generic API key")])
secret("secret-duplicates", S + "duplicate-detection/service-config.yaml", G, [
    tp("SEC-DUP-006A", "first of three credentials in one config file", anchor="  api_key: jkMif"),
    tp("SEC-DUP-006B", "second of three credentials in one config file", anchor="  api_key: K35h"),
    tp("SEC-DUP-006C", "third of three credentials in one config file", anchor="  secret_key:"),
])
secret("loc-exclusions", "loc/minified/analytics.min.js", G, [
    tp("SEC-LOC-001", "minified bundle is excluded from LOC and SAST but must still be secret-scanned",
       anchor="apiKey:"),
])

# SCA: a lockfile excluded from LOC is still the dependency manifest SCA reads.
group("loc-exclusions", "javascript", "loc/excluded-files/package-lock.json", "vulnerable-dependency",
      ["CVE-2021-23337"], [
          tp("SCA-LOC-001", "lodash 4.17.20 in package-lock.json (CVE-2021-23337, command injection in template)",
             anchor="\"node_modules/lodash\""),
      ], finding_type="sca", cwe=["CWE-94"])
