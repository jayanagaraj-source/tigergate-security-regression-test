#!/usr/bin/env python3
"""Build expected/*.manifest.json from scripts/case_catalog.py and the case markers in the fixtures.

  build-manifest.py           write the manifests
  build-manifest.py --check   fail if the committed manifests are stale or a consistency check fails

A case's line is the one line of its file that carries the case ID after code (a trailing comment), or
the one line containing its `anchor` text (data files that cannot hold comments). Checks: IDs are unique,
every marker in a fixture has a case, every case resolves to exactly one line, legacy lines still carry
their legacy marker, and no manifest holds a secret value.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import case_catalog as catalog  # noqa: E402

MANIFESTS = {
    "sast": ROOT / "expected" / "sast.manifest.json",
    "secret": ROOT / "expected" / "secrets.manifest.json",
    "sca": ROOT / "expected" / "sca.manifest.json",
}
ALL = ROOT / "expected" / "findings.manifest.json"
MARKER = re.compile(r"\b((?:TG-PATH|JS|TS|PHP|PY|JAVA|CPP|GO|SEC|SCA)-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3}[A-Z]?)\b")
COMMENT_START = ("//", "#", "/*", "*", "<!--", "--")
FIXTURE_ROOTS = ("cases", "loc")


def code_part_has_marker(line, cid):
    """True when cid sits in a trailing comment after code on this line."""
    stripped = line.strip()
    if stripped.startswith(COMMENT_START):
        return False
    return re.search(r"\b" + re.escape(cid) + r"\b", line) is not None


def resolve_line(case, path, lines, errors):
    cid = case["id"]
    if "anchor" in case:
        hits = [i for i, l in enumerate(lines, 1) if case["anchor"] in l]
        what = "anchor %r" % case["anchor"]
    else:
        hits = [i for i, l in enumerate(lines, 1) if code_part_has_marker(l, cid)]
        what = "marker"
        # The same marker on the line that builds the value (a query in a variable) and on the sink.
        if len(hits) == 2 and hits[1] - hits[0] < MAX_SPAN:
            case["_span_from"] = hits[0]
            hits = hits[1:]
    if "line" in case:
        if case["line"] > len(lines) or not re.search(r"\b" + re.escape(cid) + r"\b", lines[case["line"] - 1]):
            errors.append("%s: pinned line %d of %s no longer carries the marker" % (cid, case["line"], path))
        return case["line"]
    if len(hits) != 1:
        errors.append("%s: %s matches %d lines in %s (need exactly 1)" % (cid, what, len(hits), path))
        return None
    return hits[0]


STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
MAX_SPAN = 6


def statement_span(lines, line):
    """[line, end]: the marker line through the line where its brackets close (a call split over lines)."""
    depth = 0
    for i in range(line, min(len(lines), line + MAX_SPAN - 1) + 1):
        text = STRING_LITERAL.sub('""', lines[i - 1])
        depth += text.count("(") + text.count("[") - text.count(")") - text.count("]")
        if depth <= 0:
            return [line, i]
    return [line, line]


def build():
    errors, cases, seen = [], [], set()
    file_cache = {}
    for g in catalog.GROUPS:
        path = ROOT / g["file"]
        if not path.is_file():
            errors.append("missing fixture file: %s" % g["file"])
            continue
        lines = file_cache.setdefault(g["file"], path.read_text(encoding="utf-8").splitlines())
        for c in g["cases"]:
            if c["id"] in seen:
                errors.append("duplicate case id: %s" % c["id"])
            seen.add(c["id"])
            line = resolve_line(c, g["file"], lines, errors)
            entry = {
                "test_id": c["id"],
                "issue": g["issue"],
                "language": g["language"],
                "file": g["file"],
                "expected": c["expected"],
                "finding_type": g["finding_type"],
                "expected_class": g["class"],
                "expected_rule_ids": g["rules"],
                "expected_cwe": g["cwe"],
                "expected_line": line,
                "expected_span": ([c.pop("_span_from", line), statement_span(lines, line)[1]]
                                  if line else None),
                "expected_count": c.get("count", 1),
                "description": c["description"],
                "status": c["status"],
            }
            for key in ("duplicate_of",):
                if key in c:
                    entry[key] = c[key]
            if g["allowed_other_classes"]:
                entry["allowed_other_classes"] = g["allowed_other_classes"]
            if g["forbidden_classes"]:
                entry["forbidden_classes"] = g["forbidden_classes"]
            if c.get("legacy"):
                entry["legacy_corpus"] = True
            if g["note"]:
                entry["notes"] = g["note"]
            cases.append(entry)

    # Every marker written in a fixture must belong to a case (catches typos and orphaned markers).
    for top in FIXTURE_ROOTS:
        for f in sorted((ROOT / top).rglob("*")):
            if not f.is_file():
                continue
            try:
                text = f.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for i, l in enumerate(text.splitlines(), 1):
                for m in MARKER.findall(l):
                    if m not in seen and code_part_has_marker(l, m):
                        errors.append("%s:%d: marker %s has no case in case_catalog.py" % (f.relative_to(ROOT), i, m))
    for c in cases:
        if c.get("duplicate_of") and c["duplicate_of"] not in seen:
            errors.append("%s: duplicate_of names unknown case %s" % (c["test_id"], c["duplicate_of"]))
    return cases, errors


def render(cases):
    out = {}
    for kind, path in MANIFESTS.items():
        subset = [c for c in cases if c["finding_type"] == kind]
        out[path] = {
            "schema_version": 1,
            "generated_by": "scripts/build-manifest.py from scripts/case_catalog.py",
            "line_convention": "1-based line of the sink (marker line); expected_span runs to the line where "
                               "that statement's brackets close. A finding matches when its start..end range "
                               "intersects expected_span (SCA: file-level).",
            "cases": subset,
        }
    out[ALL] = {
        "schema_version": 1,
        "generated_by": "scripts/build-manifest.py from scripts/case_catalog.py",
        "issues": catalog.ISSUES,
        "cases": cases,
    }
    return {p: json.dumps(doc, indent=2, ensure_ascii=False) + "\n" for p, doc in out.items()}


def secret_values():
    """Literal secret-shaped values from the secret fixtures; none may appear in a manifest."""
    values = set()
    for f in (ROOT / "cases" / "secrets").rglob("*"):
        if f.is_file():
            for m in re.finditer(r"[A-Za-z0-9+/_\-]{20,}", f.read_text(encoding="utf-8")):
                values.add(m.group(0))
    return values


def main():
    check = "--check" in sys.argv
    cases, errors = build()
    rendered = render(cases)
    leaked = [(p.name, v) for p, text in rendered.items() for v in secret_values() if v in text]
    for name, _ in leaked:
        errors.append("%s would contain a secret value from cases/secrets" % name)
    if errors:
        print("\n".join("ERROR: " + e for e in errors))
        return 1
    if check:
        stale = [p.name for p, text in rendered.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
        if stale:
            print("ERROR: stale manifests (run make manifest): " + ", ".join(stale))
            return 1
        print("manifests up to date: %d cases" % len(cases))
        return 0
    for p, text in rendered.items():
        p.write_text(text, encoding="utf-8")
    print("wrote %d cases to %s" % (len(cases), ", ".join(p.name for p in rendered)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
