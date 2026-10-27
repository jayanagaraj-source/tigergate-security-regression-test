#!/usr/bin/env python3
"""Combine verification results into reports/REPORT.md.

  generate-report.py [--compare A.json B.json] [--out reports/REPORT.md]

Reads every reports/*.json written by verify-findings.py (--json-out) and verify-loc.py (--json-out).
--compare lists the cases whose outcome differs between two findings results, e.g. a Dashboard export
and a CLI export of the same commit; any difference is a Dashboard/CLI consistency issue.
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
MANIFEST = ROOT / "expected" / "findings.manifest.json"
LOC_MANIFEST = ROOT / "expected" / "loc.manifest.json"
# loc/ fixture directories per LOC issue.
LOC_DIRS = {"loc-alignment": ("loc/terraform/", "loc/xml/", "loc/python/", "loc/build-files/", "loc/config/", "loc/app/", "loc/edge/"),
            "loc-exclusions": ("loc/excluded-files/", "loc/generated-code/", "loc/minified/")}


def case_counts():
    cases = json.loads(MANIFEST.read_text(encoding="utf-8"))["cases"]
    issues = json.loads(MANIFEST.read_text(encoding="utf-8"))["issues"]
    loc_files = json.loads(LOC_MANIFEST.read_text(encoding="utf-8"))["files"]
    rows = []
    for key, title in issues.items():
        cs = [c for c in cases if c["issue"] == key]
        sup = [c for c in cs if c["status"] == "supported"]
        lf = [f for f in loc_files if f["file"].startswith(LOC_DIRS.get(key, ("-",)))]
        rows.append((title, sum(c["expected"] == "detected" for c in sup), sum(c["expected"] == "not_detected" for c in sup),
                     sum(c["status"] == "known_gap" for c in cs), sum(c["status"] == "context_dependent" for c in cs),
                     sum(c["expected_count"] for c in sup if c["expected"] == "detected"),
                     "%d / %d" % (sum(f["counted"] for f in lf), sum(not f["counted"] for f in lf)) if lf else "-",
                     ", ".join(sorted({c["language"] for c in cs} | {f["language"] for f in lf if f["language"]}))))
    return rows, len(cases)


def compare(a, b):
    ra = {c["test_id"]: c["outcome"] for c in a["cases"]}
    rb = {c["test_id"]: c["outcome"] for c in b["cases"]}
    return [(t, ra.get(t), rb.get(t)) for t in sorted(set(ra) | set(rb)) if ra.get(t) != rb.get(t)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"))
    ap.add_argument("--out", default=str(REPORTS / "REPORT.md"))
    a = ap.parse_args()

    rows, total = case_counts()
    md = ["# TigerGate security regression report", "",
          "Generated %s. Expected results: `expected/`. A scan that ran is not a pass: only the outcomes below count." %
          datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "",
          "## Case inventory (%d cases)" % total, "",
          "| Issue | Positive | Negative | Known gaps | Context-dependent | Expected findings | LOC files counted / excluded | Languages |",
          "|---|---:|---:|---:|---:|---:|---:|---|"]
    md += ["| %s | %d | %d | %d | %d | %d | %s | %s |" % r for r in rows]

    results = {}
    for p in sorted(REPORTS.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if "summary" in d and "cases" in d:
            results[p.name] = d
    for name, d in results.items():
        md += ["", "## %s (`%s`)" % (d["label"], name), "", "Finding types verified: %s" % (", ".join(d["finding_types_verified"]) or "none"), "",
               "| Issue | TP | FP | FN | TN | Duplicates | Misclassified | Unverified | Known gaps | Precision | Recall | Status |",
               "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|"]
        fmt = lambda v: "n/a" if v is None else "%.3f" % v
        for r in d["summary"]:
            md.append("| %s | %d | %d | %d | %d | %d | %d | %d | %d | %s | %s | %s |" % (
                r["title"], r["TP"], r["FP"], r["FN"], r["TN"], r["Duplicates"], r["Misclassified"], r["Unverified"],
                r["Known gaps"], fmt(r["precision"]), fmt(r["recall"]), r["status"]))
        md.append("")
        md.append("Unattributed findings: %d. Details: `%s`." % (len(d["unattributed"]), name.replace(".json", ".md")))

    for p in sorted(REPORTS.glob("loc*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        md += ["", "## LOC (`%s`)" % p.name, ""]
        for c in d.get("comparisons", []):
            md.append("- %s: expected %s, actual %s%s" % (c["name"], c["expected_total"], c["actual_total"],
                      "" if c["expected_total"] == c["actual_total"] else " (**differs**)"))
        if "worker_cli_identical" in d:
            md.append("- Worker and CLI counters identical: %s" % d["worker_cli_identical"])
        md.append("- SonarCloud: %s" % d.get("sonarcloud", "compared"))

    if a.compare:
        A, B = (json.loads(Path(x).read_text(encoding="utf-8")) for x in a.compare)
        diffs = compare(A, B)
        md += ["", "## Consistency: %s vs %s" % (A["label"], B["label"]), "",
               "%d case outcomes differ." % len(diffs)]
        if diffs:
            md += ["", "| Case | %s | %s |" % (A["label"], B["label"]), "|---|---|---|"]
            md += ["| %s | %s | %s |" % d for d in diffs]
    Path(a.out).write_text("\n".join(md) + "\n", encoding="utf-8")
    print("wrote %s" % a.out)


if __name__ == "__main__":
    main()
