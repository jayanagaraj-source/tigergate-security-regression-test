#!/usr/bin/env python3
"""Compare exported TigerGate scan results with expected/findings.manifest.json.

Usage
  verify-findings.py --findings EXPORT [--findings EXPORT ...] [--label dashboard] [--fold]
                     [--json-out reports/x.json] [--md-out reports/x.md]

EXPORT formats (detected from content): SARIF (CLI raw output / semgrep --sarif), Semgrep JSON,
gitleaks JSON, Trivy JSON, and TigerGate rows (a JSON array of objects with file_path, start_line or
line_start, end_line, rule_id, cwe_ids, scan_type / issue_type, as produced by the read-only SQL in the
README). Pass every export of one scan (SAST + secrets [+ SCA]) together. A finding type with no export
leaves its cases Unverified.

Matching: a finding matches a case when the normalised paths are equal, its start..end range covers the
case line (file-level for SCA), and its vulnerability class (rule-classes.json, else CWE, else rule-ID
text) equals the case class. Findings of other classes on a case line are listed, never counted as proof.
Findings on no case line are Unattributed (each is a possible false positive to review).

--fold approximates the platform's findingfold (same file and class within 3 lines keep one finding);
use it only for raw engine output, never for Dashboard/CLI exports, which are already folded.
"""
import argparse
import csv
import hashlib
import io
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "expected" / "findings.manifest.json"
RULE_CLASSES = ROOT / "expected" / "rule-classes.json"
FOLD_WINDOW = 3

# CWE -> class, aligned with workers/pkg/findingfold CWEClass for the classes under test.
CWE_CLASS = {
    "CWE-22": "path-traversal", "CWE-23": "path-traversal", "CWE-35": "path-traversal", "CWE-36": "path-traversal",
    "CWE-73": "path-traversal",
    "CWE-79": "xss", "CWE-80": "xss",
    "CWE-89": "sql-injection", "CWE-564": "sql-injection",
    "CWE-643": "xpath-injection",
    "CWE-134": "format-string",
    "CWE-117": "log-injection",
    "CWE-798": "hardcoded-secret", "CWE-321": "hardcoded-secret", "CWE-259": "hardcoded-secret",
    "CWE-522": "hardcoded-secret", "CWE-312": "hardcoded-secret", "CWE-540": "hardcoded-secret",
}
TEXT_CLASS = [
    (r"zip.?slip|path.?traversal|tainted.?path|directory.?traversal|tarfile", "path-traversal"),
    (r"xss|cross.?site", "xss"),
    (r"xpath", "xpath-injection"),
    (r"sql", "sql-injection"),
    (r"format.?string|formatstring", "format-string"),
    (r"log.?injection|log.?forging", "log-injection"),
    (r"secret|api.?key|password|token|private.?key|credential", "hardcoded-secret"),
]
SECRET_COPY_PREFIX = "generic.secrets."
VULN_ID = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[\w-]+)$", re.I)


# ------------------------------------------------------------------------------------------- parsing
def norm_path(p):
    p = str(p or "").replace("\\", "/")
    p = re.sub(r"^file://", "", p)
    marker = "tigergate-security-regression-test/"
    if marker in p:
        p = p.split(marker, 1)[1]
    for prefix in ("/workspace/", "/src/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p.lstrip("/")


def as_list(v):
    if v is None:
        return []
    if isinstance(v, str):
        v = v.strip()
        if v.startswith("{") and v.endswith("}"):  # PostgreSQL text[] literal
            return [x.strip().strip('"') for x in v[1:-1].split('","') if x.strip()]
        return [v] if v else []
    return [str(x) for x in v]


def finding(source, ftype, rule, file, start, end=None, cwe=(), message="", value=None):
    f = {
        "source": source, "finding_type": ftype, "rule_id": str(rule or ""), "file": norm_path(file),
        "start_line": int(start or 0), "end_line": int(end or start or 0), "cwe": as_list(cwe), "message": message,
    }
    if value:
        # Fingerprint only: the secret itself never enters a report.
        f["value_fingerprint"] = hashlib.sha256(value.encode()).hexdigest()[:16]
    return f


def parse_sarif(doc, source):
    out = []
    for run in doc.get("runs", []):
        rule_cwe = {}
        for r in (run.get("tool", {}).get("driver", {}).get("rules") or []):
            tags = (r.get("properties") or {}).get("tags") or []
            cwe = [t for t in tags if str(t).upper().startswith("CWE-")]
            rule_cwe[r.get("id")] = cwe
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            region = loc.get("region", {})
            rid = res.get("ruleId", "")
            out.append(finding(source, "sast", rid, loc.get("artifactLocation", {}).get("uri"),
                               region.get("startLine"), region.get("endLine"), rule_cwe.get(rid, []),
                               (res.get("message") or {}).get("text", "")))
    return out


def parse_semgrep(doc, source):
    out = []
    for r in doc.get("results", []):
        meta = (r.get("extra") or {}).get("metadata") or {}
        out.append(finding(source, "sast", r.get("check_id"), r.get("path"), r["start"]["line"], r["end"]["line"],
                           as_list(meta.get("cwe")), (r.get("extra") or {}).get("message", "")))
    return out


def parse_gitleaks(doc, source):
    return [finding(source, "secret", r.get("RuleID"), r.get("File"), r.get("StartLine"), r.get("EndLine"),
                    ["CWE-798"], r.get("Description", ""), r.get("Secret")) for r in doc]


def parse_trivy(doc, source):
    out = []
    for res in doc.get("Results") or []:
        target = res.get("Target")
        for s in res.get("Secrets") or []:
            out.append(finding(source, "secret", s.get("RuleID"), target, s.get("StartLine"), s.get("EndLine"),
                               ["CWE-798"], s.get("Title", "")))
        for v in res.get("Vulnerabilities") or []:
            out.append(finding(source, "sca", v.get("VulnerabilityID"), target, 0, 0, as_list(v.get("CweIDs")),
                               v.get("PkgName", "")))
    return out


def tigergate_row_type(row):
    text = " ".join(str(row.get(k) or "") for k in ("scan_type", "issue_type", "category", "finding_type")).lower()
    if "secret" in text:
        return "secret"
    if VULN_ID.match(str(row.get("rule_id") or "")) or "sca" in text.split() or "vulnerab" in text:
        return "sca"
    if "misconfig" in text or text.split()[:1] == ["iac"]:
        return "iac"
    return "sast"


def parse_rows(rows, source):
    out = []
    for r in rows:
        start = r.get("start_line") or r.get("line_start") or r.get("line") or 0
        end = r.get("end_line") or r.get("line_end") or start
        out.append(finding(source, tigergate_row_type(r), r.get("rule_id"), r.get("file_path") or r.get("file"),
                           start, end, r.get("cwe_ids") or r.get("cwe"), r.get("message") or r.get("title") or ""))
    return out


def load_export(path):
    text = Path(path).read_text(encoding="utf-8")
    source = Path(path).name
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        dialect = "excel-tab" if "\t" in text.splitlines()[0] else "excel"
        return parse_rows(list(csv.DictReader(io.StringIO(text), dialect=dialect)), source)
    doc = json.loads(text)
    if isinstance(doc, dict) and "runs" in doc:
        return parse_sarif(doc, source)
    if isinstance(doc, dict) and "results" in doc and isinstance(doc["results"], list):
        return parse_semgrep(doc, source)
    if isinstance(doc, dict) and "Results" in doc:
        return parse_trivy(doc, source)
    if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        doc = doc["findings"]
    if isinstance(doc, list) and (not doc or "RuleID" in doc[0]):
        return parse_gitleaks(doc, source)
    if isinstance(doc, list):
        return parse_rows(doc, source)
    raise ValueError("unrecognised export format: %s" % path)


# ----------------------------------------------------------------------------------------- classes
def load_rule_classes():
    if RULE_CLASSES.exists():
        return json.loads(RULE_CLASSES.read_text(encoding="utf-8")).get("rules", {})
    return {}


def class_of(f, rule_classes):
    if f["finding_type"] == "secret" or f["rule_id"].startswith(SECRET_COPY_PREFIX):
        return "hardcoded-secret"
    if f["finding_type"] == "sca":
        return "vulnerable-dependency"
    rid = f["rule_id"]
    for candidate in (rid, rid[4:] if rid.startswith("tmp.") else None):
        if candidate and candidate in rule_classes:
            return rule_classes[candidate]
    for cwe in f["cwe"]:
        m = re.match(r"(CWE-\d+)", cwe.strip(), re.I)
        if m and m.group(1).upper() in CWE_CLASS:
            return CWE_CLASS[m.group(1).upper()]
    low = rid.lower()
    for pat, cls in TEXT_CLASS:
        if re.search(pat, low):
            return cls
    return "other"


def engine_of(f):
    """secret (secret engine), secret-copy (SAST port of a secret rule) or sast."""
    if f["finding_type"] == "secret":
        return "secret"
    if f["rule_id"].startswith(SECRET_COPY_PREFIX):
        return "secret-copy"
    return f["finding_type"]


def fold(findings, preferred):
    """Approximate findingfold.Cluster: per file and class, a group spans FOLD_WINDOW lines from its anchor;
    a rule already in the group starts a new one. Keeps one finding per group (a preferred rule first)."""
    keep, groups = [], defaultdict(list)
    for f in findings:
        groups[(f["file"], f["class"])].append(f)
    for (_, cls), items in groups.items():
        if cls in ("other", "hardcoded-secret", "vulnerable-dependency") or not items[0]["file"]:
            keep.extend(items)
            continue
        items.sort(key=lambda x: (x["start_line"], x["rule_id"]))
        current, anchor, rules = [], None, set()
        for f in items + [None]:
            if f is None or anchor is None or f["start_line"] - anchor > FOLD_WINDOW or f["rule_id"] in rules:
                if current:
                    current.sort(key=lambda x: (x["rule_id"] not in preferred, x["rule_id"]))
                    keep.append(current[0])
                if f is None:
                    break
                current, anchor, rules = [], f["start_line"], set()
            current.append(f)
            rules.add(f["rule_id"])
    return keep


# ---------------------------------------------------------------------------------------- matching
def covers(f, case):
    if case["finding_type"] == "sca":
        return True
    first, last = case.get("expected_span") or [case["expected_line"]] * 2
    return f["start_line"] <= last and max(f["end_line"], f["start_line"]) >= first


def evaluate(cases, findings, types_present):
    by_file = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)
    attributed = set()
    results = []
    for c in cases:
        r = {"test_id": c["test_id"], "issue": c["issue"], "status": c["status"], "expected": c["expected"],
             "file": c["file"], "line": c["expected_line"], "class": c["expected_class"]}
        on_line = [f for f in by_file.get(c["file"], []) if covers(f, c)]
        for f in on_line:
            attributed.add(id(f))
        if c["finding_type"] not in types_present:
            r["outcome"] = "Unverified"
            results.append(r)
            continue
        in_class = [f for f in on_line if f["class"] == c["expected_class"]]
        if c["finding_type"] == "sca":
            # A lockfile lists many advisories; only the one the case names is evidence.
            in_class = [f for f in in_class if f["rule_id"] in c["expected_rule_ids"]]
        overlap = []
        if c["expected_class"] == "hardcoded-secret" and c["expected"] == "detected":
            # A SAST catalog rule repeating a detected secret is reported as cross-engine overlap; the
            # duplicate count covers the secret engine and its SAST ports (generic.secrets.*). On a
            # negative case every hardcoded-secret finding is a false alarm.
            overlap = [f for f in in_class if engine_of(f) == "sast"]
            in_class = [f for f in in_class if engine_of(f) != "sast"]
        forbidden = [f for f in on_line if f["class"] in c.get("forbidden_classes", [])]
        allowed = set(c.get("allowed_other_classes", [])) | set(c.get("forbidden_classes", [])) | {c["expected_class"]}
        other = [f for f in on_line if f["class"] not in allowed]
        r["rules_in_class"] = sorted(f["rule_id"] for f in in_class)
        r["rules_other_class"] = sorted("%s (%s)" % (f["rule_id"], f["class"]) for f in other)
        if overlap:
            r["sast_overlap"] = sorted(f["rule_id"] for f in overlap)
        if forbidden:
            r["misclassified_as"] = sorted("%s (%s)" % (f["rule_id"], f["class"]) for f in forbidden)
        n, want = len(in_class), c["expected_count"]
        if c["expected"] == "detected":
            if n == 0:
                outcome = "Misclassified" if forbidden else "FN"
            else:
                outcome = "TP"
                primary = any(f["rule_id"] in c["expected_rule_ids"] or
                              f["rule_id"].replace("tmp.", "", 1) in c["expected_rule_ids"] for f in in_class)
                r["detected_by"] = "expected-rule" if primary or not c["expected_rule_ids"] else "alternate-rule"
                if n < want:
                    r["missing"] = want - n
                    outcome = "FN"
                if n > want:
                    r["duplicates"] = n - want
                if forbidden:
                    r["also_misclassified"] = True
        elif c["expected"] == "not_detected":
            if n and c.get("duplicate_of"):
                outcome, r["duplicates"] = "Duplicate", n
            elif n:
                outcome = "FP"
                r["fp_by_target_rule"] = any(f["rule_id"] in c["expected_rule_ids"] for f in in_class)
            elif forbidden:
                outcome = "Misclassified"
            else:
                outcome = "TN"
        else:
            outcome = "Observed: %s" % ("detected" if n else "not detected")
        if c["status"] == "known_gap":
            r["gap_observed"] = "detected" if n else "not detected"
            r["gap_matches_expectation"] = (bool(n) == (c["expected"] == "detected"))
            outcome = "Known gap"
        elif c["status"] == "context_dependent":
            outcome = "Context: %s" % ("detected" if n else "not detected")
        r["outcome"] = outcome
        results.append(r)
    unattributed = [f for f in findings if id(f) not in attributed]
    return results, unattributed


def summarise(results, issues):
    rows = []
    for key, title in issues.items():
        rs = [r for r in results if r["issue"] == key]
        if not rs:
            continue
        cnt = Counter(r["outcome"] for r in rs)
        dup = sum(r.get("duplicates", 0) for r in rs)
        tp, fp, fn, tn = cnt["TP"], cnt["FP"], cnt["FN"], cnt["TN"]
        mis = cnt["Misclassified"] + sum(1 for r in rs if r.get("also_misclassified"))
        unver = cnt["Unverified"]
        gaps = sum(1 for r in rs if r["outcome"] == "Known gap")
        counted = tp + fp + fn + tn + cnt["Misclassified"] + cnt["Duplicate"]
        if unver and not counted:
            status = "UNVERIFIED"
        elif fp or fn or dup or mis or cnt["Duplicate"]:
            status = "FAIL"
        elif unver:
            status = "PARTIAL"
        else:
            status = "PASS"
        fp_target = sum(1 for r in rs if r["outcome"] == "FP" and r.get("fp_by_target_rule"))
        overlap = sum(1 for r in rs if r.get("sast_overlap"))
        tp_alt = sum(1 for r in rs if r.get("detected_by") == "alternate-rule")
        precision = round(tp / (tp + fp), 3) if (tp + fp) else None
        recall = round(tp / (tp + fn), 3) if (tp + fn) else None
        rows.append({"issue": key, "title": title, "TP": tp, "FP": fp, "FN": fn, "TN": tn, "Duplicates": dup,
                     "Misclassified": mis, "Unverified": unver, "FP by target rule": fp_target,
                     "TP by alternate rule only": tp_alt, "Cross-engine overlap": overlap, "Known gaps": gaps,
                     "precision": precision, "recall": recall, "status": status})
    return rows


def markdown(label, rows, results, unattributed, exports):
    md = ["# TigerGate regression comparison: %s" % label, "",
          "Exports: " + (", ".join("`%s`" % e for e in exports) or "none"), "",
          "| Issue | TP | FP | FN | TN | Duplicates | Misclassified | Unverified | Known gaps | Precision | Recall | Status |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|"]
    fmt = lambda v: "n/a" if v is None else "%.3f" % v
    for r in rows:
        md.append("| %s | %d | %d | %d | %d | %d | %d | %d | %d | %s | %s | %s |" % (
            r["title"], r["TP"], r["FP"], r["FN"], r["TN"], r["Duplicates"], r["Misclassified"], r["Unverified"],
            r["Known gaps"], fmt(r["precision"]), fmt(r["recall"]), r["status"]))
    bad = [r for r in results if r["outcome"] in ("FP", "FN", "Misclassified", "Duplicate") or r.get("duplicates")
           or r.get("also_misclassified")]
    md += ["", "Precision and recall are computed only over supported, verified cases; known gaps are excluded.", "",
           "| Issue | FP by the target rule(s) | FP by other rules | TP by an alternate rule only | Cross-engine overlap |",
           "|---|---:|---:|---:|---:|"]
    for r in rows:
        md.append("| %s | %d | %d | %d | %d |" % (r["title"], r["FP by target rule"], r["FP"] - r["FP by target rule"],
                                              r["TP by alternate rule only"], r["Cross-engine overlap"]))
    md += ["",
           "## Cases needing attention (%d)" % len(bad), ""]
    if bad:
        md += ["| Case | Outcome | Location | In-class rules | Notes |", "|---|---|---|---|---|"]
        for r in bad:
            notes = []
            if r.get("duplicates"):
                notes.append("duplicates: %d" % r["duplicates"])
            if r.get("missing"):
                notes.append("missing: %d" % r["missing"])
            if r.get("misclassified_as"):
                notes.append("misclassified as " + ", ".join(r["misclassified_as"]))
            if r["outcome"] == "FP":
                notes.append("target rule" if r.get("fp_by_target_rule") else "other rule")
            md.append("| %s | %s | `%s:%s` | %s | %s |" % (r["test_id"], r["outcome"], r["file"], r["line"],
                                                         ", ".join(r.get("rules_in_class", [])) or "-", "; ".join(notes) or "-"))
    gaps = [r for r in results if r["outcome"] == "Known gap"]
    md += ["", "## Known gaps (%d, not counted)" % len(gaps), ""]
    if gaps:
        md += ["| Case | Expected | Observed | Location |", "|---|---|---|---|"]
        for r in gaps:
            md.append("| %s | %s | %s | `%s:%s` |" % (r["test_id"], r["expected"], r.get("gap_observed", "unverified"),
                                                     r["file"], r["line"]))
    alt = [r for r in results if r.get("detected_by") == "alternate-rule"]
    if alt:
        md += ["", "## Detected only by an alternate rule of the same class (%d)" % len(alt), ""]
        md += ["- %s `%s:%s`: %s" % (r["test_id"], r["file"], r["line"], ", ".join(r["rules_in_class"])) for r in alt]
    cross = [r for r in results if r.get("rules_other_class")]
    if cross:
        md += ["", "## Other-class findings on case lines (%d, review)" % len(cross), ""]
        md += ["- %s `%s:%s`: %s" % (r["test_id"], r["file"], r["line"], ", ".join(r["rules_other_class"])) for r in cross]
    overl = [r for r in results if r.get("sast_overlap")]
    if overl:
        md += ["", "## SAST catalog rules also reporting a secret line (%d, cross-engine overlap)" % len(overl), ""]
        md += ["- %s: %s" % (r["test_id"], ", ".join(r["sast_overlap"])) for r in overl]
    md += ["", "## Unattributed findings (%d): possible false positives" % len(unattributed), ""]
    if unattributed:
        md += ["| Location | Rule | Class | Type |", "|---|---|---|---|"]
        for f in sorted(unattributed, key=lambda x: (x["file"], x["start_line"], x["rule_id"])):
            md.append("| `%s:%d` | %s | %s | %s |" % (f["file"], f["start_line"], f["rule_id"], f["class"], f["finding_type"]))
    return "\n".join(md) + "\n"


def run(exports, label="scan", do_fold=False, manifest=MANIFEST, finding_types=None):
    doc = json.loads(Path(manifest).read_text(encoding="utf-8"))
    rule_classes = load_rule_classes()
    findings = []
    for e in exports:
        findings.extend(load_export(e))
    findings = [f for f in findings if f["finding_type"] != "iac"]
    for f in findings:
        f["class"] = class_of(f, rule_classes)
    if do_fold:
        preferred = {r for c in doc["cases"] for r in c["expected_rule_ids"]}
        findings = fold(findings, preferred)
    present = set(finding_types) if finding_types else {f["finding_type"] for f in findings}
    results, unattributed = evaluate(doc["cases"], findings, present)
    rows = summarise(results, doc["issues"])
    # Export names only: a report never records local paths.
    return {"label": label, "exports": [Path(e).name for e in exports], "finding_types_verified": sorted(present),
            "summary": rows, "cases": results,
            "unattributed": [{k: v for k, v in f.items() if k != "message"} for f in unattributed]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", action="append", default=[], help="exported scan result (repeatable)")
    ap.add_argument("--label", default="scan")
    ap.add_argument("--fold", action="store_true", help="approximate findingfold for raw engine output")
    ap.add_argument("--types", help="comma-separated finding types the exports cover (default: types seen)")
    ap.add_argument("--json-out")
    ap.add_argument("--md-out")
    a = ap.parse_args(argv)
    types = a.types.split(",") if a.types else None
    if not a.findings:
        types = []
    report = run(a.findings, a.label, a.fold, finding_types=types)
    md = markdown(a.label, report["summary"], report["cases"],
                  [dict(f, message="") for f in report["unattributed"]], report["exports"])
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if a.md_out:
        Path(a.md_out).write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
