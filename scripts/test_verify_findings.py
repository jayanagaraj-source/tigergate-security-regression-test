"""Unit tests for the verification scripts: python3 -m unittest discover -s scripts -p 'test_*.py'."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vf = load("verify-findings")
vl = load("verify-loc")


def case(**kw):
    base = {"test_id": "T-001", "issue": "js-xss", "language": "javascript", "file": "a.js", "expected": "detected",
            "finding_type": "sast", "expected_class": "xss", "expected_rule_ids": ["R-XSS"], "expected_cwe": ["CWE-79"],
            "expected_line": 10, "expected_span": [10, 10], "expected_count": 1, "description": "", "status": "supported"}
    base.update(kw)
    return base


def sast(rule, line, cwe=("CWE-79",), file="a.js", end=None):
    f = vf.finding("t", "sast", rule, file, line, end or line, list(cwe))
    f["class"] = vf.class_of(f, {})
    return f


def outcome(c, findings, types=("sast",)):
    results, unattributed = vf.evaluate([c], findings, set(types))
    return results[0], unattributed


class Parsing(unittest.TestCase):
    def test_sarif(self):
        doc = {"runs": [{"tool": {"driver": {"rules": [{"id": "R", "properties": {"tags": ["CWE-89: SQLi", "x"]}}]}},
                         "results": [{"ruleId": "R", "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "file:///workspace/cases/a.py"},
                             "region": {"startLine": 4, "endLine": 5}}}]}]}]}
        f = vf.parse_sarif(doc, "s")[0]
        self.assertEqual((f["file"], f["start_line"], f["end_line"], f["cwe"]), ("cases/a.py", 4, 5, ["CWE-89: SQLi"]))

    def test_gitleaks_keeps_only_a_fingerprint(self):
        f = vf.parse_gitleaks([{"RuleID": "jwt", "File": "./x.js", "StartLine": 2, "EndLine": 2, "Secret": "s3cr3t"}], "g")[0]
        self.assertEqual(f["finding_type"], "secret")
        self.assertNotIn("s3cr3t", json.dumps(f))
        self.assertEqual(len(f["value_fingerprint"]), 16)

    def test_tigergate_rows(self):
        rows = [{"file_path": "a.php", "line_start": None, "start_line": 7, "rule_id": "TG-X", "scan_type": "full-scan",
                 "issue_type": "security", "cwe_ids": '{"CWE-643: XPath Injection"}'},
                {"file_path": "b.py", "start_line": 3, "rule_id": "generic-api-key", "scan_type": "secret", "issue_type": "secret"},
                {"file_path": "c.tf", "start_line": 1, "rule_id": "AVD-1", "scan_type": "misconfig", "issue_type": "iac"}]
        fs = vf.parse_rows(rows, "db")
        self.assertEqual([f["finding_type"] for f in fs], ["sast", "secret", "iac"])
        self.assertEqual(vf.class_of(fs[0], {}), "xpath-injection")

    def test_trivy(self):
        doc = {"Results": [{"Target": "loc/p.json", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "x"}],
                            "Secrets": [{"RuleID": "aws-access-key-id", "StartLine": 3, "EndLine": 3}]}]}
        types = sorted(f["finding_type"] for f in vf.parse_trivy(doc, "t"))
        self.assertEqual(types, ["sca", "secret"])


class Classes(unittest.TestCase):
    def test_rule_map_then_cwe_then_text(self):
        self.assertEqual(vf.class_of(vf.finding("t", "sast", "X", "f", 1, cwe=["CWE-134"]), {}), "format-string")
        self.assertEqual(vf.class_of(vf.finding("t", "sast", "X", "f", 1), {"X": "xss"}), "xss")
        self.assertEqual(vf.class_of(vf.finding("t", "sast", "tmp.X", "f", 1), {"X": "xss"}), "xss")
        self.assertEqual(vf.class_of(vf.finding("t", "sast", "my-zip-slip-rule", "f", 1), {}), "path-traversal")
        self.assertEqual(vf.class_of(vf.finding("t", "sast", "generic.secrets.gitleaks.jwt.jwt", "f", 1), {}),
                         "hardcoded-secret")


class Matching(unittest.TestCase):
    def test_tp_by_expected_and_alternate_rule(self):
        r, _ = outcome(case(), [sast("R-XSS", 10)])
        self.assertEqual((r["outcome"], r["detected_by"]), ("TP", "expected-rule"))
        r, _ = outcome(case(), [sast("OTHER", 10)])
        self.assertEqual((r["outcome"], r["detected_by"]), ("TP", "alternate-rule"))

    def test_other_class_is_not_proof(self):
        r, _ = outcome(case(), [sast("PT", 10, ("CWE-22",))])
        self.assertEqual(r["outcome"], "FN")
        self.assertTrue(r["rules_other_class"])

    def test_span_intersection(self):
        c = case(expected_line=9, expected_span=[9, 12])
        self.assertEqual(outcome(c, [sast("R-XSS", 11)])[0]["outcome"], "TP")
        self.assertEqual(outcome(c, [sast("R-XSS", 13)])[0]["outcome"], "FN")
        self.assertEqual(outcome(case(), [sast("R-XSS", 8, end=10)])[0]["outcome"], "TP")

    def test_fp_tn_and_target_attribution(self):
        c = case(expected="not_detected")
        self.assertEqual(outcome(c, [])[0]["outcome"], "TN")
        r, _ = outcome(c, [sast("R-XSS", 10)])
        self.assertEqual((r["outcome"], r["fp_by_target_rule"]), ("FP", True))

    def test_duplicates_and_expected_count(self):
        r, _ = outcome(case(), [sast("R-XSS", 10), sast("OTHER", 10)])
        self.assertEqual((r["outcome"], r["duplicates"]), ("TP", 1))
        r, _ = outcome(case(expected_count=2), [sast("R-XSS", 10)])
        self.assertEqual((r["outcome"], r["missing"]), ("FN", 1))

    def test_multiple_findings_on_one_line_for_different_cases(self):
        a = case(test_id="A", expected_class="xss")
        b = case(test_id="B", expected_class="path-traversal", expected_rule_ids=["R-PT"])
        results, unattributed = vf.evaluate([a, b], [sast("R-XSS", 10), sast("R-PT", 10, ("CWE-22",))], {"sast"})
        self.assertEqual([r["outcome"] for r in results], ["TP", "TP"])
        self.assertEqual(unattributed, [])

    def test_misclassification(self):
        c = case(expected_class="xpath-injection", forbidden_classes=["sql-injection"])
        r, _ = outcome(c, [sast("SQL", 10, ("CWE-89",))])
        self.assertEqual(r["outcome"], "Misclassified")
        r, _ = outcome(case(expected="not_detected", expected_class="sql-injection", forbidden_classes=["xss"]),
                       [sast("X", 10)])
        self.assertEqual(r["outcome"], "Misclassified")

    def test_duplicate_of_and_known_gap_and_unverified(self):
        c = case(expected="not_detected", duplicate_of="T-000")
        self.assertEqual(outcome(c, [sast("R-XSS", 10)])[0]["outcome"], "Duplicate")
        g = case(status="known_gap")
        r, _ = outcome(g, [])
        self.assertEqual((r["outcome"], r["gap_observed"], r["gap_matches_expectation"]), ("Known gap", "not detected", False))
        self.assertEqual(outcome(case(), [], types=())[0]["outcome"], "Unverified")

    def test_secret_overlap_versus_negative(self):
        tp = case(expected_class="hardcoded-secret", finding_type="secret", expected_rule_ids=["generic-api-key"])
        sec = vf.finding("g", "secret", "generic-api-key", "a.js", 10, 10, ["CWE-798"])
        cat = vf.finding("s", "sast", "PY-101", "a.js", 10, 10, ["CWE-798"])
        for f in (sec, cat):
            f["class"] = vf.class_of(f, {})
        r, _ = outcome(tp, [sec, cat], types=("secret", "sast"))
        self.assertEqual((r["outcome"], r.get("duplicates"), r["sast_overlap"]), ("TP", None, ["PY-101"]))
        tn = dict(tp, expected="not_detected")
        self.assertEqual(outcome(tn, [cat], types=("secret", "sast"))[0]["outcome"], "FP")

    def test_sca_counts_only_the_named_advisory(self):
        c = case(finding_type="sca", expected_class="vulnerable-dependency", expected_rule_ids=["CVE-2"], expected_line=1)
        fs = [vf.finding("t", "sca", cve, "a.js", 0) for cve in ("CVE-1", "CVE-2")]
        for f in fs:
            f["class"] = vf.class_of(f, {})
        r, _ = outcome(c, fs, types=("sca",))
        self.assertEqual((r["outcome"], r.get("duplicates")), ("TP", None))

    def test_unattributed(self):
        _, un = outcome(case(), [sast("R-XSS", 50)])
        self.assertEqual(len(un), 1)

    def test_fold_keeps_one_per_window_and_prefers_expected(self):
        fs = [sast("UP", 10), sast("R-XSS", 11), sast("UP", 20)]
        kept = vf.fold(fs, {"R-XSS"})
        self.assertEqual(sorted((f["rule_id"], f["start_line"]) for f in kept), [("R-XSS", 11), ("UP", 20)])


class Summary(unittest.TestCase):
    def test_status_and_metrics(self):
        rows = vf.summarise([{"issue": "k", "outcome": "TP", "status": "supported"},
                             {"issue": "k", "outcome": "TN", "status": "supported"}], {"k": "K"})
        self.assertEqual((rows[0]["status"], rows[0]["precision"], rows[0]["recall"]), ("PASS", 1.0, 1.0))
        rows = vf.summarise([{"issue": "k", "outcome": "Unverified", "status": "supported"}], {"k": "K"})
        self.assertEqual((rows[0]["status"], rows[0]["precision"]), ("UNVERIFIED", None))
        rows = vf.summarise([{"issue": "k", "outcome": "Known gap", "status": "known_gap"}], {"k": "K"})
        self.assertEqual((rows[0]["TP"], rows[0]["Known gaps"], rows[0]["recall"]), (0, 1, None))


class Loc(unittest.TestCase):
    def count(self, name, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            p.write_text(text, encoding="utf-8")
            return vl.reference_count(p)

    def test_python_docstrings_are_not_code(self):
        src = '"""Doc."""\nimport os\n\n\ndef f():\n    """Doc."""\n    x = """kept"""\n    return x\n'
        self.assertEqual(self.count("m.py", src), (True, "python", 4))

    def test_line_starting_with_block_comment_then_code(self):
        self.assertEqual(self.count("a.js", "/* c */ const a = 1;\n// x\nconst s = '/* not a comment';\n"),
                         (True, "javascript", 2))

    def test_exclusions(self):
        self.assertEqual(self.count("x.ts", "// @generated by tool\nexport const a = 1;\n")[0], False)
        self.assertEqual(self.count("c.yml", "services:\n  a:\n    image: x\n")[0], False)
        self.assertEqual(self.count("k.yaml", "apiVersion: v1\nkind: ConfigMap\n"), (True, "yaml", 2))
        self.assertEqual(self.count("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")[0], False)
        self.assertEqual(self.count("b.min.js", "var a=1;\n")[0], False)
        self.assertEqual(self.count("build.gradle.kts", "plugins {}\n")[0], False)
        self.assertEqual(self.count("Dockerfile", "# c\nFROM x\n"), (True, "dockerfile", 1))

    def test_compare_lists_unexpected_and_missing(self):
        exp = {"totals": {"code": 3, "per_language": {"javascript": 3}},
               "files": [{"file": "a.js", "counted": True, "code": 3}, {"file": "b.min.js", "counted": False, "code": 0}]}
        res = vl.compare(exp, {"code": 5, "per_language": {"javascript": 5}, "files": {"b.min.js": 5}}, "x")
        self.assertEqual((res["unexpectedly_counted"], res["missing_counted"]), (["b.min.js"], ["a.js"]))

    def test_sonar_measures(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text(json.dumps({"component": {"measures": [{"metric": "ncloc", "value": "12"},
                                                                {"metric": "ncloc_language_distribution", "value": "js=10;py=2"}]}}))
            s = vl.load_sonar([str(p)])
        self.assertEqual((s["code"], s["per_language"]), (12, {"javascript": 10, "python": 2}))


class Manifests(unittest.TestCase):
    def test_manifests_are_current(self):
        for script, arg in (("build-manifest.py", "--check"), ("verify-loc.py", "--check")):
            proc = subprocess.run([sys.executable, "-B", str(HERE / script), arg], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_ids_unique_and_spans_inside_files(self):
        doc = json.loads((HERE.parent / "expected" / "findings.manifest.json").read_text(encoding="utf-8"))
        ids = [c["test_id"] for c in doc["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        for c in doc["cases"]:
            n = len((HERE.parent / c["file"]).read_text(encoding="utf-8").splitlines())
            first, last = c["expected_span"]
            self.assertTrue(1 <= first <= c["expected_line"] <= last <= n, c["test_id"])
            self.assertIn(c["expected"], ("detected", "not_detected", "context_dependent"))
            self.assertIn(c["status"], ("supported", "known_gap", "context_dependent"))


if __name__ == "__main__":
    unittest.main()
