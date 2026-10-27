#!/usr/bin/env python3
"""Write expected/rule-classes.json: rule ID -> vulnerability class, from rule metadata (CWE) only.

  build-rule-classes.py --source "TigerGate <commit>" RULESET.yaml [PACK.yaml ...]

RULESET is the Semgrep ruleset the backend serves (see scripts/local-engine-scan.sh, which builds it from
a TigerGate checkout); PACKs are registry packs. Only rules whose CWE maps to a class under test are kept.
The verifier falls back to a finding's own CWE, then to rule-ID text, for rules missing from this file.
Requires PyYAML (only this maintenance script does).
"""
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_findings", HERE / "verify-findings.py")
vf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vf)


def cwes(rule):
    meta = rule.get("metadata") or {}
    raw = meta.get("cwe") or rule.get("cwe") or []
    raw = raw if isinstance(raw, list) else [raw]
    out = []
    for c in raw:
        m = re.match(r"\s*(CWE-\d+)", str(c), re.I)
        if m:
            out.append(m.group(1).upper())
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, help="where the rules came from (commit, pack fetch date)")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    rules = {}
    for f in a.files:
        for r in (yaml.safe_load(Path(f).read_text(encoding="utf-8")) or {}).get("rules", []):
            # AI-usage inventory rules name AI vendors in their IDs, which the r/ai pack would then flag in this
            # file; generic.secrets.* are classified by prefix in the verifier.
            if r["id"].startswith(("ai.", vf.SECRET_COPY_PREFIX)):
                continue
            for c in cwes(r):
                cls = vf.CWE_CLASS.get(c)
                if cls:
                    rules.setdefault(r["id"], cls)
                    break
    out = {"schema_version": 1, "source": a.source, "files": [Path(f).name for f in a.files],
           "rules": dict(sorted(rules.items()))}
    target = HERE.parent / "expected" / "rule-classes.json"
    target.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print("wrote %d rule classes to %s" % (len(rules), target))


if __name__ == "__main__":
    sys.exit(main())
