#!/usr/bin/env python3
"""Entry point:  python3 code/main.py   ->  <repo root>/output.csv"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ghostaudit.common import ROOT
from ghostaudit.engine import Auditor
from ghostaudit.output import write_output, validate_output


def main() -> int:
    au = Auditor()
    reqs = Auditor.load_requests()
    results = au.audit_all(reqs)
    out = ROOT / "output.csv"
    write_output(results, out)
    errs = validate_output(out, [r["case_id"] for r in reqs])
    from collections import Counter
    print(f"wrote {out} rows={len(results)} statuses={dict(Counter(r.status for r in results.values()))}")
    print(f"parser warnings: {len(au.corpus.warnings)}")
    if errs:
        print("VALIDATION ERRORS:"); [print(" ", e) for e in errs[:20]]
        return 1
    print("schema validation: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
