"""Output serialization + schema validation for output.csv."""
from __future__ import annotations
import csv, json
from pathlib import Path
from .engine import OP_ORDER, STATE_OF

HEADER = ["case_id", "deletion_status", "steps_json"]
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
STEP_KEYS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def case_sort_key(cid: str):
    return (cid.rsplit("_", 1)[0], int(cid.rsplit("_", 1)[1])) if cid.rsplit("_", 1)[-1].isdigit() else (cid, 0)


def write_output(results: dict, path: Path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(HEADER)
        for cid in sorted(results, key=case_sort_key):
            r = results[cid]
            steps = [{k: s[k] for k in STEP_KEYS} for s in r.steps]
            w.writerow([cid, r.status, json.dumps(steps, ensure_ascii=False, separators=(",", ":"))])


def validate_output(path: Path, expected_case_ids: list[str]) -> list[str]:
    errs = []
    with open(path, encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))
    if rows[0] != HEADER:
        errs.append(f"bad header {rows[0]}")
    body = rows[1:]
    ids = [r[0] for r in body]
    if len(ids) != len(set(ids)):
        errs.append("duplicate case_id rows")
    if set(ids) != set(expected_case_ids):
        errs.append(f"case set mismatch: missing={sorted(set(expected_case_ids)-set(ids))[:5]} extra={sorted(set(ids)-set(expected_case_ids))[:5]}")
    if ids != sorted(ids, key=case_sort_key) and ids != sorted(ids):
        errs.append("rows not sorted by case_id")
    for r in body:
        cid, st, sj = r
        if st not in STATUSES:
            errs.append(f"{cid}: bad status {st}")
        try:
            steps = json.loads(sj)
        except ValueError:
            errs.append(f"{cid}: steps_json not JSON"); continue
        if st == "NOT_APPLICABLE" and steps != []:
            errs.append(f"{cid}: NOT_APPLICABLE must have []")
        phase_rank = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        last = -1
        for i, s in enumerate(steps, 1):
            if set(s) != set(STEP_KEYS):
                errs.append(f"{cid}: step {i} keys {sorted(s)}"); break
            if s["step_no"] != i:
                errs.append(f"{cid}: step_no not consecutive at {i}")
            if s["phase"] not in phase_rank or s["operation"] not in OP_ORDER.get(s["phase"], []) \
                    or STATE_OF.get(s["operation"]) != s["state"]:
                errs.append(f"{cid}: invalid phase/operation/state at {i}")
            elif phase_rank[s["phase"]] < last:
                errs.append(f"{cid}: phase order violated at {i}")
            else:
                last = phase_rank[s["phase"]]
            if s["phase"] != "FINDING" and st == "INCOMPLETE" and s["evidence_id"] != "":
                errs.append(f"{cid}: future step {i} must have empty evidence_id")
            if st == "COMPLETE" and s["phase"] != "VERIFICATION":
                errs.append(f"{cid}: COMPLETE may only contain VERIFICATION steps")
    return errs
