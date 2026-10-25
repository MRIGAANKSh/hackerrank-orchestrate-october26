"""Scoring helpers shared by the evaluation script and tests."""
from __future__ import annotations
import json

KEY = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def step_tuple(s: dict) -> tuple:
    return tuple(s[k] for k in KEY)


def compare(pred: dict, gold: dict) -> dict:
    """pred/gold: {case_id: (status, steps)}"""
    n = len(gold)
    status_ok = sum(pred.get(c, (None,))[0] == g[0] for c, g in gold.items())
    exact = seq_ok = 0
    tp = fp = fn = 0
    field_tot = field_ok = 0
    per_field = {k: [0, 0] for k in KEY}
    for c, (gs, gsteps) in gold.items():
        ps, psteps = pred.get(c, (None, []))
        gt = [step_tuple(s) for s in gsteps]
        pt = [step_tuple(s) for s in psteps]
        exact += pt == gt
        seq_ok += [t[:4] for t in pt] == [t[:4] for t in gt]
        gset, pset = set(gt), set(pt)
        tp += len(gset & pset); fp += len(pset - gset); fn += len(gset - pset)
        for a, b in zip(pt, gt):
            for i, k in enumerate(KEY):
                per_field[k][1] += 1
                per_field[k][0] += a[i] == b[i]
        for k in KEY:  # missing/extra steps count as wrong fields
            per_field[k][1] += abs(len(pt) - len(gt))
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"cases": n, "status_accuracy": status_ok / n, "exact_steps_match": exact / n,
            "sequence_match": seq_ok / n, "step_precision": prec, "step_recall": rec, "step_f1": f1,
            "field_accuracy": {k: (v[0] / v[1] if v[1] else 1.0) for k, v in per_field.items()}}
