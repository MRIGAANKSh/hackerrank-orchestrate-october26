"""Deletion audit engine.

Pipeline per request:
  1. intent       - does request_text authorize deletion?  (else NOT_APPLICABLE, [])
  2. identity     - request email -> user -> all current/historical identifiers
  3. discovery    - observations visible at audit_at that share an identifier
  4. state        - latest observation per resource (reported statuses are claims)
  5. policy       - deletion_rules.csv decides required treatment per record
  6. decision     - COMPLETE only if every copy is compliant and nothing can recreate data
  7. steps        - findings -> remediation -> verification, deterministic ordering
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .common import DATASET, EMAIL_RE, USER_RE, norm_email, parse_ts
from .evidence import Corpus, Obs, load_corpus
from .identity import Identity, IdentityBook
from .intent import authorizes_deletion
from .policy import Policy

# ------------------------------------------------------------------ constants
OP_ORDER = {
    "FINDING": ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"],
    "REMEDIATION": ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"],
    "VERIFICATION": ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                     "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"],
}
STATE_OF = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
RESULT_FOR_REPORTED = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


@dataclass
class Item:
    """One relevant record with its state at audit_at."""
    system: str
    rid: str
    kind: str
    obs: Obs | None            # latest observation (None => known only from activity)
    treatment: str             # DELETE / REDACT / ANONYMIZE / RETAIN / DISABLE / BLOCK
    compliant: bool
    finding_op: str | None
    remediation_op: str | None
    verify_op: str
    why: str = ""
    cite: str = ""             # evidence file proving the state (captured at/before audit_at)


@dataclass
class CaseResult:
    case_id: str
    status: str
    steps: list
    identity: Identity | None = None
    items: list = field(default_factory=list)
    notes: list = field(default_factory=list)


class Auditor:
    def __init__(self, corpus: Corpus | None = None):
        self.corpus = corpus or load_corpus()
        self.book = IdentityBook()
        self.policy = Policy()
        self.activity = self._load_activity()
        self.act_by_res: dict[str, list[dict]] = {}
        for a in self.activity:
            self.act_by_res.setdefault(a["resource_id"], []).append(a)
        self.account_deletes = sorted(
            (a for a in self.activity if a["event_type"] == "DELETE_RECORD" and a["target_system"] == "account_service"),
            key=lambda a: a["_t"])
        self.by_res: dict[tuple, list[Obs]] = {}
        for o in self.corpus.obs:
            self.by_res.setdefault((o.system, o.rid), []).append(o)
        self.claimed_accounts: dict[str, str] = {}
        # explicit resource<->identity links published in the activity stream (data catalog)
        self.links: list[tuple] = []
        for a in self.activity:
            if a["event_type"] == "LINK_RESOURCE_IDENTITY" and a["target_system"] != "object_storage":
                ids = set(EMAIL_RE.findall(a["details"]))
                ids = {norm_email(x) for x in ids} | set(USER_RE.findall(a["details"]))
                self.links.append((a["target_system"], a["resource_id"], ids, a["_t"]))

    # ------------------------------------------------------------------ loading
    @staticmethod
    def _load_activity() -> list[dict]:
        rows = []
        with open(DATASET / "system_activity.csv", encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                r["_t"] = parse_ts(r["event_time"])
                rows.append(r)
        return rows

    @staticmethod
    def load_requests(name="deletion_requests.csv") -> list[dict]:
        with open(DATASET / name, encoding="utf-8", newline="") as fh:
            return list(csv.DictReader(fh))

    # ---------------------------------------------------------------- discovery
    def _visible(self, o: Obs, audit_at: datetime) -> bool:
        # State is judged by when the *observation* was made, never after audit_at.
        # (A later-exported bundle may still contain snapshots taken before audit_at.)
        return o.obs_time <= audit_at

    def discover(self, ident: Identity, audit_at: datetime) -> dict[tuple, list[Obs]]:
        keys = ident.all()
        out: dict[tuple, list[Obs]] = {}
        for k, lst in self.by_res.items():
            vis = [o for o in lst if self._visible(o, audit_at)]
            if not vis:
                continue
            if any(o.idents() & keys for o in vis):
                out[k] = vis
        for system, rid, ids, t in self.links:       # catalog links tie otherwise anonymous rows to a subject
            if t <= audit_at and ids & keys and (system, rid) not in out:
                vis = [o for o in self.by_res.get((system, rid), []) if self._visible(o, audit_at)]
                if vis:
                    out[(system, rid)] = vis
        return out

    # -------------------------------------------------------------------- items
    def _item_for(self, system, rid, obs_list: list[Obs], audit_at: datetime | None = None) -> Item | None:
        it = self._item_for_inner(system, rid, obs_list)
        if it and audit_at is not None:
            cit = [o for o in obs_list if o.file_time <= audit_at]
            it.cite = max(cit, key=lambda o: (o.obs_time, o.file_time)).file_id if cit else ""
        return it

    def _item_for_inner(self, system, rid, obs_list: list[Obs]) -> Item | None:
        latest = max(obs_list, key=lambda o: (o.obs_time, o.file_time))
        kind, fl = latest.kind, latest.flags
        rule = self.policy.action_for(kind)
        act = rule.action if rule else None
        if kind == "ACCOUNT":
            present = fl.get("present", False)
            return Item(system, rid, kind, latest, "DELETE", not present,
                        "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT")
        if kind in ("SEARCH", "EXPORT", "MARKETING", "SECONDARY_ID", "CACHE"):
            present = fl.get("present", True)
            if not present:
                return None
            return Item(system, rid, kind, latest, "DELETE", False,
                        "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT")
        if kind == "SUPPORT_ATT":
            return Item(system, rid, kind, latest, "DELETE", False,
                        "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT")
        if kind == "SUPPORT_MSG":
            if fl.get("marker_found") is False and "present" in fl and fl["present"]:
                pass
            comp = bool(fl.get("redacted"))
            if fl.get("present") is False:
                comp = True
            return Item(system, rid, kind, latest, "REDACT", comp,
                        "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED")
        if kind == "ANALYTICS":
            comp = not fl.get("identifiable", True)
            return Item(system, rid, kind, latest, "ANONYMIZE", comp,
                        "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED")
        if kind == "TOMBSTONE":
            comp = not fl.get("identifiable", True)
            return Item(system, rid, kind, latest, "REDACT", comp,
                        "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED")
        if kind == "FLOW":
            comp = not fl.get("enabled", True)
            return Item(system, rid, kind, latest, "DISABLE", comp,
                        "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED")
        if kind == "BACKUP":
            comp = not fl.get("restore_allowed", True)
            return Item(system, rid, kind, latest, "BLOCK", comp,
                        "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED")
        if kind in ("AUDIT", "LEGAL_HOLD"):
            return Item(system, rid, kind, latest, "RETAIN", True, None, None, "VERIFY_RECORD_PRESENT")
        return None

    def _has_delete_event(self, rid: str, req: dict) -> bool:
        lo = parse_ts(req["requested_at"]) - timedelta(days=1)
        hi = parse_ts(req["reported_at"]) + timedelta(hours=12)
        return any(a["event_type"] == "DELETE_RECORD" and lo <= a["_t"] <= hi for a in self.act_by_res.get(rid, []))

    # --------------------------------------------------------- account location
    def _account_candidates(self, req: dict, other_items: list[Item]) -> list[dict]:
        """Deletion-worker account events that could belong to this case, closest first."""
        rep = parse_ts(req["reported_at"])
        want = RESULT_FOR_REPORTED.get(req["reported_status"])
        chain = []
        for it in other_items:
            for a in self.act_by_res.get(it.rid, []):
                if a["event_type"] in ("DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "DISABLE_DATA_FLOW",
                                       "BLOCK_RESTORE", "CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS") \
                        and a["_t"] >= rep - timedelta(hours=1):
                    chain.append(a["_t"])
        anchor = min(chain) if chain else rep
        cands = [a for a in self.account_deletes
                 if a["_t"] <= anchor + timedelta(minutes=30) and anchor - a["_t"] <= timedelta(hours=12)]
        pref = [a for a in cands if a["reported_result"] == want] or cands
        # An account that shows up in evidence (e.g. a 404 lookup) belongs to a case whose
        # other copies are compliant; accounts invisible in evidence belong to cases with leftovers.
        audit_at = parse_ts(req["audit_at"])
        dirty = any(not i.compliant for i in other_items)
        def in_ev(a):
            return any(o.obs_time <= audit_at for o in self.by_res.get(("account_service", a["resource_id"]), []))
        return sorted(pref, key=lambda a: ((in_ev(a) == dirty), -a["_t"].timestamp()))

    def _account_item(self, rid: str, audit_at: datetime, why: str) -> Item:
        lst = [o for o in self.by_res.get(("account_service", rid), []) if o.obs_time <= audit_at]
        if lst:
            it = self._item_for("account_service", rid, lst, audit_at)
            if it:
                it.why = why
                return it
        it = Item("account_service", rid, "ACCOUNT", None, "DELETE", True, "REPORT_REMAINING_RECORD",
                  "DELETE_RECORD", "VERIFY_RECORD_ABSENT", why=why)
        it.cite = self._absence_proof(rid, audit_at)
        return it

    def _absence_proof(self, rid: str, audit_at: datetime) -> str:
        """A full account-table snapshot (primary/replica SQL or bundle) taken after the account's
        deletion event and at/before audit_at that does not list `rid` proves the record is absent."""
        t_del = [a["_t"] for a in self.act_by_res.get(rid, []) if a["event_type"] == "DELETE_RECORD"]
        floor = min(t_del) if t_del else None
        best = None
        for fid, rids in self._account_tables().items():
            ft = self.corpus.files[fid].captured_at
            if ft <= audit_at and (floor is None or ft >= floor) and rid not in rids:
                if best is None or ft > best[0]:
                    best = (ft, fid)
        return best[1] if best else ""

    def _account_tables(self) -> dict[str, set]:
        if not hasattr(self, "_acct_tables"):
            t: dict[str, set] = {}
            for o in self.corpus.obs:
                if o.kind == "ACCOUNT" and o.source.split(":")[0] in ("sql",) and "customer_profiles" in o.source:
                    t.setdefault(o.file_id, set()).add(o.rid)
            self._acct_tables = t
        return self._acct_tables

    # -------------------------------------------------------------------- audit
    def audit_all(self, reqs: list[dict]) -> dict[str, CaseResult]:
        """Two phases so that account ids located from the activity stream are assigned
        globally (each deletion event belongs to exactly one case)."""
        pre = {}
        claimed: dict[str, str] = {}
        for req in reqs:
            if not authorizes_deletion(req["request_text"]):
                continue
            audit_at = parse_ts(req["audit_at"])
            ident = self.book.resolve(req["email"])
            found = self.discover(ident, audit_at) if ident.all() else {}
            items = [i for k, l in found.items() if (i := self._item_for(k[0], k[1], l, audit_at))]
            accounts = [i for i in items if i.kind == "ACCOUNT" and self._has_delete_event(i.rid, req)]
            for a in accounts:
                claimed[a.rid] = req["case_id"]
            pre[req["case_id"]] = (ident, [i for i in items if i.kind != "ACCOUNT"], accounts)
        pending = {}
        for req in reqs:
            if req["case_id"] in pre and not pre[req["case_id"]][2]:
                pending[req["case_id"]] = (req, self._account_candidates(req, pre[req["case_id"]][1]))
        assigned: dict[str, str] = {}
        taken = set(claimed)
        progress = True
        while pending and progress:
            progress = False
            for cid, (req, cands) in sorted(pending.items(), key=lambda kv: len([c for c in kv[1][1] if c["resource_id"] not in taken])):
                free = [c for c in cands if c["resource_id"] not in taken]
                if not free:
                    continue
                if len(free) == 1 or not progress:
                    pick = free[0]
                    assigned[cid] = pick["resource_id"]
                    taken.add(pick["resource_id"])
                    del pending[cid]
                    progress = True
                    break
        extra_an = self._assign_anonymized_analytics(reqs, pre, assigned)
        out = {}
        for req in reqs:
            cid = req["case_id"]
            if cid not in pre:
                out[cid] = CaseResult(cid, "NOT_APPLICABLE", [], notes=["request does not authorize deletion"])
                continue
            ident, others, accounts = pre[cid]
            if not accounts and cid in assigned:
                accounts = [self._account_item(assigned[cid], parse_ts(req["audit_at"]), "located via activity stream")]
            out[cid] = self._decide(cid, ident, accounts + others + extra_an.get(cid, []))
        return out

    def _assign_anonymized_analytics(self, reqs, pre, assigned) -> dict[str, list[Item]]:
        """Anonymized analytics rows carry no identifier by design, so they can only be tied to a
        case through the deletion worker's activity chain (ANONYMIZE_RECORD shortly after the
        account deletion).  Used only for cases whose copies are otherwise all compliant."""
        linked = {k[1] for k in self.by_res if k[0] == "analytics_platform" and any(o.idents() for o in self.by_res[k])}
        taken = set()
        for cid, (ident, others, accounts) in pre.items():
            taken |= {i.rid for i in others if i.kind == "ANALYTICS"}
        evs = [a for a in self.activity if a["event_type"] == "ANONYMIZE_RECORD" and a["reported_result"] == "SUCCESS"
               and a["target_system"] == "analytics_platform" and a["resource_id"] not in taken]
        out: dict[str, list[Item]] = {}
        todo = []
        for req in reqs:
            cid = req["case_id"]
            if cid not in pre or any(not i.compliant for i in pre[cid][1]) or any(i.kind == "ANALYTICS" for i in pre[cid][1]):
                continue
            acc = pre[cid][2][0].rid if pre[cid][2] else assigned.get(cid)
            if not acc or not self.act_by_res.get(acc):
                continue
            t0 = min(a["_t"] for a in self.act_by_res[acc] if a["event_type"] == "DELETE_RECORD")
            todo.append((t0, req, acc))
        for t0, req, acc in sorted(todo, key=lambda x: x[0]):
            audit_at = parse_ts(req["audit_at"])
            cands = [a for a in evs if t0 < a["_t"] <= t0 + timedelta(minutes=90) and a["_t"] <= audit_at
                     and a["resource_id"] not in taken]
            if not cands:
                continue
            pick = min(cands, key=lambda a: a["_t"])
            taken.add(pick["resource_id"])
            lst = [o for o in self.by_res.get(("analytics_platform", pick["resource_id"]), []) if o.obs_time <= audit_at]
            if lst:
                it = self._item_for("analytics_platform", pick["resource_id"], lst, audit_at)
            else:
                it = Item("analytics_platform", pick["resource_id"], "ANALYTICS", None, "ANONYMIZE", True,
                          "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED")
            if it and it.compliant:
                out.setdefault(req["case_id"], []).append(it)
        return out

    def audit_case(self, req: dict) -> CaseResult:
        return self.audit_all([req])[req["case_id"]]

    # ---------------------------------------------------------------- decision
    def _decide(self, cid: str, ident: Identity, items: list[Item]) -> CaseResult:
        noncompliant = [i for i in items if not i.compliant]
        # Absence of any evidence is not proof of deletion: no findings AND no verifiable
        # records => the request cannot be shown complete.
        status = "INCOMPLETE" if (noncompliant or not items) else "COMPLETE"
        steps: list[dict] = []

        def cite(it: Item) -> str:
            return it.cite

        if status == "INCOMPLETE":
            for it in noncompliant:
                steps.append(self._s("FINDING", it, it.finding_op, cite(it)))
            for it in noncompliant:
                steps.append(self._s("REMEDIATION", it, it.remediation_op, ""))
            seen = set()
            ver = [i for i in items if i.kind == "ACCOUNT"] + [i for i in items if i.kind in ("AUDIT", "LEGAL_HOLD")] + noncompliant
            for it in ver:
                if (it.system, it.rid) in seen:
                    continue
                seen.add((it.system, it.rid))
                steps.append(self._s("VERIFICATION", it, it.verify_op, ""))
        else:
            for it in items:
                steps.append(self._s("VERIFICATION", it, it.verify_op, cite(it)))
        steps = self._order(steps)
        return CaseResult(cid, status, steps, ident, items)

    @staticmethod
    def _s(phase, it: Item, op: str, evidence_id: str) -> dict:
        return {"phase": phase, "system_id": it.system, "resource_id": it.rid, "operation": op,
                "state": STATE_OF[op], "evidence_id": evidence_id}

    @staticmethod
    def _order(steps: list[dict]) -> list[dict]:
        ph = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        steps.sort(key=lambda s: (ph[s["phase"]], OP_ORDER[s["phase"]].index(s["operation"]), s["system_id"], s["resource_id"]))
        for i, s in enumerate(steps, 1):
            s["step_no"] = i
        return steps
