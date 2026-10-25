"""Evidence ingestion.

Every evidence file (log families, JSON exports/bundles/ledgers, SQL snapshots,
plain-text handovers, OCR'd images, PDFs) is converted into a flat list of
``Obs`` observations that share one schema.  Original values and provenance
(file_id, observation time) are preserved; nothing is discarded because it does
not fit an expected shape (unparseable files are reported in ``Corpus.warnings``).
"""
from __future__ import annotations

import csv
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .common import (DATASET, EMAIL_RE, EVIDENCE, HASH_RE, PHONE_RE, USER_RE,
                     is_null, norm_email, norm_hash, norm_phone, parse_ts)

# ---------------------------------------------------------------- data model
KINDS = ("ACCOUNT", "SEARCH", "SUPPORT_MSG", "SUPPORT_ATT", "ANALYTICS",
         "SECONDARY_ID", "EXPORT", "FLOW", "BACKUP", "AUDIT", "TOMBSTONE",
         "MARKETING", "LEGAL_HOLD", "CACHE", "EMAIL_LOG")


@dataclass
class Obs:
    file_id: str
    file_time: datetime
    obs_time: datetime
    system: str
    rid: str
    kind: str
    emails: frozenset = frozenset()
    phones: frozenset = frozenset()
    hashes: frozenset = frozenset()
    refs: frozenset = frozenset()          # stable user references (user_NN)
    names: frozenset = frozenset()
    # state flags -- semantics depend on kind:
    #   ACCOUNT: present      SEARCH: present        EXPORT: present
    #   SUPPORT_*: present, redacted      ANALYTICS: present, identifiable
    #   FLOW: enabled         BACKUP: restore_allowed  AUDIT: present, retention_until
    #   TOMBSTONE: present, identifiable
    flags: dict = field(default_factory=dict)
    source: str = ""                         # parser name, for audit trail
    topology: str = ""                       # primary / replica name when relevant

    def idents(self) -> set:
        return set(self.emails) | set(self.phones) | set(self.hashes) | set(self.refs)


@dataclass
class EvidenceFile:
    file_id: str
    path: Path
    origin: str
    captured_at: datetime


class Corpus:
    def __init__(self):
        self.files: dict[str, EvidenceFile] = {}
        self.obs: list[Obs] = []
        self.warnings: list[str] = []


# ------------------------------------------------------------- small helpers
def _S(*vals) -> frozenset:
    return frozenset(v for v in vals if v)


def _emails(*vals) -> frozenset:
    return _S(*[norm_email(v) for v in vals])


def _phones(*vals) -> frozenset:
    return _S(*[norm_phone(v) for v in vals])


def _hashes(*vals) -> frozenset:
    return _S(*[norm_hash(v) for v in vals])


def _refs(*vals) -> frozenset:
    out = []
    for v in vals:
        if v and USER_RE.fullmatch(str(v).strip()):
            out.append(str(v).strip())
    return _S(*out)


def _split_subject(v) -> dict:
    """A free-form subject (email / phone / user ref / hash) -> typed idents."""
    if is_null(v):
        return {}
    v = str(v).strip()
    return dict(emails=_emails(v), phones=_phones(v) if v.startswith("+") else frozenset(),
                hashes=_hashes(v), refs=_refs(v))


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes", "y")


# ------------------------------------------------------------------ log lines
_KV = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')


def _kv(s: str) -> dict:
    out = {}
    for m in _KV.finditer(s):
        out[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


def parse_log_line(line: str) -> dict | None:
    """Parse one log line of any supported family into
    {ts, service, trace, event, kv}.  Returns None for non-event lines."""
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = re.match(r"(\d{4}-\d\d-\d\dT[\d:]+Z)\s+(.*)", line)
    if not m:
        return None
    ts, rest = m.group(1), m.group(2)
    rec: dict = {"ts": ts, "service": None, "trace": None, "event": None, "kv": {}}
    rest_s = rest.strip()
    if rest_s.startswith("{"):                                   # json lines
        try:
            j = json.loads(rest_s)
        except ValueError:
            return None
        rec["service"] = j.get("service") or j.get("logger")
        rec["trace"] = j.get("trace_id")
        rec["event"] = j.get("event")
        rec["kv"] = {k: ("" if v is None else str(v)) for k, v in j.items()}
        return rec
    if rest_s.startswith("<"):                                   # syslog
        sm = re.match(r"<\d+>1 (\S+) (\S+) (\S+) - - (.*)", rest_s)
        if not sm:
            return None
        rec["service"], rec["trace"] = sm.group(2), sm.group(3)
        rec["kv"] = _kv(sm.group(4))
        rec["event"] = rec["kv"].get("event")
        return rec
    if rest_s.startswith("[") and "] [" in rest_s:               # bracket
        bm = re.match(r"\[(\w+)\] \[(\w+)\] \[([^\]]+)\] (\w+): (.*)", rest_s)
        if not bm:
            return None
        rec["service"], rec["trace"], rec["event"] = bm.group(2), bm.group(3), bm.group(4)
        rec["kv"] = _kv(bm.group(5))
        return rec
    if rest_s.startswith("|"):                                   # pipe
        parts = [p.strip() for p in rest_s.lstrip("| ").split(" | ", 4)]
        if len(parts) < 5:
            return None
        rec["service"], rec["trace"], rec["event"] = parts[1], parts[2], parts[3]
        rec["kv"] = _kv(parts[4])
        return rec
    if "requestId=" in rest_s and "message=" in rest_s:          # cloud runtime
        cm = re.match(r'requestId=(\S+) level=\S+ function=(\S+) message="(.*)"$', rest_s)
        if not cm:
            return None
        rec["trace"], rec["service"] = cm.group(1), cm.group(2)
        rec["kv"] = _kv(cm.group(3).replace('\\"', '"'))
        rec["event"] = rec["kv"].get("event")
        return rec
    kvs = _kv(rest_s)                                            # key=value
    rec["service"] = kvs.get("service")
    rec["trace"] = kvs.get("trace_id")
    rec["event"] = kvs.get("event")
    rec["kv"] = kvs
    return rec


# service-name aliases seen in logs -> canonical system ids
_SERVICE_ALIAS = {"profile_service": "account_service", "support_replica": "support_platform"}


def _canon_system(s: str | None) -> str | None:
    return _SERVICE_ALIAS.get(s, s)


_KEY_FIELDS = ("lookup_key", "match_key", "subject_key", "scan_key", "owner_key",
               "subject_ref", "correlation_key", "subject_selector")


def _trace_keys(kv: dict) -> dict:
    ids: dict = dict(emails=set(), phones=set(), hashes=set(), refs=set())
    for f in _KEY_FIELDS + ("matched_value", "email", "customer_email", "owner_email",
                            "requester_email", "phone", "requester_phone",
                            "customer_reference", "subject_reference", "email_hash"):
        v = kv.get(f)
        if is_null(v):
            continue
        d = _split_subject(v)
        for k in ids:
            ids[k] |= set(d.get(k, ()))
        if f in ("phone", "requester_phone", "matched_value", "scan_key", "lookup_key",
                 "subject_key") and str(v).strip().startswith("+"):
            ids["phones"].add(norm_phone(v))
    return {k: frozenset(x for x in v if x) for k, v in ids.items()}


def obs_from_log(fid: str, ftime: datetime, path: Path, corpus: Corpus):
    """Group events by trace and emit one Obs per resource touched."""
    traces: dict[str, list[dict]] = {}
    order = 0
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        rec = parse_log_line(raw)
        if not rec:
            continue
        rec["service"] = _canon_system(rec["service"])
        order += 1
        key = rec["trace"] or f"_solo{order}"
        traces.setdefault(key, []).append(rec)

    for tkey, evs in traces.items():
        # assertion-style lines (record_lookup) carry their own full record
        for e in evs:
            if e["event"] == "record_lookup":
                _emit_assertion(corpus, fid, ftime, e["ts"], e["kv"], "log-record-lookup")
        # identifiers visible anywhere in the trace (started key, correlation key...)
        tid = {"emails": set(), "phones": set(), "hashes": set(), "refs": set()}
        for e in evs:
            for k, v in _trace_keys(e["kv"]).items():
                tid[k] |= v
        for e in evs:
            ev, kv, svc, ts = e["event"], e["kv"], e["service"], parse_ts(e["ts"]) or ftime
            rid = kv.get("resource_id")
            if not rid or ev in ("record_lookup",):
                continue
            ids = {k: frozenset(v) for k, v in tid.items()}
            base = dict(file_id=fid, file_time=ftime, obs_time=ts, system=svc, rid=rid,
                        emails=ids["emails"], phones=ids["phones"], hashes=ids["hashes"],
                        refs=ids["refs"], source="log:" + (ev or ""))
            o = _log_event_obs(ev, kv, base)
            if o:
                corpus.obs.append(o)


def _log_event_obs(ev: str, kv: dict, base: dict) -> Obs | None:
    svc = base["system"]
    if ev == "profile_lookup_completed":
        rows = kv.get("rows")
        status = kv.get("http_status")
        present = (str(rows) not in ("0",)) and str(status) not in ("404",)
        return Obs(kind="ACCOUNT", flags={"present": present}, **base)
    if ev == "index_query_completed":
        present = kv.get("result", "hit") == "hit"
        return Obs(kind="SEARCH", flags={"present": present}, **base)
    if ev == "message_pii_scan":
        return Obs(kind="SUPPORT_MSG", flags={"present": True, "redacted": False}, **base)
    if ev == "attachment_pii_scan":
        return Obs(kind="SUPPORT_ATT", flags={"present": True, "redacted": False,
                                              "file": kv.get("file")}, **base)
    if ev == "message_read":
        txt = kv.get("message_text", "")
        return Obs(kind="SUPPORT_MSG", flags={"present": True,
                                              "redacted": "[REDACTED]" in txt}, **base)
    if ev == "analytics_identity_scan":
        return Obs(kind="ANALYTICS", flags={"present": True, "identifiable": True}, **base)
    if ev == "analytics_profile_read":
        ident = (kv.get("direct_identifiers", "0") not in ("0",)) or not is_null(kv.get("email")) \
            or not is_null(kv.get("phone"))
        return Obs(kind="ANALYTICS", flags={"present": True, "identifiable": bool(ident)}, **base)
    if ev == "contact_lookup_completed":
        return Obs(kind="SECONDARY_ID", flags={"present": kv.get("rows", "1") != "0"}, **base)
    if ev in ("connector_heartbeat", "connector_config_loaded"):
        return Obs(kind="FLOW", flags={"enabled": _truthy(kv.get("enabled")),
                                       "scheduler": _truthy(kv.get("scheduler_registered", "true"))}, **base)
    if ev == "restore_candidate_evaluated":
        allowed = _truthy(kv.get("eligible")) and not _truthy(kv.get("deletion_block"))
        return Obs(kind="BACKUP", flags={"restore_allowed": allowed}, **base)
    if ev == "restore_authorization_completed":
        return Obs(kind="BACKUP", flags={"restore_allowed": kv.get("decision") != "deny"}, **base)
    if ev == "export_download_check_completed":
        return Obs(kind="EXPORT", flags={"present": _truthy(kv.get("available"))}, **base)
    if ev == "audit_record_read_completed":
        return Obs(kind="AUDIT", flags={"present": True, "retention_until": kv.get("retention_until")}, **base)
    # --- resource_lookup_trace (readback collector) style completions
    if ev == "connector_config_read_completed":
        b = dict(base); b["emails"] = b["emails"] | _emails(kv.get("customer_email"))
        return Obs(kind="FLOW", flags={"enabled": _truthy(kv.get("enabled"))}, **b)
    if ev == "analytics_profile_read_completed":
        ident = any(not is_null(kv.get(k)) for k in ("email", "phone", "email_hash", "customer_reference"))
        return Obs(kind="ANALYTICS", flags={"present": True, "identifiable": ident}, **base)
    if ev == "export_metadata_read_completed":
        return Obs(kind="EXPORT", flags={"present": _truthy(kv.get("available"))}, **base)
    if ev == "support_ticket_read_completed":
        ident = any(not is_null(kv.get(k)) for k in ("requester_name", "requester_email", "requester_phone"))
        return Obs(kind="SUPPORT_MSG", flags={"present": True, "redacted": not ident}, **base)
    if ev == "restore_policy_read_completed":
        return Obs(kind="BACKUP", flags={"restore_allowed": _truthy(kv.get("restore_allowed")),
                                         "archive_present": _truthy(kv.get("archive_present"))}, **base)
    if ev == "audit_record_read_completed_rb":
        return None
    if ev == "deletion_marker_check":
        # replica row still present when no deletion marker propagated to it
        return Obs(kind="SUPPORT_ATT", flags={"present": not _truthy(kv.get("marker_found")), "redacted": False,
                                              "marker_found": _truthy(kv.get("marker_found"))}, **base)
    if ev == "contact_query_completed":
        return None
    return None


# ---------------------------------------------------------- assertion records
_ASSERT_KIND = {
    "USER_PROFILE": "ACCOUNT", "SEARCH_INDEX_ENTRY": "SEARCH", "SUPPORT_MESSAGE": "SUPPORT_MSG",
    "SUPPORT_ATTACHMENT": "SUPPORT_ATT", "ANALYTICS_PROFILE": "ANALYTICS", "PRODUCT_TELEMETRY": "ANALYTICS",
    "USER_EXPORT": "EXPORT", "DATA_FLOW": "FLOW", "BACKUP_ARCHIVE": "BACKUP",
    "SECURITY_AUDIT_LOG": "AUDIT", "LEGAL_HOLD_RECORD": "LEGAL_HOLD", "ACCOUNT_TOMBSTONE": "TOMBSTONE",
    "MARKETING_PROFILE": "MARKETING", "CACHE_ENTRY": "CACHE", "SECONDARY_IDENTIFIER": "SECONDARY_ID",
    "EMAIL_DELIVERY_LOG": "EMAIL_LOG",
}


def _emit_assertion(corpus: Corpus, fid, ftime, ts, rec: dict, source: str):
    system = rec.get("system") or rec.get("system_id")
    rid = rec.get("resource_id")
    rtype = rec.get("record_type")
    result = (rec.get("result") or "").upper()
    subj = rec.get("subject_reference") or rec.get("lookup_value")
    if not (system and rid and rtype):
        return
    kind = _ASSERT_KIND.get(rtype)
    if not kind:
        corpus.warnings.append(f"{fid}: unknown record_type {rtype}")
        return
    flags: dict = {}
    if kind == "ACCOUNT":
        flags["present"] = result == "FOUND"
    elif kind == "FLOW":
        flags["enabled"] = result == "ACTIVE"
    elif kind == "BACKUP":
        flags["restore_allowed"] = result == "ACTIVE"
    elif kind == "ANALYTICS":
        flags.update(present=True, identifiable=result == "IDENTIFIABLE")
    elif kind in ("SUPPORT_MSG", "SUPPORT_ATT"):
        flags.update(present=True, redacted=result == "REDACTED")
    elif kind == "TOMBSTONE":
        flags.update(present=True, identifiable=result in ("IDENTIFIABLE", "FOUND"))
    else:
        flags["present"] = result in ("FOUND", "PRESENT", "ACTIVE", "IDENTIFIABLE")
    ids = _split_subject(subj)
    t = parse_ts(ts) or ftime
    corpus.obs.append(Obs(file_id=fid, file_time=ftime, obs_time=t, system=system, rid=rid, kind=kind,
                          emails=ids.get("emails", frozenset()), phones=ids.get("phones", frozenset()),
                          hashes=ids.get("hashes", frozenset()), refs=ids.get("refs", frozenset()),
                          flags=flags, source=source))


def obs_from_handover_txt(fid, ftime, path: Path, corpus: Corpus):
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("- "):
            continue
        p = [x.strip() for x in line[2:].split("|")]
        if len(p) < 6:
            continue
        _emit_assertion(corpus, fid, ftime, p[0], dict(system=p[1], resource_id=p[2], record_type=p[3],
                                                       result=p[4], subject_reference=p[5]), "txt-handover")


def obs_from_assertion_json(fid, ftime, doc: dict, corpus: Corpus):
    for r in doc.get("records", []):
        ts = r.get("recorded_at")
        _emit_assertion(corpus, fid, ftime, ts, r, "json-assertion")


# ------------------------------------------------------ service export (json)
def obs_from_service_export(fid, ftime, doc: dict, corpus: Corpus):
    ex = doc.get("service_exports", {})
    def T(r):
        return parse_ts(r.get("observed_at")) or ftime
    def add(system, rid, kind, r, flags, **ids):
        corpus.obs.append(Obs(file_id=fid, file_time=ftime, obs_time=T(r), system=system, rid=rid,
                              kind=kind, flags=flags, source="json-service-export", **ids))
    for r in ex.get("account_service", {}).get("profile_lookups", []):
        prof = r.get("profile") or {}
        present = r.get("status_code") == 200 and r.get("profile") is not None
        add("account_service", r["resource_id"], "ACCOUNT", r, {"present": present},
            emails=_emails(prof.get("email")), phones=_phones(prof.get("phone")),
            hashes=_hashes(prof.get("email_hash")), refs=_refs(prof.get("customer_reference")),
            names=_S(prof.get("full_name")))
    for r in ex.get("analytics_platform", {}).get("profiles", []):
        ident = any(not is_null(r.get(k)) for k in ("email", "phone", "email_hash", "customer_reference"))
        add("analytics_platform", r["resource_id"], "ANALYTICS", r, {"present": True, "identifiable": ident},
            emails=_emails(r.get("email")), phones=_phones(r.get("phone")), hashes=_hashes(r.get("email_hash")),
            refs=_refs(r.get("customer_reference")))
    for r in ex.get("backup_service", {}).get("restore_entries", []):
        add("backup_service", r["resource_id"], "BACKUP", r, {"restore_allowed": bool(r.get("restore_allowed"))},
            emails=_emails(r.get("customer_email")), refs=_refs(r.get("customer_reference")))
    for r in ex.get("export_service", {}).get("exports", []):
        add("export_service", r["resource_id"], "EXPORT", r, {"present": True},
            emails=_emails(r.get("owner_email")), phones=_phones(r.get("owner_phone")),
            refs=_refs(r.get("customer_reference")))
    for r in ex.get("integration_service", {}).get("connectors", []):
        add("integration_service", r["resource_id"], "FLOW", r, {"enabled": bool(r.get("enabled"))},
            emails=_emails(r.get("customer_email")), refs=_refs(r.get("customer_reference")))
    for r in ex.get("search_service", {}).get("index_queries", []):
        docs = (r.get("hits") or {}).get("documents") or []
        for d in docs:
            add("search_service", d["resource_id"], "SEARCH", r, {"present": True},
                emails=_emails(d.get("email")), phones=_phones(d.get("phone")), hashes=_hashes(d.get("email_hash")),
                refs=_refs(d.get("customer_reference")), names=_S(d.get("display_name")))
    for r in ex.get("security_service", {}).get("audit_records", []):
        add("security_service", r["resource_id"], "AUDIT", r,
            {"present": True, "retention_until": r.get("retention_until")}, refs=_refs(r.get("subject_reference")))
    for r in ex.get("support_platform", {}).get("tickets", []):
        ident = any(not is_null(r.get(k)) for k in ("requester_name", "requester_email", "requester_phone"))
        add("support_platform", r["resource_id"], "SUPPORT_MSG", r, {"present": True, "redacted": not ident},
            emails=_emails(r.get("requester_email")), phones=_phones(r.get("requester_phone")),
            refs=_refs(r.get("customer_reference")), names=_S(r.get("requester_name")))


# ------------------------------------------------------------ snapshot bundle
def _doc_ids(txt: str) -> dict:
    return dict(emails=frozenset(norm_email(e) for e in EMAIL_RE.findall(txt or "")) - {None},
                phones=frozenset(norm_phone(p) for p in PHONE_RE.findall(txt or "")) - {None})


def obs_from_bundle(fid, ftime, doc: dict, corpus: Corpus):
    for snap in doc.get("snapshots", []):
        st = _canon_system(snap.get("data_store"))
        coll = snap.get("collection")
        sc = parse_ts(snap.get("captured_at")) or ftime
        for r in snap.get("records", []):
            rid = r.get("resource_id")
            def add(system, kind, flags, **ids):
                corpus.obs.append(Obs(file_id=fid, file_time=ftime, obs_time=sc, system=system, rid=rid,
                                      kind=kind, flags=flags, source=f"bundle:{coll}", **ids))
            if coll == "customer_profiles":
                add(st, "ACCOUNT", {"present": True, "status": r.get("account_status")},
                    emails=_emails(r.get("email")), phones=_phones(r.get("phone")),
                    refs=_refs(r.get("customer_reference")), names=_S(r.get("full_name")))
            elif coll == "customer_search_documents":
                d = r.get("document") or {}
                add(st, "SEARCH", {"present": True}, emails=_emails(d.get("email")),
                    refs=_refs(d.get("customer_reference")), names=_S(d.get("display_name")))
            elif coll == "customer_analytics_reports":
                ident = any(not is_null(r.get(k)) for k in ("email", "phone", "email_hash", "user_id"))
                add(st, "ANALYTICS", {"present": True, "identifiable": ident}, emails=_emails(r.get("email")),
                    phones=_phones(r.get("phone")), hashes=_hashes(r.get("email_hash")), refs=_refs(r.get("user_id")))
            elif coll == "backup_catalog":
                add(st, "BACKUP", {"restore_allowed": bool(r.get("restore_allowed"))}, refs=_refs(r.get("subject_reference")))
            elif coll == "connector_configurations":
                sel = r.get("subject_selector")
                d = _split_subject(sel)
                add(st, "FLOW", {"enabled": bool(r.get("enabled"))}, emails=d.get("emails", frozenset()),
                    refs=d.get("refs", frozenset()))
            elif coll == "customer_export_jobs":
                add(st, "EXPORT", {"present": bool(r.get("download_available", True))}, emails=_emails(r.get("owner_email")))
            elif coll == "security_audit_events":
                add(st, "AUDIT", {"present": True}, refs=_refs(r.get("subject_reference")))
            elif coll == "support_conversations":
                txt = r.get("message_text") or ""
                ids = _doc_ids(txt)
                red = "[REDACTED]" in txt or not (ids["emails"] or ids["phones"])
                add(st, "SUPPORT_MSG", {"present": True, "redacted": red}, emails=ids["emails"], phones=ids["phones"],
                    refs=_refs(r.get("subject_reference")))
            elif coll == "ticket_attachments":
                add(st, "SUPPORT_ATT", {"present": True, "redacted": False, "file": r.get("file_name")},
                    emails=_emails(r.get("uploaded_by")))
            elif coll == "retained_order_records":
                add(st, "LEGAL_HOLD", {"present": True, "retained_until": r.get("retained_until")},
                    refs=_refs(r.get("subject_reference")))
            elif coll == "deleted_customer_references":
                ident = any(not is_null(r.get(k)) for k in ("name", "email", "phone", "email_hash"))
                add(st or "identity_service", "TOMBSTONE", {"present": True, "identifiable": ident},
                    emails=_emails(r.get("email")), phones=_phones(r.get("phone")), hashes=_hashes(r.get("email_hash")),
                    refs=_refs(r.get("subject_reference")), names=_S(r.get("name")))
            elif coll == "operational_record_history":
                _emit_assertion(corpus, fid, ftime, r.get("recorded_at"), r, "bundle:operational_record_history")
            else:
                corpus.warnings.append(f"{fid}: unhandled bundle collection {coll}")


# ------------------------------------------------------------------------ sql
def _bool(v) -> bool:
    return str(v).strip() in ("1", "true", "True")


def obs_from_sql(fid, ftime, path: Path, corpus: Corpus):
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    try:
        con.executescript(path.read_text(encoding="utf-8", errors="replace"))
    except sqlite3.Error as e:
        corpus.warnings.append(f"{fid}: SQL error {e}")
        return
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    for t in tables:
        cols = [r[1] for r in con.execute(f"pragma table_info({t})")]
        for row in con.execute(f"select * from {t}"):
            r = dict(row)
            ts = parse_ts(r.get("updated_at") or r.get("indexed_at")) or ftime
            topo = t
            if "record_json" in cols:
                rec = json.loads(r["record_json"])
                coll = r["collection_name"]
                _sql_json_record(corpus, fid, ftime, ts, r["origin_system"], coll, rec, topo)
                continue
            _sql_typed_row(corpus, fid, ftime, ts, t, r, topo)


def _sql_typed_row(corpus, fid, ftime, ts, t, r, topo):
    rid = r.get("resource_id")
    if t == "snapshot_scope" or not rid:
        return
    def add(system, kind, flags, **ids):
        corpus.obs.append(Obs(file_id=fid, file_time=ftime, obs_time=ts, system=system, rid=rid, kind=kind,
                              flags=flags, source="sql:" + t, topology=topo, **ids))
    if t in ("customer_profiles", "customer_profiles_primary", "customer_profiles_failover_replica"):
        add("account_service", "ACCOUNT", {"present": True, "status": r.get("account_status")},
            emails=_emails(r.get("email")), phones=_phones(r.get("phone")), hashes=_hashes(r.get("email_hash")),
            refs=_refs(r.get("customer_reference"), r.get("user_id")), names=_S(r.get("full_name")))
    elif t == "customer_search_documents":
        add("search_service", "SEARCH", {"present": True}, emails=_emails(r.get("email")), phones=_phones(r.get("phone")),
            hashes=_hashes(r.get("email_hash")), refs=_refs(r.get("customer_reference")), names=_S(r.get("display_name")))
    elif t == "search_documents_primary":
        add("search_service", "SEARCH", {"present": True, "source_resource": r.get("source_resource_id")},
            emails=_emails(r.get("email")), names=_S(r.get("display_name")))
    elif t == "customer_analytics_profiles":
        ident = any(not is_null(r.get(k)) for k in ("email", "phone", "email_hash", "customer_reference"))
        add("analytics_platform", "ANALYTICS", {"present": True, "identifiable": ident}, emails=_emails(r.get("email")),
            phones=_phones(r.get("phone")), hashes=_hashes(r.get("email_hash")), refs=_refs(r.get("customer_reference")))
    elif t == "support_records":
        ident = any(not is_null(r.get(k)) for k in ("requester_name", "requester_email", "requester_phone"))
        add("support_platform", "SUPPORT_MSG", {"present": True, "redacted": not ident}, emails=_emails(r.get("requester_email")),
            phones=_phones(r.get("requester_phone")), refs=_refs(r.get("customer_reference")), names=_S(r.get("requester_name")))
    elif t == "customer_exports":
        add("export_service", "EXPORT", {"present": True}, emails=_emails(r.get("owner_email")),
            phones=_phones(r.get("owner_phone")), refs=_refs(r.get("customer_reference")))
    elif t == "connector_subscriptions":
        add("integration_service", "FLOW", {"enabled": _bool(r.get("enabled"))}, emails=_emails(r.get("customer_email")),
            refs=_refs(r.get("customer_reference")))
    elif t == "backup_restore_entries":
        add("backup_service", "BACKUP", {"restore_allowed": _bool(r.get("restore_allowed"))},
            emails=_emails(r.get("customer_email")), refs=_refs(r.get("customer_reference")))
    elif t == "security_audit_records":
        add("security_service", "AUDIT", {"present": True, "retention_until": r.get("retention_until")},
            refs=_refs(r.get("subject_reference")))
    else:
        corpus.warnings.append(f"{fid}: unhandled SQL table {t}")


def _sql_json_record(corpus, fid, ftime, ts, system, coll, rec, topo):
    rid = rec.get("resource_id")
    def add(kind, flags, **ids):
        corpus.obs.append(Obs(file_id=fid, file_time=ftime, obs_time=ts, system=system, rid=rid, kind=kind,
                              flags=flags, source="sql-json:" + coll, topology=topo, **ids))
    # reuse the bundle logic through a synthetic one-record snapshot
    tmp = Corpus()
    obs_from_bundle(fid, ftime, {"snapshots": [{"data_store": system, "collection": coll,
                                                "captured_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                "records": [rec]}]}, tmp)
    if coll == "deleted_customer_references":
        ident = any(not is_null(rec.get(k)) for k in ("name", "email", "phone", "email_hash"))
        add("TOMBSTONE", {"present": True, "identifiable": ident}, emails=_emails(rec.get("email")),
            phones=_phones(rec.get("phone")), hashes=_hashes(rec.get("email_hash")),
            refs=_refs(rec.get("subject_reference")), names=_S(rec.get("name")))
        return
    for o in tmp.obs:
        o.obs_time, o.topology, o.source = ts, topo, f"sql-json:{coll}"
        corpus.obs.append(o)
    corpus.warnings.extend(tmp.warnings)


# ------------------------------------------------------------------ top level
def load_corpus(ocr_texts: dict | None = None) -> Corpus:
    corpus = Corpus()
    with open(DATASET / "evidence_files.csv", encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            corpus.files[r["file_id"]] = EvidenceFile(r["file_id"], DATASET / r["file_path"], r["origin"],
                                                       parse_ts(r["captured_at"]))
    for fid, ef in corpus.files.items():
        p, ft = ef.path, ef.captured_at
        try:
            suf = p.suffix.lower()
            if suf == ".log":
                obs_from_log(fid, ft, p, corpus)
            elif suf == ".sql":
                obs_from_sql(fid, ft, p, corpus)
            elif suf == ".txt":
                obs_from_handover_txt(fid, ft, p, corpus)
            elif suf == ".json":
                doc = json.loads(p.read_text(encoding="utf-8"))
                if "service_exports" in doc:
                    obs_from_service_export(fid, ft, doc, corpus)
                elif "snapshots" in doc:
                    obs_from_bundle(fid, ft, doc, corpus)
                elif "records" in doc and doc["records"] and "record_type" in doc["records"][0]:
                    obs_from_assertion_json(fid, ft, doc, corpus)
                else:
                    corpus.warnings.append(f"{fid}: JSON shape handled by document parsers")
                    from .documents import obs_from_misc_json
                    obs_from_misc_json(fid, ft, doc, corpus)
            elif suf in (".png", ".pdf"):
                from .documents import obs_from_document
                obs_from_document(fid, ft, p, corpus, ocr_texts)
        except Exception as e:  # never silently drop a file
            corpus.warnings.append(f"{fid}: failed to parse {p.name}: {type(e).__name__}: {e}")
    return corpus
