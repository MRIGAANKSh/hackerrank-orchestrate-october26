"""Documents: OCR for screenshots, text extraction for PDFs, miscellaneous JSON.

Screenshots/PDFs are ordinary business artifacts (consoles, statements,
handover notes).  We extract the *facts they contain* -- resource ids and the
identifiers printed next to them -- and emit presence observations.  OCR is
best-effort (tesseract) and degrades to "no observations" if unavailable.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .common import EMAIL_RE, HASH_RE, PHONE_RE, USER_RE, norm_email, norm_hash, norm_phone, parse_ts
from .evidence import Obs, Corpus, _emails, _phones, _hashes, _refs, _S, is_null

_PREFIX_KIND = [
    ("account_", "account_service", "ACCOUNT"), ("search_", "search_service", "SEARCH"),
    ("support_", "support_platform", "SUPPORT_MSG"), ("analytics_", "analytics_platform", "ANALYTICS"),
    ("export_", "export_service", "EXPORT"), ("data_flow_", "integration_service", "FLOW"),
    ("backup_", "backup_service", "BACKUP"), ("audit_record_", "security_service", "AUDIT"),
    ("tombstone_", "identity_service", "TOMBSTONE"), ("marketing_", "marketing_service", "MARKETING"),
    ("legal_hold_", "legal_service", "LEGAL_HOLD"),
]
RID_RE = re.compile(r"\b(account|search|support|analytics|export|data_flow|backup|audit_record|tombstone|marketing|legal_hold)_(\d+)\b")


def extract_text(path: Path, ocr_texts: dict | None = None) -> str:
    key = str(path.name)
    if ocr_texts and key in ocr_texts:
        return ocr_texts[key]
    try:
        if path.suffix.lower() == ".pdf":
            if shutil.which("pdftotext"):
                return subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True,
                                      text=True, timeout=60).stdout
            from pypdf import PdfReader  # fallback
            return "\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)
        if shutil.which("tesseract"):
            return subprocess.run(["tesseract", str(path), "-", "--psm", "6"], capture_output=True,
                                  text=True, timeout=120).stdout
    except Exception:
        pass
    return ""


def obs_from_document(fid, ftime, path: Path, corpus: Corpus, ocr_texts=None):
    text = extract_text(path, ocr_texts)
    if ocr_texts is not None:
        ocr_texts[str(path.name)] = text
    if not text.strip():
        corpus.warnings.append(f"{fid}: no text extracted from {path.name}")
        return
    is_pdf = path.suffix.lower() == ".pdf"
    lines = text.splitlines()

    def ids_in(chunk: str):
        return (frozenset(norm_email(e) for e in EMAIL_RE.findall(chunk)) - {None},
                frozenset(norm_phone(p) for p in PHONE_RE.findall(chunk)) - {None},
                frozenset(norm_hash(h) for h in HASH_RE.findall(chunk)) - {None},
                frozenset(USER_RE.findall(chunk)))

    doc_ids = ids_in(text)
    all_rids = list(dict.fromkeys(m.group(0) for m in RID_RE.finditer(text)))
    lower = text.lower()
    seen = set()
    for i, line in enumerate(lines):
        for m in RID_RE.finditer(line):
            rid = m.group(0)
            if rid in seen:
                continue
            seen.add(rid)
            emails, phones, hashes, refs = ids_in(line)
            if is_pdf and len(all_rids) <= 2:       # small single-subject document: whole page applies
                emails, phones, hashes, refs = doc_ids
            for pre, system, kind in _PREFIX_KIND:
                if not rid.startswith(pre):
                    continue
                flags = {"present": True}
                if kind == "ANALYTICS":
                    flags["identifiable"] = bool(emails or hashes or refs or phones)
                if kind == "FLOW":
                    flags["enabled"] = True
                if kind == "BACKUP":
                    flags["restore_allowed"] = True
                if kind == "SUPPORT_MSG" and ("attachment" in lower or ".pdf" in lower or "identity document" in lower):
                    kind = "SUPPORT_ATT"
                if kind == "SUPPORT_MSG":
                    flags["redacted"] = False
                corpus.obs.append(Obs(file_id=fid, file_time=ftime, obs_time=ftime, system=system, rid=rid,
                                      kind=kind, emails=emails, phones=phones, hashes=hashes, refs=refs,
                                      flags=flags, source="document-text"))
                break


def obs_from_misc_json(fid, ftime, doc, corpus: Corpus):
    src = doc.get("source", "")
    ts = parse_ts(doc.get("captured_at")) or ftime
    for r in doc.get("records", []):
        rid = r.get("resource_id")
        if not rid:
            continue
        if rid.startswith("analytics_"):
            ident = any(not is_null(r.get(k)) for k in ("email", "phone", "email_hash", "user_id"))
            corpus.obs.append(Obs(file_id=fid, file_time=ftime, obs_time=ts, system="analytics_platform", rid=rid,
                                  kind="ANALYTICS", emails=_emails(r.get("email")), phones=_phones(r.get("phone")),
                                  hashes=_hashes(r.get("email_hash")), refs=_refs(r.get("user_id")),
                                  flags={"present": True, "identifiable": ident}, source="json-analytics-report"))
        elif rid.startswith("export_"):
            corpus.obs.append(Obs(file_id=fid, file_time=ftime, obs_time=ts, system="export_service", rid=rid,
                                  kind="EXPORT", emails=_emails(r.get("owner_email")),
                                  flags={"present": bool(r.get("download_available", True))}, source="json-export-jobs"))
        else:
            corpus.warnings.append(f"{fid}: unhandled misc record {rid}")
