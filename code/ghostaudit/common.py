"""Shared helpers: paths, time parsing, identifier normalization."""
from __future__ import annotations
import re
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"
EVIDENCE = DATASET / "evidence"

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+\d[\d ()\-]{6,}\d")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
USER_RE = re.compile(r"\buser_\d+\b")


def parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip().replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def norm_email(v: str | None) -> str | None:
    """Casefold + trim. Deliberately NOT fuzzy: only formatting differences."""
    if v is None:
        return None
    v = str(v).strip().lower()
    if not v or v in ("null", "none"):
        return None
    return v if "@" in v else None


def norm_phone(v: str | None) -> str | None:
    if v is None:
        return None
    v = str(v).strip()
    if not v or v.lower() in ("null", "none"):
        return None
    digits = re.sub(r"\D", "", v)
    return digits if len(digits) >= 7 else None


def norm_hash(v: str | None) -> str | None:
    if v is None:
        return None
    v = str(v).strip().lower()
    return v if HASH_RE.fullmatch(v) else None


def is_null(v) -> bool:
    return v is None or str(v).strip().lower() in ("", "null", "none")
