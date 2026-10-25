"""Does the request authorize deletion?  Multilingual, negation-aware."""
from __future__ import annotations

import re

_NEG = [
    r"not asking for deletion", r"do not close", r"don't delete", r"do not delete", r"leave the account",
    r"leave my profile", r"keep the account", r"not a request to erase", r"marketing lists only",
    r"stop the promotional", r"without removing", r"still need the account", r"still use it",
    r"continue using the service", r"resetting the login", r"reset the login", r"(need|send me) a copy of", r"download my account",
    r"portable format", r"what personal information", r"misspelled", r"out of date", r"change the email address",
    r"receipts and service messages",
]
_POS = [
    r"\bdelet", r"\berase", r"\bremov", r"\bclose\b", r"\bclosed\b", r"permanent", r"suppression", r"supprim",
    r"exclus[aã]o", r"eliminaci", r"eliminar", r"削除", r"삭제", r"\bclosing\b", r"erasure",
    r"\bgone\b", r"\bremoved\b", r"\bdeletion\b", r"\bdeleted\b", r"deleting", r"fully removed",
]


def authorizes_deletion(text: str) -> bool:
    t = (text or "").lower()
    if any(re.search(p, t) for p in _NEG):
        return False
    return any(re.search(p, t) for p in _POS)
