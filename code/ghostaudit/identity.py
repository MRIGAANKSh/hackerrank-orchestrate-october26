"""Identity resolution: request email -> user -> every current/historical identifier."""
from __future__ import annotations

import csv
from dataclasses import dataclass, field

from .common import DATASET, norm_email, norm_hash, norm_phone


@dataclass
class Identity:
    user_id: str | None
    emails: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    names: set = field(default_factory=set)
    notes: list = field(default_factory=list)
    ambiguous: bool = False

    @property
    def refs(self) -> set:
        return {self.user_id} if self.user_id else set()

    def all(self) -> set:
        return self.emails | self.phones | self.hashes | self.refs


class IdentityBook:
    def __init__(self):
        self.users: dict[str, dict] = {}
        self.by_current_email: dict[str, list[str]] = {}
        self.by_hist_email: dict[str, list[str]] = {}
        self.hist: dict[str, list[dict]] = {}
        with open(DATASET / "user_identities.csv", encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                self.users[r["user_id"]] = r
                e = norm_email(r["email"])
                if e:
                    self.by_current_email.setdefault(e, []).append(r["user_id"])
        with open(DATASET / "user_audit_log.csv", encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                self.hist.setdefault(r["user_id"], []).append(r)
                if r["field_name"] == "email":
                    for v in (r["old_value"], r["new_value"]):
                        e = norm_email(v)
                        if e:
                            self.by_hist_email.setdefault(e, [])
                            if r["user_id"] not in self.by_hist_email[e]:
                                self.by_hist_email[e].append(r["user_id"])

    def resolve(self, email: str) -> Identity:
        e = norm_email(email)
        cur = self.by_current_email.get(e, [])
        his = [u for u in self.by_hist_email.get(e, []) if u not in cur]
        if len(cur) == 1:
            uid, note = cur[0], "matched current email"
        elif len(cur) > 1:
            return Identity(None, {e}, notes=[f"ambiguous current email: {cur}"], ambiguous=True)
        elif len(his) == 1:
            uid, note = his[0], "matched historical email via user_audit_log"
        elif len(his) > 1:
            return Identity(None, {e}, notes=[f"ambiguous historical email: {his}"], ambiguous=True)
        else:
            return Identity(None, {e} if e else set(), notes=["email not found in identity data"])
        ident = Identity(uid, {e}, notes=[note])
        u = self.users[uid]
        ident.emails |= {x for x in [norm_email(u["email"])] if x}
        ident.phones |= {x for x in [norm_phone(u["phone"])] if x}
        ident.hashes |= {x for x in [norm_hash(u["email_hash"])] if x}
        if u.get("name"):
            ident.names.add(u["name"])
        for h in self.hist.get(uid, []):
            f = h["field_name"]
            for v in (h["old_value"], h["new_value"]):
                if f == "email":
                    x = norm_email(v)
                    if x: ident.emails.add(x)
                elif f == "phone":
                    x = norm_phone(v)
                    if x: ident.phones.add(x)
                elif f == "email_hash":
                    x = norm_hash(v)
                    if x: ident.hashes.add(x)
                elif f == "name" and v:
                    ident.names.add(v)
        return ident
