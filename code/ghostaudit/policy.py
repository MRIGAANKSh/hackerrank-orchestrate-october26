"""Data-driven policy engine built from deletion_rules.csv."""
from __future__ import annotations

import csv
from dataclasses import dataclass

from .common import DATASET

# evidence kind -> deletion_rules.csv data_category
KIND_CATEGORY = {
    "ACCOUNT": "USER_PROFILE", "SEARCH": "SEARCH_INDEX_ENTRY", "CACHE": "CACHE_ENTRY",
    "SUPPORT_MSG": "SUPPORT_MESSAGE", "SUPPORT_ATT": "SUPPORT_ATTACHMENT",
    "ANALYTICS": "ANALYTICS_PROFILE", "EXPORT": "USER_EXPORT", "MARKETING": "MARKETING_PROFILE",
    "SECONDARY_ID": "SECONDARY_IDENTIFIER", "EMAIL_LOG": "EMAIL_DELIVERY_LOG",
    "AUDIT": "SECURITY_AUDIT_LOG", "LEGAL_HOLD": "LEGAL_HOLD_RECORD", "BACKUP": "BACKUP_ARCHIVE",
    "TOMBSTONE": "ACCOUNT_TOMBSTONE",
}


@dataclass
class Rule:
    rule_id: str
    category: str
    condition: str
    action: str


class Policy:
    def __init__(self):
        self.rules: dict[str, Rule] = {}
        with open(DATASET / "deletion_rules.csv", encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                self.rules[r["data_category"]] = Rule(r["rule_id"], r["data_category"], r["condition"], r["required_action"])

    def action_for(self, kind: str) -> Rule | None:
        return self.rules.get(KIND_CATEGORY.get(kind, ""))
