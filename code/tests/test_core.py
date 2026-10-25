"""Unit tests (supplementary; the real dataset is evaluated in evaluation/main.py)."""
import json, sys, unittest
from datetime import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ghostaudit.common import norm_email, norm_phone, parse_ts
from ghostaudit.evidence import Obs, Corpus, parse_log_line, _log_event_obs
from ghostaudit.engine import Auditor, Item, OP_ORDER
from ghostaudit.identity import IdentityBook
from ghostaudit.intent import authorizes_deletion
from ghostaudit.output import write_output, validate_output

T = datetime(2026, 9, 1)
_AU = None
def au():
    global _AU
    if _AU is None:
        _AU = Auditor()
    return _AU

def obs(kind, rid, system, **flags):
    return Obs("evidence_x", T, T, system, rid, kind, flags=flags)


class Normalization(unittest.TestCase):
    def test_email_case_and_space(self):
        self.assertEqual(norm_email("  CHOI.JIHOON94@GMAIL.COM "), "choi.jihoon94@gmail.com")
    def test_similar_email_not_merged(self):
        self.assertNotEqual(norm_email("smartinez6461.jr@gmail.com"), norm_email("smartinez6461@gmail.com"))
    def test_phone_digits(self):
        self.assertEqual(norm_phone("+81 90 6156 0005"), "819061560005")


class Identity(unittest.TestCase):
    def test_historical_email_resolves_same_user(self):
        b = IdentityBook()
        cur, old = b.resolve("minjun.kim@gmail.com"), b.resolve("minjun.kim90@gmail.com")
        self.assertEqual(cur.user_id, old.user_id)
        self.assertIn("minjun.kim90@gmail.com", cur.emails)
        self.assertGreaterEqual(len(cur.hashes), 2)
    def test_unknown_email_unresolved(self):
        self.assertIsNone(IdentityBook().resolve("nobody@example.invalid").user_id)


class Intent(unittest.TestCase):
    def test_deletion_languages(self):
        for t in ["Please erase the account linked to this email address.", "Solicito la eliminación permanente de la cuenta",
                  "Je demande la suppression définitive du compte", "このメールアドレスに関連するアカウントの完全な削除を依頼します。", "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다."]:
            self.assertTrue(authorizes_deletion(t), t)
    def test_non_deletion(self):
        for t in ["Please remove me from marketing lists only.", "I still need the account and my order history, so I am not asking for deletion.",
                  "Can you correct it without removing any of my records?", "I need a copy of last year's invoices for my records."]:
            self.assertFalse(authorizes_deletion(t), t)


class Logs(unittest.TestCase):
    def test_all_log_families_parse(self):
        lines = [
            '2026-09-15T11:51:19Z level=INFO service=account_service trace_id=tr-1 resource_id=account_1 event=profile_lookup_completed rows=0 http_status=404',
            '2026-07-28T05:51:21Z [INFO] [account_service] [tr-2] profile_lookup_completed: resource_id="account_1" rows="0" http_status="404"',
            '2026-07-03T07:51:32Z | DEBUG | account_service | tr-3 | profile_lookup_completed | resource_id="account_1" rows="0" http_status="404"',
            '2026-04-19T06:51:21Z {"severity":"INFO","service":"account_service","trace_id":"tr-4","resource_id":"account_1","event":"profile_lookup_completed","rows":"0","http_status":"404"}',
            '2026-03-25T08:51:54Z <14>1 node-4 account_service tr-5 - - level=INFO resource_id="account_1" event="profile_lookup_completed" rows="0" http_status="404"',
            '2026-06-08T09:51:35Z requestId=tr-6 level=INFO function=account_service message="resource_id=\\"account_1\\" event=\\"profile_lookup_completed\\" rows=\\"0\\" http_status=\\"404\\""',
        ]
        for l in lines:
            r = parse_log_line(l)
            self.assertEqual(r["event"], "profile_lookup_completed", l)
            self.assertEqual(r["kv"]["resource_id"], "account_1", l)
    def test_404_means_absent(self):
        base = dict(file_id="e", file_time=T, obs_time=T, system="account_service", rid="a", emails=frozenset(), phones=frozenset(), hashes=frozenset(), refs=frozenset(), source="t")
        o = _log_event_obs("profile_lookup_completed", {"rows": "0", "http_status": "404"}, base)
        self.assertFalse(o.flags["present"])


class Decisions(unittest.TestCase):
    def item(self, kind, rid, system, **fl):
        return au()._item_for(system, rid, [obs(kind, rid, system, **fl)], T)
    def test_policy_mapping(self):
        cases = [("SEARCH", dict(present=True), "DELETE_RECORD"), ("SUPPORT_MSG", dict(present=True, redacted=False), "REDACT_RECORD"),
                 ("SUPPORT_ATT", dict(present=True), "DELETE_RECORD"), ("ANALYTICS", dict(present=True, identifiable=True), "ANONYMIZE_RECORD"),
                 ("FLOW", dict(enabled=True), "DISABLE_DATA_FLOW"), ("BACKUP", dict(restore_allowed=True), "BLOCK_RESTORE"),
                 ("TOMBSTONE", dict(present=True, identifiable=True), "REDACT_RECORD")]
        for kind, fl, op in cases:
            it = self.item(kind, "r_1", "sys", **fl)
            self.assertFalse(it.compliant); self.assertEqual(it.remediation_op, op)
    def test_retained_records_never_deleted(self):
        for kind in ("AUDIT", "LEGAL_HOLD"):
            it = self.item(kind, "r", "s", present=True)
            self.assertTrue(it.compliant); self.assertEqual(it.verify_op, "VERIFY_RECORD_PRESENT"); self.assertIsNone(it.remediation_op)
    def test_compliant_states(self):
        self.assertTrue(self.item("ANALYTICS", "r", "s", present=True, identifiable=False).compliant)
        self.assertTrue(self.item("SUPPORT_MSG", "r", "s", present=True, redacted=True).compliant)
        self.assertTrue(self.item("FLOW", "r", "s", enabled=False).compliant)
        self.assertTrue(self.item("BACKUP", "r", "s", restore_allowed=False).compliant)
        self.assertTrue(self.item("ACCOUNT", "r", "s", present=False).compliant)
    def test_active_flow_makes_case_incomplete_even_if_everything_else_clean(self):
        items = [self.item("ACCOUNT", "account_1", "account_service", present=False), self.item("FLOW", "data_flow_1", "integration_service", enabled=True)]
        res = au()._decide("c", None, items)
        self.assertEqual(res.status, "INCOMPLETE")
        ops = [s["operation"] for s in res.steps]
        self.assertLess(ops.index("DISABLE_DATA_FLOW"), ops.index("VERIFY_DATA_FLOW_DISABLED"))
        self.assertTrue(all(s["evidence_id"] == "" for s in res.steps if s["phase"] != "FINDING"))
    def test_missing_evidence_is_not_complete(self):
        self.assertEqual(au()._decide("c", None, []).status, "INCOMPLETE")
    def test_complete_has_only_cited_verification(self):
        res = au()._decide("c", None, [self.item("ACCOUNT", "account_1", "account_service", present=False)])
        self.assertEqual(res.status, "COMPLETE")
        self.assertTrue(all(s["phase"] == "VERIFICATION" and s["evidence_id"] == "evidence_x" for s in res.steps))
    def test_ordering_rule(self):
        items = [self.item("SEARCH", "search_2", "search_service", present=True), self.item("SEARCH", "search_1", "search_service", present=True),
                 self.item("ANALYTICS", "analytics_1", "analytics_platform", present=True, identifiable=True),
                 self.item("FLOW", "data_flow_1", "integration_service", enabled=True)]
        res = au()._decide("c", None, items)
        rem = [(s["operation"], s["resource_id"]) for s in res.steps if s["phase"] == "REMEDIATION"]
        self.assertEqual(rem, [("DISABLE_DATA_FLOW", "data_flow_1"), ("DELETE_RECORD", "search_1"), ("DELETE_RECORD", "search_2"), ("ANONYMIZE_RECORD", "analytics_1")])
        self.assertEqual([s["step_no"] for s in res.steps], list(range(1, len(res.steps) + 1)))


class Serialization(unittest.TestCase):
    def test_roundtrip_and_validation(self):
        from ghostaudit.engine import CaseResult
        import tempfile
        steps = au()._decide("case_1", None, [au()._item_for("account_service", "account_1", [obs("ACCOUNT", "account_1", "account_service", present=False)], T)]).steps
        res = {"case_2": CaseResult("case_2", "NOT_APPLICABLE", []), "case_1": CaseResult("case_1", "COMPLETE", steps)}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "o.csv"; write_output(res, p)
            self.assertEqual(validate_output(p, ["case_1", "case_2"]), [])
            self.assertIn("case_2,NOT_APPLICABLE,[]", p.read_text())


if __name__ == "__main__":
    unittest.main()
