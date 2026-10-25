# Ghost Data Still Exists - deletion audit agent

Deterministic, evidence-driven audit of 518 deletion requests for Northstar Shop. No LLM or API key is
needed at inference time (see `code/evaluation/usage_report.md`).

## Run
```bash
python3 code/main.py                 # writes ./output.csv (518 rows) and validates its schema
python3 code/evaluation/main.py      # sample evaluation, unit tests, full run, regenerates both reports
(cd code && python3 -m unittest tests.test_core)   # unit tests only
```
Requirements: Python 3.10+, `pypdf` (fallback only); `tesseract` and `pdftotext` (poppler) on PATH for
screenshots/PDFs (the run degrades gracefully without them). Runtime ~30 s. Paths are resolved relative to the repo root.

## Architecture (`code/ghostaudit/`)
| Module | Role |
|---|---|
| `evidence.py` | Parses six log dialects, JSON exports/bundles/ledgers, SQLite SQL snapshots (executed, primary vs replicas), text handovers into one `Obs` schema with provenance (file_id, observation time) |
| `documents.py` | OCR (tesseract) / pdftotext; identifiers attached to resource ids **per line** |
| `identity.py` | request email -> user via current email, then historical emails (`user_audit_log`); collects every email/phone/hash; ambiguous matches are not merged; no fuzzy matching |
| `policy.py` | Loads `deletion_rules.csv`; kind -> data_category -> DELETE/REDACT/ANONYMIZE/RETAIN |
| `intent.py` | Multilingual, negation-aware "does this authorize deletion?" |
| `engine.py` | Discovery by shared identifier, state at `audit_at` (latest observation per resource), policy compliance, COMPLETE/INCOMPLETE decision, step generation and ordering, activity-stream account location |
| `output.py` | CSV serialization + schema validation |
| `scoring.py`, `evaluation/main.py` | Metrics and report generation (labels used only here) |

## Decision rules
* NOT_APPLICABLE: request text does not authorize deletion -> `[]`.
* Reported statuses and activity results are **claims**; state comes from evidence observations at or before `audit_at`.
* INCOMPLETE if any copy violates policy (remaining record, exposed PII, enabled data flow, restorable backup) or if nothing can be verified.
  COMPLETE only when every discovered copy is compliant; retained audit/legal records are verified PRESENT, never deleted.
* INCOMPLETE rows: findings (cite evidence) -> remediation (empty evidence id) -> verification (empty evidence id).
  Order: operation order in the spec, then system_id, then resource_id.
* Evidence captured after `audit_at` is never cited (state is judged by observation time).

## Assumptions and limitations
* Account ids that never appear next to an identifier are located from deletion-worker events in `system_activity.csv`
  (window before `reported_at`, result matched to `reported_status`, global one-to-one assignment). Anonymized analytics rows (no identifiers by design) are tied to a case through the ANONYMIZE_RECORD chain and may be swapped between look-alike cases.
* Screenshot facts come from OCR heuristics; three screenshot-only cases end INCOMPLETE with no steps (missing evidence is not proof).
* The agent audits and recommends; it does not execute deletions.
