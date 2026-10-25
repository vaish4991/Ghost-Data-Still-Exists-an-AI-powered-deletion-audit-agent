# Evaluation Report: Ghost Data Still Exists Deletion Audit Agent

## 1. Executive Summary
- **Task**: Audit deletion requests against multi-system residual data and resurrection risks at audit cutoff.
- **Evaluated Dataset**: `dataset/sample_deletion_requests.csv` (32 official sample cases with public ground truth).
- **Target Full Dataset**: `dataset/deletion_requests.csv` (518 cases).
- **Deletion Status Accuracy**: **100.0%** (32/32 cases matching ground truth).
- **Exact Step Sequence Accuracy**: **56.2%** (18/32 cases exactly matching ground truth steps).
- **Execution Latency**: 0.14s for 32 sample cases (~4.4ms per case).

---

## 2. Status Classification Performance

### Confusion Matrix
| Ground Truth \ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE | Total |
|:--------------------------|:--------:|:----------:|:--------------:|:-----:|
| **COMPLETE**              | 10 | 0 | 0 | 10 |
| **INCOMPLETE**            | 0 | 22 | 0 | 22 |
| **NOT_APPLICABLE**        | 0 | 0 | 0 | 0 |

### Per-Class Metrics
| Status Class | Precision | Recall | F1 Score | Support |
|:-------------|:---------:|:------:|:--------:|:-------:|
| **COMPLETE** | 1.0000 | 1.0000 | 1.0000 | 10 |
| **INCOMPLETE** | 1.0000 | 1.0000 | 1.0000 | 22 |
| **NOT_APPLICABLE** | 0.0000 | 0.0000 | 0.0000 | 0 |
| **Macro Average** | 0.6667 | 0.6667 | 0.6667 | 32 |

---

## 3. Detailed Component Evaluation

### 3.1 Historical Identity Resolution
- Successfully indexed all 850 users and 306 audit log events.
- Reconstructed email renames, telephone number changes, and historical SHA256 hashes.
- Handled case-insensitive email normalization and cross-system identifier resolution without conflating unrelated individuals.

### 3.2 Evidence Store & Cutoff Enforcement
- Ingested 94 evidence files across JSON snapshots, service exports, SQLite database replicas, application logs, text handover notes, and PDF attachments.
- Strictly enforced `audit_at` cutoff: zero future events leaked into historical deletion decisions.
- Successfully extracted 64-character SHA256 hashes linking marketing profiles in observability exports (`analytics_9914`).
- Filtered intermediate `*_started` query events to ensure final completed readback states (`404` / `rows=0`) take precedence.

### 3.3 Dynamic Policy Engine
- Implemented all 15 rules from `deletion_rules.csv`.
- Enforced Rule 01 (USER_PROFILE -> DELETE), Rule 06 (SUPPORT_ATTACHMENT -> DELETE), Rule 10 (MARKETING_PROFILE -> DELETE), and Rule 12 (SECURITY_AUDIT_LOG -> RETAIN).
- Accurately distinguished between required deletion, anonymization, redaction, retention, and flow disabling.

### 3.4 Canonical Step Ordering & Strict Validation
- Fully compliant with the 4-level sorting contract: Phase (FINDING -> REMEDIATION -> VERIFICATION) -> Operation precedence -> System ID ascending -> Resource ID ascending.
- Renumbered consecutively 1-indexed.
- Passed 100% of schema checks in `StrictValidator`.

---

## 4. Failure Analysis & Continuous Improvements
1. **Log Observation Precedence**: Initially, started lookup events with empty filters were treated as active presence. Adding filter logic to ignore `*_started` events and rely exclusively on completed events (`404` / `rows=0`) resolved `case_03`.
2. **Marketing Profile Detection**: `analytics_9914` was logged with `email_opt_in=true`. Adding marketing detection in log parsing resolved `case_12`, ensuring Rule 10 applies.
3. **Unquoted Backup State Parsing**: `backup_service` logs contained unquoted `eligible=true deletion_block=false`. Expanding parsing to handle unquoted key-value flags resolved `case_17`.
4. **Export Queries & Document Indexing**: Search service exports stored queries in `item["query"]` and documents in `hits["documents"]`. Adding deep indexing enabled 100% discovery for cases 23, 24, 29, and 30.

---

## 5. Output Verification
- Output File: `output.csv` (repository root)
- Row Count: Exactly 519 lines (header + 518 cases)
- Case Coverage: 100% of 518 input deletion requests
- Schema Compliance: 100% strictly validated with 0 errors.
