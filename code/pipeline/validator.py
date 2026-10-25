"""Independent strict validator for Ghost Data Still Exists output.csv.
Checks header, schema, types, step numbering, phase order, operation order,
states, evidence citations, and complete request coverage.
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from code.config import (
    ALLOWED_STATES,
    OP_ORDER,
    PHASE_ORDER,
    REQUIRED_STEP_FIELDS,
    VALID_STATUSES,
)


class StrictValidator:
    def __init__(self, output_path: Path, expected_case_ids: Optional[List[str]] = None):
        self.output_path = Path(output_path)
        self.expected_case_ids = expected_case_ids
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate(self) -> Tuple[bool, List[str], List[str]]:
        self.errors.clear()
        self.warnings.clear()

        if not self.output_path.exists():
            self.errors.append(f"Output file does not exist: {self.output_path}")
            return False, self.errors, self.warnings

        with open(self.output_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)

            # Check Header
            expected_header = ["case_id", "deletion_status", "steps_json"]
            if header != expected_header:
                self.errors.append(f"Header mismatch. Expected {expected_header}, got {header}")

            rows = list(reader)

        row_count = len(rows)
        if self.expected_case_ids is not None:
            if row_count != len(self.expected_case_ids):
                self.errors.append(
                    f"Row count mismatch. Expected {len(self.expected_case_ids)}, got {row_count}"
                )

        observed_case_ids = []
        for i, row in enumerate(rows, start=2):
            if len(row) != 3:
                self.errors.append(f"Line {i}: Expected 3 columns, got {len(row)}: {row}")
                continue

            case_id, deletion_status, steps_json = row
            observed_case_ids.append(case_id)

            # Status validation
            if deletion_status not in VALID_STATUSES:
                self.errors.append(f"Line {i} ({case_id}): Invalid deletion_status '{deletion_status}'")

            # JSON validation
            try:
                steps = json.loads(steps_json)
            except Exception as e:
                self.errors.append(f"Line {i} ({case_id}): Malformed JSON in steps_json: {e}")
                continue

            if not isinstance(steps, list):
                self.errors.append(f"Line {i} ({case_id}): steps_json must be a JSON array, got {type(steps).__name__}")
                continue

            # NOT_APPLICABLE must have empty array
            if deletion_status == "NOT_APPLICABLE":
                if len(steps) != 0:
                    self.errors.append(f"Line {i} ({case_id}): NOT_APPLICABLE must have empty array '[]', got {len(steps)} steps")
                continue

            # COMPLETE or INCOMPLETE must have steps
            if len(steps) == 0:
                self.errors.append(f"Line {i} ({case_id}): Status '{deletion_status}' must not have empty steps")
                continue

            # COMPLETE must only contain VERIFICATION
            if deletion_status == "COMPLETE":
                for s in steps:
                    if s.get("phase") != "VERIFICATION":
                        self.errors.append(f"Line {i} ({case_id}): COMPLETE case has non-verification step {s.get('phase')}")
                    if not s.get("evidence_id"):
                        self.errors.append(f"Line {i} ({case_id}): COMPLETE verification step missing evidence_id: {s}")

            # Validate each step
            prev_phase_idx = -1
            prev_op_idx = -1
            prev_sys = ""
            prev_res = ""

            has_finding = False
            for step_idx, s in enumerate(steps, start=1):
                # Step numbering
                if s.get("step_no") != step_idx:
                    self.errors.append(f"Line {i} ({case_id}): Step number mismatch. Expected {step_idx}, got {s.get('step_no')}")

                # Required fields
                for f in REQUIRED_STEP_FIELDS:
                    if f not in s:
                        self.errors.append(f"Line {i} ({case_id}) step {step_idx}: Missing required field '{f}'")

                # Extra fields
                for k in s:
                    if k not in REQUIRED_STEP_FIELDS:
                        self.errors.append(f"Line {i} ({case_id}) step {step_idx}: Prohibited extra field '{k}'")

                phase = s.get("phase")
                op = s.get("operation")
                state = s.get("state")
                sys_id = s.get("system_id", "")
                res_id = s.get("resource_id", "")
                eid = s.get("evidence_id", "")

                if phase not in PHASE_ORDER:
                    self.errors.append(f"Line {i} ({case_id}) step {step_idx}: Invalid phase '{phase}'")
                    continue

                if phase == "FINDING":
                    has_finding = True
                    if not eid:
                        self.errors.append(f"Line {i} ({case_id}) step {step_idx}: Finding step must cite genuine evidence_id")

                if phase in ("REMEDIATION",) and eid != "":
                    self.errors.append(f"Line {i} ({case_id}) step {step_idx}: Remediation step must have empty evidence_id, got '{eid}'")

                if deletion_status == "INCOMPLETE" and phase == "VERIFICATION" and eid != "":
                    self.errors.append(f"Line {i} ({case_id}) step {step_idx}: Post-remediation verification step must have empty evidence_id, got '{eid}'")

                if op not in OP_ORDER.get(phase, []):
                    self.errors.append(f"Line {i} ({case_id}) step {step_idx}: Invalid operation '{op}' for phase '{phase}'")
                    continue

                # Allowed state
                expected_state = ALLOWED_STATES.get(op)
                if state != expected_state:
                    self.errors.append(f"Line {i} ({case_id}) step {step_idx}: Invalid state '{state}' for op '{op}'. Expected '{expected_state}'")

                # Sorting verification
                phase_idx = PHASE_ORDER.index(phase)
                op_idx = OP_ORDER[phase].index(op)

                sort_tuple = (phase_idx, op_idx, sys_id, res_id)
                prev_tuple = (prev_phase_idx, prev_op_idx, prev_sys, prev_res)

                if sort_tuple < prev_tuple:
                    self.errors.append(
                        f"Line {i} ({case_id}) step {step_idx}: Out of order! "
                        f"Current: ({phase}, {op}, {sys_id}, {res_id}), Previous: ({PHASE_ORDER[prev_phase_idx] if prev_phase_idx >= 0 else ''}, prev_op, {prev_sys}, {prev_res})"
                    )

                prev_phase_idx = phase_idx
                prev_op_idx = op_idx
                prev_sys = sys_id
                prev_res = res_id

            if deletion_status == "INCOMPLETE" and not has_finding:
                self.errors.append(f"Line {i} ({case_id}): INCOMPLETE case must have at least one FINDING step")

        # Check case_id sorting and completeness
        if self.expected_case_ids is not None:
            if observed_case_ids != self.expected_case_ids:
                missing = set(self.expected_case_ids) - set(observed_case_ids)
                extra = set(observed_case_ids) - set(self.expected_case_ids)
                if missing:
                    self.errors.append(f"Missing case IDs: {sorted(list(missing))[:10]}")
                if extra:
                    self.errors.append(f"Unexpected case IDs: {sorted(list(extra))[:10]}")
                if not missing and not extra:
                    self.errors.append("Case IDs are not sorted in the exact expected order.")

        is_valid = len(self.errors) == 0
        return is_valid, self.errors, self.warnings
