"""Output Generator module for Ghost Data Still Exists.
Handles step ordering, serialization, and writing the final output.csv.
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List
from code.config import OP_ORDER, PHASE_ORDER


def sort_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort steps according to challenge rules:
    1. Phase: FINDING, then REMEDIATION, then VERIFICATION.
    2. Operation: defined in problem statement table.
    3. system_id ascending.
    4. resource_id ascending.
    Then renumbers step_no consecutively from 1.
    """
    def sort_key(s: Dict[str, Any]):
        phase = s["phase"]
        operation = s["operation"]
        system_id = s["system_id"]
        resource_id = s["resource_id"]
        p_idx = PHASE_ORDER.index(phase) if phase in PHASE_ORDER else 99
        op_idx = OP_ORDER[phase].index(operation) if phase in OP_ORDER and operation in OP_ORDER[phase] else 99
        return (p_idx, op_idx, system_id, resource_id)

    sorted_list = sorted(steps, key=sort_key)
    for i, s in enumerate(sorted_list):
        s["step_no"] = i + 1
    return sorted_list


def serialize_steps(steps: List[Dict[str, Any]]) -> str:
    """Serialize steps array to JSON string."""
    return json.dumps(steps, separators=(",", ":"))


def write_output_csv(records: List[Dict[str, Any]], output_path: Path):
    """Write predictions to output.csv preserving the official input request order."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for r in records:
            cid = r["case_id"]
            status = r["deletion_status"]
            steps_json = r["steps_json"]
            if not isinstance(steps_json, str):
                steps_json = serialize_steps(steps_json)
            writer.writerow([cid, status, steps_json])
