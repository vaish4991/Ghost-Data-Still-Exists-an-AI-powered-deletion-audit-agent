"""Dataset ingestion module for Ghost Data Still Exists.
Reads and normalizes all CSV, JSON, SQL, LOG, TXT, and PDF evidence files.
"""

import csv
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import fitz


def parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 string to a timezone-aware UTC datetime."""
    if not dt_str:
        return None
    cleaned = dt_str.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def normalize_email(email: Optional[str]) -> str:
    """Normalize email address to lowercase and stripped whitespace."""
    if not email:
        return ""
    return email.strip().lower()


def normalize_phone(phone: Optional[str]) -> str:
    """Normalize phone number by stripping whitespace."""
    if not phone:
        return ""
    return re.sub(r"\s+", " ", phone.strip())


def normalize_hash(h: Optional[str]) -> str:
    """Normalize hex hash."""
    if not h:
        return ""
    return h.strip().lower()


class IngestionEngine:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = Path(dataset_dir)
        self.evidence_dir = self.dataset_dir / "evidence"

    def load_deletion_requests(self, filename: str = "deletion_requests.csv") -> List[Dict[str, Any]]:
        path = Path(filename) if Path(filename).is_file() else (self.dataset_dir / filename)
        requests = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                requests.append({
                    "case_id": row["case_id"].strip(),
                    "email": normalize_email(row["email"]),
                    "raw_email": row["email"],
                    "requested_at": row["requested_at"].strip(),
                    "requested_dt": parse_iso(row["requested_at"]),
                    "reported_status": row["reported_status"].strip(),
                    "reported_at": row["reported_at"].strip(),
                    "reported_dt": parse_iso(row["reported_at"]),
                    "audit_at": row["audit_at"].strip(),
                    "audit_dt": parse_iso(row["audit_at"]),
                    "request_text": row["request_text"].strip(),
                })
        return requests

    def load_user_identities(self) -> List[Dict[str, Any]]:
        path = self.dataset_dir / "user_identities.csv"
        identities = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                identities.append({
                    "user_id": row["user_id"].strip(),
                    "name": row["name"].strip(),
                    "email": normalize_email(row["email"]),
                    "phone": normalize_phone(row["phone"]),
                    "email_hash": normalize_hash(row["email_hash"]),
                    "updated_at": row["updated_at"].strip(),
                    "updated_dt": parse_iso(row["updated_at"]),
                })
        return identities

    def load_user_audit_log(self) -> List[Dict[str, Any]]:
        path = self.dataset_dir / "user_audit_log.csv"
        logs = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                field = row["field_name"].strip()
                old_val = row["old_value"].strip()
                new_val = row["new_value"].strip()
                if field == "email":
                    old_val = normalize_email(old_val)
                    new_val = normalize_email(new_val)
                elif field == "email_hash":
                    old_val = normalize_hash(old_val)
                    new_val = normalize_hash(new_val)
                elif field == "phone":
                    old_val = normalize_phone(old_val)
                    new_val = normalize_phone(new_val)

                logs.append({
                    "audit_id": row["audit_id"].strip(),
                    "user_id": row["user_id"].strip(),
                    "event_time": row["event_time"].strip(),
                    "event_dt": parse_iso(row["event_time"]),
                    "field_name": field,
                    "old_value": old_val,
                    "new_value": new_val,
                })
        return logs

    def load_system_activity(self) -> List[Dict[str, Any]]:
        path = self.dataset_dir / "system_activity.csv"
        activities = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                activities.append({
                    "activity_id": row["activity_id"].strip(),
                    "event_time": row["event_time"].strip(),
                    "event_dt": parse_iso(row["event_time"]),
                    "event_type": row["event_type"].strip(),
                    "source_system": row["source_system"].strip(),
                    "target_system": row["target_system"].strip(),
                    "resource_id": row["resource_id"].strip(),
                    "reported_result": row["reported_result"].strip(),
                    "details": row["details"].strip(),
                })
        return activities

    def load_deletion_rules(self) -> Dict[str, str]:
        path = self.dataset_dir / "deletion_rules.csv"
        rules = {}
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cat = row["data_category"].strip()
                act = row["required_action"].strip()
                rules[cat] = act
        return rules

    def load_evidence_manifest(self) -> Dict[str, Dict[str, Any]]:
        path = self.dataset_dir / "evidence_files.csv"
        manifest = {}
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                fid = row["file_id"].strip()
                rel_path = row["file_path"].strip()
                abs_path = self.dataset_dir / rel_path
                manifest[fid] = {
                    "file_id": fid,
                    "file_path": rel_path,
                    "abs_path": abs_path,
                    "origin": row["origin"].strip(),
                    "captured_at": row["captured_at"].strip(),
                    "captured_dt": parse_iso(row["captured_at"]),
                }
        return manifest
