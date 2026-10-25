"""Evidence Retrieval and Inspection module for Ghost Data Still Exists.
Parses, indexes, and queries evidence across JSON snapshots, SQLite databases, logs, text records, and PDFs.
"""

import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import fitz
from code.pipeline.ingestion import parse_iso


class EvidenceStore:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = Path(dataset_dir)
        self.manifest: Dict[str, Dict[str, Any]] = {}
        self.resource_snapshots: Dict[str, List[Dict[str, Any]]] = {}
        self.user_to_resources: Dict[str, Set[str]] = {}
        self._load_manifest()
        self._parse_all_evidence()

    def _load_manifest(self):
        manifest_path = self.dataset_dir / "evidence_files.csv"
        import csv
        with open(manifest_path, "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                fid = r["file_id"].strip()
                rel_path = r["file_path"].strip()
                self.manifest[fid] = {
                    "file_id": fid,
                    "file_path": rel_path,
                    "abs_path": self.dataset_dir / rel_path,
                    "origin": r["origin"].strip(),
                    "captured_at": r["captured_at"].strip(),
                    "captured_dt": parse_iso(r["captured_at"]),
                }

    def _add_obs(
        self,
        rid: str,
        system_id: str,
        state: str,
        evidence_id: str,
        dt: datetime,
        raw_data: Optional[Dict[str, Any]] = None,
        user_refs: Optional[List[Optional[str]]] = None,
    ):
        if not rid:
            return
        obs = {
            "resource_id": rid,
            "system_id": system_id,
            "state": state,
            "evidence_id": evidence_id,
            "captured_dt": dt,
            "data": raw_data or {},
        }
        self.resource_snapshots.setdefault(rid, []).append(obs)
        if user_refs:
            for u in user_refs:
                if u:
                    clean_u = u.strip().lower()
                    self.user_to_resources.setdefault(clean_u, set()).add(rid)

    def _parse_all_evidence(self):
        for fid, info in self.manifest.items():
            p = info["abs_path"]
            dt = info["captured_dt"]
            str_path = str(p)

            if str_path.endswith(".json"):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self._parse_json(fid, dt, data)
                except Exception:
                    pass

            elif str_path.endswith(".sql"):
                try:
                    self._parse_sql(fid, dt, str_path)
                except Exception:
                    pass

            elif str_path.endswith(".log") or str_path.endswith(".txt"):
                try:
                    self._parse_log_or_txt(fid, dt, str_path)
                except Exception:
                    pass

            elif str_path.endswith(".pdf"):
                try:
                    self._parse_pdf(fid, dt, str_path)
                except Exception:
                    pass

    def _parse_json(self, fid: str, dt: datetime, data: Any):
        # 1. Snapshot bundle
        if isinstance(data, dict) and "snapshots" in data:
            for snap in data["snapshots"]:
                store = snap.get("data_store")
                for rec in snap.get("records", []):
                    rid = rec.get("resource_id")
                    uid = rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference")
                    email = (
                        rec.get("email")
                        or rec.get("requester_email")
                        or rec.get("customer_email")
                        or rec.get("owner_email")
                    )
                    refs = [uid, email]

                    if store == "account_service":
                        status = rec.get("account_status", "ACTIVE")
                        state = "PRESENT" if status != "DELETED" else "ABSENT"
                        self._add_obs(rid, "account_service", state, fid, dt, rec, refs)
                    elif store == "identity_service":
                        has_pii = any(rec.get(k) for k in ["name", "email", "phone", "email_hash"])
                        state = "PRESENT" if has_pii else "REDACTED"
                        self._add_obs(rid, "identity_service", state, fid, dt, rec, refs)
                    elif store == "search_service":
                        self._add_obs(rid, "search_service", "PRESENT", fid, dt, rec, refs)
                    elif store == "analytics_platform":
                        has_pii = any(rec.get(k) for k in ["email", "phone", "email_hash"])
                        state = "PRESENT" if has_pii else "ANONYMIZED"
                        self._add_obs(rid, "analytics_platform", state, fid, dt, rec, refs)
                    elif store == "support_platform":
                        if "attachment" in str(rec).lower():
                            self._add_obs(rid, "support_platform", "PRESENT", fid, dt, rec, refs)
                        else:
                            has_pii = any(
                                rec.get(k) for k in ["requester_email", "requester_name", "requester_phone"]
                            )
                            state = "PRESENT" if has_pii else "REDACTED"
                            self._add_obs(rid, "support_platform", state, fid, dt, rec, refs)
                    elif store == "security_service":
                        self._add_obs(rid, "security_service", "PRESENT", fid, dt, rec, refs)
                    elif store == "backup_service":
                        allowed = rec.get("restore_allowed", True)
                        state = "ACTIVE" if allowed else "BLOCKED"
                        self._add_obs(rid, "backup_service", state, fid, dt, rec, refs)
                    elif store == "integration_service":
                        enabled = rec.get("enabled", True)
                        state = "ACTIVE" if enabled else "DISABLED"
                        self._add_obs(rid, "integration_service", state, fid, dt, rec, refs)

        # 2. service_resource_export
        elif isinstance(data, dict) and "service_exports" in data:
            for sys_id, export_data in data["service_exports"].items():
                for coll_name, items in export_data.items():
                    if isinstance(items, list):
                        for item in items:
                            rid = item.get("resource_id")
                            uid = (
                                item.get("customer_reference")
                                or item.get("subject_reference")
                                or item.get("user_id")
                            )
                            email = (
                                item.get("email")
                                or item.get("customer_email")
                                or item.get("requester_email")
                                or item.get("owner_email")
                            )
                            refs = [uid, email]
                            if item.get("query"):
                                refs.append(item.get("query"))
                            if "hits" in item and isinstance(item["hits"], dict):
                                for doc in item["hits"].get("documents", []):
                                    refs.extend([doc.get("customer_reference"), doc.get("email"), doc.get("resource_id")])

                            if sys_id == "account_service":
                                status_code = item.get("status_code", 404)
                                prof = item.get("profile")
                                state = "PRESENT" if (status_code == 200 and prof) else "ABSENT"
                                self._add_obs(rid, "account_service", state, fid, dt, item, refs)
                            elif sys_id == "search_service":
                                hits = item.get("hits", {})
                                total = hits.get("total", 0)
                                state = "PRESENT" if total > 0 else "ABSENT"
                                self._add_obs(rid, "search_service", state, fid, dt, item, refs)
                            elif sys_id == "analytics_platform":
                                has_pii = any(item.get(k) for k in ["email", "phone", "email_hash"])
                                state = "PRESENT" if has_pii else "ANONYMIZED"
                                self._add_obs(rid, "analytics_platform", state, fid, dt, item, refs)
                            elif sys_id == "support_platform":
                                has_pii = any(
                                    item.get(k) for k in ["requester_email", "requester_name", "requester_phone"]
                                )
                                state = "PRESENT" if has_pii else "REDACTED"
                                self._add_obs(rid, "support_platform", state, fid, dt, item, refs)
                            elif sys_id == "backup_service":
                                allowed = item.get("restore_allowed", False)
                                state = "ACTIVE" if allowed else "BLOCKED"
                                self._add_obs(rid, "backup_service", state, fid, dt, item, refs)
                            elif sys_id == "integration_service":
                                enabled = item.get("enabled", False)
                                state = "ACTIVE" if enabled else "DISABLED"
                                self._add_obs(rid, "integration_service", state, fid, dt, item, refs)
                            elif sys_id == "security_service":
                                self._add_obs(rid, "security_service", "PRESENT", fid, dt, item, refs)
                            elif sys_id == "export_service":
                                self._add_obs(rid, "export_service", "PRESENT", fid, dt, item, refs)

        # 3. customer_analytics_report or customer_export_jobs or other records
        elif isinstance(data, dict) and "records" in data:
            coll = data.get("collection", "")
            src = data.get("source", "")
            for rec in data["records"]:
                rid = rec.get("resource_id")
                if not rid:
                    continue
                if "analytics" in coll or "analytics" in src:
                    has_pii = any(rec.get(k) for k in ["email", "phone", "email_hash"])
                    state = "PRESENT" if has_pii else "ANONYMIZED"
                    refs = [rec.get("user_id"), rec.get("email")]
                    self._add_obs(rid, "analytics_platform", state, fid, dt, rec, refs)
                elif "export" in coll or "export" in src:
                    refs = [rec.get("owner_email"), rec.get("customer_reference")]
                    avail = rec.get("download_available", True)
                    state = "PRESENT" if avail else "ABSENT"
                    self._add_obs(rid, "export_service", state, fid, dt, rec, refs)
                else:
                    refs = [rec.get("user_id"), rec.get("email"), rec.get("customer_reference"), rec.get("subject_reference")]
                    self._add_obs(rid, "account_service", "PRESENT", fid, dt, rec, refs)

        elif isinstance(data, dict) and "jobs" in data:
            for rec in data["jobs"]:
                rid = rec.get("resource_id")
                refs = [rec.get("owner_email"), rec.get("customer_reference")]
                self._add_obs(rid, "export_service", "PRESENT", fid, dt, rec, refs)

    def _parse_sql(self, fid: str, dt: datetime, path: str):
        con = sqlite3.connect(":memory:")
        with open(path, "r", encoding="utf-8") as f:
            con.executescript(f.read())
        cur = con.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for tbl in tables:
            cols = [c[1] for c in cur.execute(f"PRAGMA table_info({tbl})").fetchall()]
            if "resource_id" in cols:
                for row in cur.execute(f"SELECT * FROM {tbl}").fetchall():
                    row_dict = dict(zip(cols, row))
                    rid = row_dict["resource_id"]
                    
                    if "record_json" in cols:
                        try:
                            rj = json.loads(row_dict["record_json"])
                            sys_id = row_dict.get("origin_system", "account_service")
                            uid = (
                                rj.get("user_id")
                                or rj.get("subject_reference")
                                or rj.get("customer_reference")
                            )
                            email = rj.get("email") or rj.get("customer_email") or rj.get("requester_email") or rj.get("owner_email")
                            if "document" in rj and isinstance(rj["document"], dict):
                                doc = rj["document"]
                                if not email: email = doc.get("email")
                                if not uid: uid = doc.get("customer_reference")
                            refs = [uid, email]

                            state = "PRESENT"
                            if sys_id == "account_service":
                                state = "PRESENT" if rj.get("account_status") != "DELETED" else "ABSENT"
                            elif sys_id == "analytics_platform":
                                has_pii = any(rj.get(k) for k in ["email", "phone", "email_hash"])
                                state = "PRESENT" if has_pii else "ANONYMIZED"
                            elif sys_id == "support_platform":
                                has_pii = any(
                                    rj.get(k) for k in ["requester_email", "requester_name", "requester_phone"]
                                )
                                state = "PRESENT" if has_pii else "REDACTED"
                            elif sys_id == "backup_service":
                                allowed = rj.get("restore_allowed", False)
                                state = "ACTIVE" if allowed else "BLOCKED"
                            elif sys_id == "integration_service":
                                enabled = rj.get("enabled", False)
                                state = "ACTIVE" if enabled else "DISABLED"
                            elif sys_id == "search_service":
                                state = "PRESENT"
                            elif sys_id == "security_service":
                                state = "PRESENT"

                            self._add_obs(rid, sys_id, state, fid, dt, row_dict, refs)
                        except Exception:
                            pass
                    else:
                        uid = (
                            row_dict.get("user_id")
                            or row_dict.get("customer_reference")
                            or row_dict.get("subject_reference")
                        )
                        email = (
                            row_dict.get("email")
                            or row_dict.get("customer_email")
                            or row_dict.get("requester_email")
                            or row_dict.get("owner_email")
                        )
                        refs = [uid, email]
                        if "source_resource_id" in row_dict:
                            refs.append(row_dict["source_resource_id"])

                        sys_id = "account_service"
                        state = "PRESENT"
                        if "customer_profiles" in tbl:
                            sys_id = "account_service"
                            state = "PRESENT" if row_dict.get("account_status") != "DELETED" else "ABSENT"
                        elif "analytics" in tbl:
                            sys_id = "analytics_platform"
                            has_pii = any(row_dict.get(k) for k in ["email", "phone", "email_hash"])
                            state = "PRESENT" if has_pii else "ANONYMIZED"
                        elif "backup" in tbl:
                            sys_id = "backup_service"
                            allowed = row_dict.get("restore_allowed") in (1, "1", True, "true", "TRUE")
                            state = "ACTIVE" if allowed else "BLOCKED"
                        elif "search" in tbl:
                            sys_id = "search_service"
                            state = "PRESENT"
                        elif "export" in tbl:
                            sys_id = "export_service"
                            state = "PRESENT"
                        elif "support" in tbl:
                            sys_id = "support_platform"
                            state = "PRESENT"
                        elif "security" in tbl or "audit" in tbl:
                            sys_id = "security_service"
                            state = "PRESENT"
                        self._add_obs(rid, sys_id, state, fid, dt, row_dict, refs)
        con.close()

    def _parse_log_or_txt(self, fid: str, dt: datetime, path: str):
        if path.endswith(".txt"):
            self._parse_txt(fid, dt, path)
        else:
            self._parse_log(fid, dt, path)

    def _parse_txt(self, fid: str, dt: datetime, path: str):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("- "):
                    parts = [p.strip() for p in line[2:].split("|")]
                    if len(parts) >= 6:
                        sys_id = parts[1]
                        rid = parts[2]
                        st_raw = parts[4]
                        ident = parts[5]
                        
                        state = "PRESENT"
                        if st_raw in ("NOT_FOUND", "ABSENT"):
                            state = "ABSENT"
                        elif st_raw in ("FOUND", "IDENTIFIABLE", "PRESENT"):
                            state = "PRESENT"
                        elif st_raw == "ANONYMIZED":
                            state = "ANONYMIZED"
                        elif st_raw == "REDACTED":
                            state = "REDACTED"
                        elif st_raw in ("ACTIVE", "ENABLED"):
                            state = "ACTIVE"
                        elif st_raw in ("BLOCKED", "DISABLED"):
                            state = "BLOCKED" if sys_id == "backup_service" else "DISABLED"

                        self._add_obs(rid, sys_id, state, fid, dt, {"line": line}, [ident])

    def _parse_log(self, fid: str, dt: datetime, path: str):
        trace_map = {}
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                t_match = re.search(r"tr-[0-9a-zA-Z]+", line)
                tid = t_match.group(0) if t_match else None

                emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", line)
                uids = re.findall(r"user_\d+", line)
                rids = re.findall(r"(?:account|analytics|backup|data_flow|search|security|audit_record|support|export|object|tombstone)_\d+", line)
                hashes = re.findall(r"\b[a-f0-9]{64}\b", line)

                if tid:
                    if tid not in trace_map:
                        trace_map[tid] = {"keys": set(), "resources": set()}
                    for e in emails: trace_map[tid]["keys"].add(e.lower())
                    for u in uids: trace_map[tid]["keys"].add(u.lower())
                    for h in hashes: trace_map[tid]["keys"].add(h.lower())
                    for r in rids: trace_map[tid]["resources"].add(r)
                else:
                    for r in rids:
                        for e in emails:
                            self.user_to_resources.setdefault(e.lower(), set()).add(r)
                        for u in uids:
                            self.user_to_resources.setdefault(u.lower(), set()).add(r)
                        for h in hashes:
                            self.user_to_resources.setdefault(h.lower(), set()).add(r)

                rm = re.search(r"resource_id[=:\s\"]+([a-zA-Z0-9_-]+)", line)
                if rm:
                    if "event=" in line and "_started" in line:
                        continue

                    rid = rm.group(1)
                    sys_id = "account_service"
                    for s in [
                        "account_service", "analytics_platform", "backup_service",
                        "integration_service", "search_service", "security_service",
                        "support_platform", "export_service", "identity_service"
                    ]:
                        if s in line:
                            sys_id = s
                            break

                    state = "PRESENT"
                    if "404" in line or "rows=0" in line or "rows\": \"0\"" in line or "rows\":\"0\"" in line:
                        state = "ABSENT"
                    elif "200" in line or "rows=1" in line or "rows\": \"1\"" in line or "rows\":\"1\"" in line:
                        state = "PRESENT"

                    if sys_id == "analytics_platform":
                        has_pii = (
                            ("email=" in line and "email=null" not in line)
                            or ("email\": null" not in line and "\"email\":" in line)
                            or ("matched_value" in line)
                            or ("email_opt_in=true" in line.lower())
                            or ("correlation_key=" in line and "correlation_key=null" not in line and 'correlation_key=""' not in line)
                        )
                        state = "PRESENT" if has_pii else "ANONYMIZED"
                    elif sys_id == "support_platform":
                        has_pii = ("requester_email=" in line and "requester_email=null" not in line) or ("message_text" in line and "[REDACTED]" not in line) or ("message_pii_scan" in line)
                        state = "PRESENT" if has_pii else "REDACTED"
                    elif sys_id == "backup_service":
                        ll = line.lower()
                        state = "ACTIVE" if (
                            "restore_allowed=true" in ll
                            or "eligible=true" in ll
                            or 'eligible":"true"' in ll
                            or 'eligible": true' in ll
                            or "deletion_block=false" in ll
                            or 'deletion_block":"false"' in ll
                            or 'deletion_block": false' in ll
                        ) else "BLOCKED"
                    elif sys_id == "integration_service":
                        state = "ACTIVE" if ("enabled=true" in line.lower() or "status=delivered" in line.lower() or "remains enabled" in line.lower()) else "DISABLED"

                    refs = emails + uids + hashes
                    self._add_obs(rid, sys_id, state, fid, dt, {"line": line}, refs)

        for t, v in trace_map.items():
            for k in v["keys"]:
                for r in v["resources"]:
                    self.user_to_resources.setdefault(k, set()).add(r)

    def _parse_pdf(self, fid: str, dt: datetime, path: str):
        doc = fitz.open(path)
        full_text = ""
        for page in doc:
            full_text += page.get_text() + "\n"
        matches = re.findall(
            r"(support_\d+|audit_record_\d+|export_\d+|account_\d+|search_\d+|analytics_\d+|backup_\d+|data_flow_\d+|tombstone_\d+)",
            full_text,
        )
        users = re.findall(r"(user_\d+)", full_text)
        emails = re.findall(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", full_text)
        refs = list(users) + list(emails)
        for rid in set(matches):
            sys_id = (
                "support_platform"
                if "support" in rid
                else ("security_service" if "audit" in rid else "export_service")
            )
            self._add_obs(rid, sys_id, "PRESENT", fid, dt, {"pdf": True}, refs)

    def get_latest_observation(
        self, resource_id: str, cutoff_dt: datetime
    ) -> Optional[Dict[str, Any]]:
        obs_list = [o for o in self.resource_snapshots.get(resource_id, []) if o["captured_dt"] <= cutoff_dt]
        if not obs_list:
            return None
        obs_list.sort(key=lambda x: x["captured_dt"], reverse=True)
        return obs_list[0]

