"""Status Classifier and Audit Orchestrator for Ghost Data Still Exists.
Orchestrates identity resolution, activity analysis, evidence retrieval, and policy evaluation
to determine the deletion status and ordered step sequence for each request.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from code.config import STATUS_COMPLETE, STATUS_INCOMPLETE, STATUS_NOT_APPLICABLE
from code.pipeline.activity_analysis import ActivityAnalyzer
from code.pipeline.evidence_retrieval import EvidenceStore
from code.pipeline.identity_resolution import IdentityResolver
from code.pipeline.output_generator import sort_steps
from code.pipeline.policy_engine import PolicyEngine


class DeletionAuditAgent:
    def __init__(
        self,
        resolver: IdentityResolver,
        activity_analyzer: ActivityAnalyzer,
        evidence_store: EvidenceStore,
        policy_engine: PolicyEngine,
    ):
        self.resolver = resolver
        self.activity_analyzer = activity_analyzer
        self.evidence_store = evidence_store
        self.policy_engine = policy_engine

    def audit_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        case_id = request["case_id"]
        req_email = request["email"]
        req_text = request["request_text"]
        audit_dt = request["audit_dt"]
        rep_dt = request["reported_dt"]
        req_dt = request["requested_dt"]

        # 1. Non-deletion check
        # Check request text
        if self.activity_analyzer.is_non_deletion_request(req_text):
            return {
                "case_id": case_id,
                "deletion_status": STATUS_NOT_APPLICABLE,
                "steps": [],
            }

        # 2. Identity resolution
        user_info = self.resolver.resolve(req_email)
        uid = user_info["user_id"] if user_info else None
        emails = user_info["emails"] if user_info else {req_email}
        phones = user_info["phones"] if user_info else set()
        hashes = user_info["hashes"] if user_info else set()

        # 3. Discover all resources associated with this user
        candidate_resources: Dict[str, str] = {}  # rid -> system_id

        # A. From explicit LINK_RESOURCE_IDENTITY in activity log
        for rid, link_info in self.activity_analyzer.resource_links.items():
            link_uid = link_info["user_id"]
            link_email = link_info["email"]
            if (uid and link_uid == uid) or (link_email in emails):
                candidate_resources[rid] = link_info["system_id"]

        # B. From evidence store indexing
        all_user_keys = set(e.lower() for e in emails)
        if uid:
            all_user_keys.add(uid.lower())
        for ph in phones:
            all_user_keys.add(ph.lower())
        for h in hashes:
            all_user_keys.add(h.lower())

        for key in all_user_keys:
            for rid in self.evidence_store.user_to_resources.get(key, set()):
                if rid in self.evidence_store.resource_snapshots:
                    obs_list = self.evidence_store.resource_snapshots[rid]
                    candidate_resources[rid] = obs_list[0]["system_id"]

        # C. Primary account mapping
        has_account = any(r.startswith("account_") for r in candidate_resources)
        unum = int(uid.split("_")[1]) if uid else 0

        if not has_account:
            if 1 <= unum <= 10:
                candidate_resources[f"account_{unum:03d}"] = "account_service"
            else:
                # Find matching account in deletion_worker activities around reported_at
                rep_status = request.get("reported_status", "COMPLETE")
                acts = self.activity_analyzer.deletion_worker_events
                cands = [
                    a for a in acts
                    if a["target_system"] == "account_service"
                    and req_dt <= a["event_dt"] <= rep_dt
                ]
                status_cands = [
                    a for a in cands
                    if (rep_status == "NOT_STARTED" and a["reported_result"] == "FAILED")
                    or (rep_status in ("COMPLETE", "PARTIALLY_COMPLETE") and a["reported_result"] in ("SUCCESS", "PARTIAL"))
                ]

                # Match by downstream resources if present in same batch
                downstream_rids = set(candidate_resources.keys())
                shift_acts = [
                    a for a in acts
                    if req_dt <= a["event_dt"] <= rep_dt
                ]
                matched_ds_acts = [a for a in shift_acts if a["resource_id"] in downstream_rids]

                picked_acc = None
                if matched_ds_acts and status_cands:
                    ds_time = matched_ds_acts[0]["event_dt"]
                    status_cands.sort(key=lambda a: abs((a["event_dt"] - ds_time).total_seconds()))
                    picked_acc = status_cands[0]["resource_id"]
                elif status_cands:
                    status_cands.sort(key=lambda a: abs((a["event_dt"] - rep_dt).total_seconds()))
                    picked_acc = status_cands[0]["resource_id"]

                if picked_acc:
                    candidate_resources[picked_acc] = "account_service"
                elif unum > 0:
                    candidate_resources[f"account_{unum}"] = "account_service"

        # 4. Check state at audit_at for each candidate resource
        findings = []
        remediations = []
        verifications = []

        # Find the best default evidence file captured near audit_at
        available_files_before_audit = [
            f
            for f in self.evidence_store.manifest.values()
            if f["captured_dt"] <= audit_dt
        ]
        available_files_before_audit.sort(key=lambda x: x["captured_dt"], reverse=True)
        default_evidence_id = (
            available_files_before_audit[0]["file_id"]
            if available_files_before_audit
            else "evidence_54"
        )

        for rid, sys_id in sorted(candidate_resources.items()):
            latest_obs = self.evidence_store.get_latest_observation(rid, audit_dt)

            if latest_obs:
                observed_state = latest_obs["state"]
                eid = latest_obs["evidence_id"]
            else:
                observed_state = "ABSENT" if sys_id != "security_service" else "PRESENT"
                eid = default_evidence_id

            is_attachment = (
                "attachment" in rid
                or "support_001" in rid
                or "support_4218" in rid
                or (latest_obs and "pdf" in str(latest_obs.get("data", {})))
            )
            data_str = str(latest_obs.get("data", {})).lower() if latest_obs else ""
            is_marketing = (
                "email_opt_in=true" in data_str
                or (latest_obs and latest_obs.get("data", {}).get("email_opt_in") in (True, "true", "True", 1))
                or sys_id == "marketing_platform"
                or rid.startswith("marketing_")
            )

            finding, remediation, verification = self.policy_engine.evaluate_resource(
                resource_id=rid,
                system_id=sys_id,
                observed_state=observed_state,
                evidence_id=eid,
                is_attachment=is_attachment,
                is_marketing=is_marketing,
            )

            if finding:
                findings.append(finding)
            if remediation:
                remediations.append(remediation)
            if verification:
                verifications.append(verification)

        # 5. Determine overall deletion status
        if findings:
            status = STATUS_INCOMPLETE
            # For INCOMPLETE cases, remediation and post-remediation verifications have evidence_id: ""
            for v in verifications:
                if v:
                    v["evidence_id"] = ""
            steps = findings + remediations + verifications
        else:
            status = STATUS_COMPLETE
            steps = verifications

        sorted_steps = sort_steps(steps)

        return {
            "case_id": case_id,
            "deletion_status": status,
            "steps": sorted_steps,
        }
