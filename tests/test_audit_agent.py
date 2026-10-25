"""Comprehensive Test Suite for Ghost Data Still Exists AI Deletion-Audit Agent.
Validates ingestion, identity resolution, evidence store, policy engine,
step ordering, strict validation, and public sample benchmarks.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
import pytest

from code.config import (
    ALLOWED_STATES,
    DATASET_DIR,
    OP_ORDER,
    PHASE_ORDER,
    STATUS_COMPLETE,
    STATUS_INCOMPLETE,
    STATUS_NOT_APPLICABLE,
)
from code.pipeline.activity_analysis import ActivityAnalyzer
from code.pipeline.evidence_retrieval import EvidenceStore
from code.pipeline.identity_resolution import IdentityResolver
from code.pipeline.ingestion import IngestionEngine, parse_iso
from code.pipeline.output_generator import serialize_steps, sort_steps
from code.pipeline.policy_engine import PolicyEngine
from code.pipeline.status_classifier import DeletionAuditAgent
from code.pipeline.validator import StrictValidator


@pytest.fixture(scope="session")
def dataset_path():
    return Path("dataset")


@pytest.fixture(scope="session")
def ingestion_engine(dataset_path):
    return IngestionEngine(dataset_path)


@pytest.fixture(scope="session")
def loaded_data(ingestion_engine):
    identities = ingestion_engine.load_user_identities()
    audit_log = ingestion_engine.load_user_audit_log()
    activities = ingestion_engine.load_system_activity()
    rules = ingestion_engine.load_deletion_rules()
    requests = ingestion_engine.load_deletion_requests("deletion_requests.csv")
    samples = ingestion_engine.load_deletion_requests("sample_deletion_requests.csv")
    return {
        "identities": identities,
        "audit_log": audit_log,
        "activities": activities,
        "rules": rules,
        "requests": requests,
        "samples": samples,
    }


@pytest.fixture(scope="session")
def initialized_agent(dataset_path, loaded_data):
    resolver = IdentityResolver(loaded_data["identities"], loaded_data["audit_log"])
    activity_analyzer = ActivityAnalyzer(loaded_data["activities"])
    evidence_store = EvidenceStore(dataset_path)
    policy_engine = PolicyEngine(loaded_data["rules"])
    agent = DeletionAuditAgent(
        resolver=resolver,
        activity_analyzer=activity_analyzer,
        evidence_store=evidence_store,
        policy_engine=policy_engine,
    )
    return {
        "resolver": resolver,
        "activity_analyzer": activity_analyzer,
        "evidence_store": evidence_store,
        "policy_engine": policy_engine,
        "agent": agent,
    }


# =====================================================================
# 1. Ingestion Tests
# =====================================================================

def test_ingestion_counts(loaded_data):
    """Verify exact dataset counts and schemas."""
    assert len(loaded_data["requests"]) == 518, "Must load exactly 518 full deletion requests"
    assert len(loaded_data["samples"]) == 32, "Must load exactly 32 sample requests"
    assert len(loaded_data["rules"]) == 15, "Must load 15 official deletion rules"
    assert len(loaded_data["identities"]) >= 800, "Identities must exceed 800 records"
    assert len(loaded_data["activities"]) >= 4000, "Activities must exceed 4000 records"


def test_iso_parsing():
    """Verify robust UTC ISO-8601 timestamp parsing."""
    dt = parse_iso("2026-09-15T12:00:00Z")
    assert dt.year == 2026 and dt.month == 9 and dt.day == 15 and dt.hour == 12
    assert dt.tzinfo is not None

    dt_offset = parse_iso("2026-09-15T14:00:00+02:00")
    assert dt_offset == dt  # Both represent the exact same UTC instant


# =====================================================================
# 2. Historical Identity Resolution Tests
# =====================================================================

def test_identity_resolution_known_user(initialized_agent):
    """Verify resolution of a user with historical identity changes."""
    resolver = initialized_agent["resolver"]
    # User 12 changed email from minjun.kim90@gmail.com to minjun.kim@gmail.com
    res1 = resolver.resolve("minjun.kim@gmail.com")
    res2 = resolver.resolve("minjun.kim90@gmail.com")

    assert res1 is not None
    assert res2 is not None
    assert res1["user_id"] == "user_12"
    assert res2["user_id"] == "user_12"
    assert "minjun.kim@gmail.com" in res1["emails"]
    assert "minjun.kim90@gmail.com" in res1["emails"]
    assert len(res1["hashes"]) >= 2, "Must include both current and historical SHA256 hashes"


def test_unknown_identity_resolution(initialized_agent):
    """Verify fallback when an email is not in user_identities.csv."""
    resolver = initialized_agent["resolver"]
    res = resolver.resolve("nonexistent_customer_xyz99@domain.org")
    assert res is None


# =====================================================================
# 3. Audit Cutoff Enforcement Tests
# =====================================================================

def test_cutoff_enforcement(initialized_agent):
    """Verify that evidence captured after audit_at is strictly excluded."""
    store = initialized_agent["evidence_store"]
    # Pick a resource with known observations over time
    rid = next(iter(store.resource_snapshots.keys()))
    cutoff_before = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    obs = store.get_latest_observation(rid, cutoff_before)
    assert obs is None, "Should observe nothing before 2025"

    cutoff_after = datetime(2027, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    obs_after = store.get_latest_observation(rid, cutoff_after)
    assert obs_after is not None, "Should observe resource at 2027 cutoff"


# =====================================================================
# 4. Activity Analysis & Non-Deletion Classification Tests
# =====================================================================

def test_non_deletion_classification(initialized_agent):
    """Verify that non-deletion requests (data export, marketing inquiry, etc.) are correctly identified."""
    analyzer = initialized_agent["activity_analyzer"]
    # Explicit non-deletion texts
    assert analyzer.is_non_deletion_request("Please download my account information; this is an information request, not a request to erase.")
    assert analyzer.is_non_deletion_request("Please send a copy of last year's invoices and leave the account active.")
    assert analyzer.is_non_deletion_request("Please stop the promotional emails but do not close the account.")

    # Genuine deletion texts
    assert not analyzer.is_non_deletion_request("Please close my account and permanently delete all personal data.")
    assert not analyzer.is_non_deletion_request("I want to exercise my right to erasure under GDPR.")


# =====================================================================
# 5. Policy Engine Tests
# =====================================================================

def test_policy_user_profile(initialized_agent):
    """Rule 01: USER_PROFILE must be DELETE."""
    engine = initialized_agent["policy_engine"]
    # When PRESENT -> Finding + Remediation + Verification
    finding, rem, ver = engine.evaluate_resource(
        resource_id="account_101",
        system_id="account_service",
        observed_state="PRESENT",
        evidence_id="evidence_01",
    )
    assert finding is not None
    assert finding["phase"] == "FINDING"
    assert finding["operation"] == "REPORT_REMAINING_RECORD"
    assert rem["operation"] == "DELETE_RECORD"
    assert ver["operation"] == "VERIFY_RECORD_ABSENT"

    # When ABSENT -> Only Verification
    f_none, r_none, ver_abs = engine.evaluate_resource(
        resource_id="account_101",
        system_id="account_service",
        observed_state="ABSENT",
        evidence_id="evidence_01",
    )
    assert f_none is None
    assert r_none is None
    assert ver_abs["operation"] == "VERIFY_RECORD_ABSENT"
    assert ver_abs["evidence_id"] == "evidence_01"


def test_policy_audit_record(initialized_agent):
    """Rule 12: SECURITY_AUDIT_LOG must be RETAIN."""
    engine = initialized_agent["policy_engine"]
    f, r, v = engine.evaluate_resource(
        resource_id="audit_record_500",
        system_id="security_service",
        observed_state="PRESENT",
        evidence_id="evidence_01",
    )
    assert f is None, "Retained audit records should not generate findings"
    assert r is None
    assert v["operation"] == "VERIFY_RECORD_PRESENT"
    assert v["state"] == "PRESENT"


def test_policy_marketing_profile(initialized_agent):
    """Rule 10: MARKETING_PROFILE must be DELETE."""
    engine = initialized_agent["policy_engine"]
    f, r, v = engine.evaluate_resource(
        resource_id="analytics_9914",
        system_id="analytics_platform",
        observed_state="PRESENT",
        evidence_id="evidence_01",
        is_marketing=True,
    )
    assert f is not None
    assert f["operation"] == "REPORT_REMAINING_RECORD"
    assert r["operation"] == "DELETE_RECORD"
    assert v["operation"] == "VERIFY_RECORD_ABSENT"


# =====================================================================
# 6. Step Ordering and Serialization Tests
# =====================================================================

def test_step_ordering():
    """Verify canonical sorting: FINDING -> REMEDIATION -> VERIFICATION,
    then operation order, system_id, resource_id, and 1-indexed numbering.
    """
    raw_steps = [
        {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "account_service", "resource_id": "account_002", "state": "ABSENT", "evidence_id": ""},
        {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "search_service", "resource_id": "search_001", "state": "PRESENT", "evidence_id": "evidence_01"},
        {"phase": "REMEDIATION", "operation": "DELETE_RECORD", "system_id": "search_service", "resource_id": "search_001", "state": "ABSENT", "evidence_id": ""},
        {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "account_service", "resource_id": "account_001", "state": "PRESENT", "evidence_id": "evidence_01"},
    ]

    sorted_res = sort_steps(raw_steps)
    assert sorted_res[0]["step_no"] == 1
    assert sorted_res[0]["phase"] == "FINDING"
    assert sorted_res[0]["system_id"] == "account_service"
    assert sorted_res[1]["phase"] == "FINDING"
    assert sorted_res[1]["system_id"] == "search_service"
    assert sorted_res[2]["phase"] == "REMEDIATION"
    assert sorted_res[3]["phase"] == "VERIFICATION"
    assert [s["step_no"] for s in sorted_res] == [1, 2, 3, 4]


def test_json_serialization():
    """Verify steps_json serialization uses standard JSON format."""
    steps = [
        {"step_no": 1, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_001", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"}
    ]
    serialized = serialize_steps(steps)
    assert isinstance(serialized, str)
    deserialized = json.loads(serialized)
    assert deserialized == steps


# =====================================================================
# 7. Sample Dataset Benchmark Tests (100% Status Accuracy)
# =====================================================================

def test_sample_benchmark_status_accuracy(initialized_agent, loaded_data):
    """Verify 100% status match across all 32 public reference cases."""
    agent = initialized_agent["agent"]
    sample_output = {
        r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
        for r in csv.DictReader(open("dataset/sample_output.csv"))
    }

    correct_status = 0
    total = len(loaded_data["samples"])
    for req in loaded_data["samples"]:
        cid = req["case_id"]
        res = agent.audit_request(req)
        exp_status, _ = sample_output[cid]
        if res["deletion_status"] == exp_status:
            correct_status += 1

    accuracy = correct_status / total
    assert accuracy == 1.0, f"Sample status accuracy must be 100% (32/32), got {correct_status}/{total}"


# =====================================================================
# 8. Strict Validator Compliance Tests
# =====================================================================

def test_strict_validator_passes():
    """Verify that output.csv generated by the agent strictly passes all validation rules."""
    output_path = Path("output.csv")
    assert output_path.exists(), "output.csv must exist at repository root"
    requests = list(csv.DictReader(open("dataset/deletion_requests.csv")))
    expected_ids = [r["case_id"] for r in requests]

    validator = StrictValidator(output_path, expected_case_ids=expected_ids)
    is_valid, errors, warnings = validator.validate()

    assert is_valid, f"StrictValidator failed with errors: {errors}"
    assert len(errors) == 0
