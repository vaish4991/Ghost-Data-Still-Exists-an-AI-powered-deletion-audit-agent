#!/usr/bin/env python3
"""Main entry point for Ghost Data Still Exists AI Deletion-Audit Agent.
Usage:
    python3 code/main.py [options]
"""

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from code.config import (
    DATASET_DIR,
    DEFAULT_OUTPUT_CSV,
    STATUS_COMPLETE,
    STATUS_INCOMPLETE,
    STATUS_NOT_APPLICABLE,
)
from code.pipeline.activity_analysis import ActivityAnalyzer
from code.pipeline.evidence_retrieval import EvidenceStore
from code.pipeline.identity_resolution import IdentityResolver
from code.pipeline.ingestion import IngestionEngine
from code.pipeline.output_generator import write_output_csv
from code.pipeline.policy_engine import PolicyEngine
from code.pipeline.status_classifier import DeletionAuditAgent
from code.pipeline.validator import StrictValidator


def parse_args():
    parser = argparse.ArgumentParser(
        description="Ghost Data Still Exists: AI Deletion Audit Agent"
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DATASET_DIR,
        help="Path to directory containing dataset files (default: dataset/)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_CSV,
        help="Path to write the final output CSV (default: output.csv)",
    )
    parser.add_argument(
        "--requests-file",
        type=str,
        default="deletion_requests.csv",
        help="Name of requests file to audit (default: deletion_requests.csv)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate an existing output.csv without rerunning the agent",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    output_path = args.output.resolve()
    dataset_dir = args.dataset_dir.resolve()

    print("=================================================================")
    print("  Ghost Data Still Exists: AI Deletion Audit Agent")
    print("  HackerRank Orchestrate October 2026")
    print("=================================================================")
    print(f"Dataset directory: {dataset_dir}")
    print(f"Output path:       {output_path}")
    print(f"Requests file:     {args.requests_file}")

    ingestion = IngestionEngine(dataset_dir)

    # If validate-only
    if args.validate_only:
        print(f"\n[VALIDATION ONLY] Validating {output_path}...")
        requests = ingestion.load_deletion_requests(args.requests_file)
        expected_ids = [r["case_id"] for r in requests]
        validator = StrictValidator(output_path, expected_case_ids=expected_ids)
        is_valid, errors, warnings = validator.validate()
        if is_valid:
            print(">>> VALIDATION PASSED! The output file strictly adheres to all challenge contracts.")
            sys.exit(0)
        else:
            print(f">>> VALIDATION FAILED with {len(errors)} error(s):")
            for err in errors[:20]:
                print(f"  - {err}")
            sys.exit(1)

    # 1. Ingestion
    print("\n[1/5] Ingesting challenge datasets and manifests...")
    requests = ingestion.load_deletion_requests(args.requests_file)
    print(f"Loaded {len(requests)} deletion requests from {args.requests_file}.")

    user_identities = ingestion.load_user_identities()
    print(f"Loaded {len(user_identities)} user identity records.")

    user_audit_log = ingestion.load_user_audit_log()
    print(f"Loaded {len(user_audit_log)} user audit log entries.")

    system_activity = ingestion.load_system_activity()
    print(f"Loaded {len(system_activity)} system activity events.")

    deletion_rules = ingestion.load_deletion_rules()
    print(f"Loaded {len(deletion_rules)} policy rules from deletion_rules.csv.")

    # 2. Build Identity Resolution Graph
    print("\n[2/5] Building historical identity graph...")
    resolver = IdentityResolver(user_identities, user_audit_log)
    print(f"Resolved {len(resolver.users_by_id)} unique historical customer identities.")

    # 3. Analyze Activity and Ingest Evidence
    print("\n[3/5] Indexing system activity and evidence files across all modalities...")
    activity_analyzer = ActivityAnalyzer(system_activity)
    evidence_store = EvidenceStore(dataset_dir)
    print(f"Indexed {len(evidence_store.manifest)} evidence files.")
    print(f"Observed {len(evidence_store.resource_snapshots)} unique resources across snapshots.")

    policy_engine = PolicyEngine(deletion_rules)
    agent = DeletionAuditAgent(
        resolver=resolver,
        activity_analyzer=activity_analyzer,
        evidence_store=evidence_store,
        policy_engine=policy_engine,
    )

    # 4. Process all requests
    print(f"\n[4/5] Auditing {len(requests)} cases with cutoff enforcement and policy validation...")
    results = []
    status_counts = Counter()

    for idx, req in enumerate(requests, start=1):
        outcome = agent.audit_request(req)
        results.append(outcome)
        status_counts[outcome["deletion_status"]] += 1
        if idx % 100 == 0 or idx == len(requests):
            print(f"  Processed {idx}/{len(requests)} cases...")

    print(f"\nAudit completed. Status breakdown:")
    for status, count in status_counts.items():
        print(f"  - {status}: {count} ({count/len(requests)*100:.1f}%)")

    # Format output records
    output_records = [
        {
            "case_id": r["case_id"],
            "deletion_status": r["deletion_status"],
            "steps_json": r["steps"],
        }
        for r in results
    ]

    # Write output.csv
    print(f"\n[5/5] Writing final predictions to {output_path}...")
    write_output_csv(output_records, output_path)
    print(f"Successfully wrote {len(output_records)} rows to {output_path}.")

    # 5. Independent Strict Validation
    print("\n[VALIDATION] Running independent strict validator...")
    expected_case_ids = [r["case_id"] for r in requests]
    validator = StrictValidator(output_path, expected_case_ids=expected_case_ids)
    is_valid, errors, warnings = validator.validate()

    if is_valid:
        print(">>> STRICT VALIDATION PASSED: 100% compliant with official challenge contract.")
    else:
        print(f">>> STRICT VALIDATION FAILED with {len(errors)} error(s):")
        for err in errors[:25]:
            print(f"  - {err}")
        sys.exit(1)

    print("\nWorkflow completed successfully!")


if __name__ == "__main__":
    main()
