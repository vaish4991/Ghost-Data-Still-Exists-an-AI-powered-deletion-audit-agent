"""Policy Engine module for Ghost Data Still Exists.
Applies deletion_rules.csv and determines findings, remediations, and verifications
for each discovered resource.
"""

from typing import Any, Dict, List, Optional, Tuple
from code.config import ALLOWED_STATES


class PolicyEngine:
    def __init__(self, rules: Dict[str, str]):
        self.rules = rules

    def evaluate_resource(
        self,
        resource_id: str,
        system_id: str,
        observed_state: str,
        evidence_id: str,
        is_attachment: bool = False,
        is_marketing: bool = False,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        """Evaluate a resource against policy.
        Returns (finding_step or None, remediation_step or None, verification_step).
        """
        finding = None
        remediation = None
        verification = None

        if is_marketing or system_id == "marketing_platform" or resource_id.startswith("marketing_"):
            if observed_state == "PRESENT":
                finding = {
                    "phase": "FINDING",
                    "operation": "REPORT_REMAINING_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "PRESENT",
                    "evidence_id": evidence_id,
                }
                remediation = {
                    "phase": "REMEDIATION",
                    "operation": "DELETE_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": "",
                }
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": "",
                }
            else:
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": evidence_id,
                }

        elif system_id == "account_service":
            if observed_state == "PRESENT":
                finding = {
                    "phase": "FINDING",
                    "operation": "REPORT_REMAINING_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "PRESENT",
                    "evidence_id": evidence_id,
                }
                remediation = {
                    "phase": "REMEDIATION",
                    "operation": "DELETE_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": "",
                }
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": "",
                }
            else:
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": evidence_id,
                }

        elif system_id == "search_service":
            if observed_state == "PRESENT":
                finding = {
                    "phase": "FINDING",
                    "operation": "REPORT_REMAINING_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "PRESENT",
                    "evidence_id": evidence_id,
                }
                remediation = {
                    "phase": "REMEDIATION",
                    "operation": "DELETE_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": "",
                }
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": "",
                }
            else:
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": evidence_id,
                }

        elif system_id == "analytics_platform":
            # Rule 07/08: Anonymize
            if observed_state == "PRESENT":
                # Exposed PII
                finding = {
                    "phase": "FINDING",
                    "operation": "REPORT_EXPOSED_PII",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "PRESENT",
                    "evidence_id": evidence_id,
                }
                remediation = {
                    "phase": "REMEDIATION",
                    "operation": "ANONYMIZE_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ANONYMIZED",
                    "evidence_id": "",
                }
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ANONYMIZED",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ANONYMIZED",
                    "evidence_id": "",
                }
            else:
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ANONYMIZED",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ANONYMIZED",
                    "evidence_id": evidence_id,
                }

        elif system_id == "support_platform":
            if is_attachment or "attachment" in resource_id:
                # Rule 06: Delete attachment
                if observed_state == "PRESENT":
                    finding = {
                        "phase": "FINDING",
                        "operation": "REPORT_REMAINING_RECORD",
                        "system_id": system_id,
                        "resource_id": resource_id,
                        "state": "PRESENT",
                        "evidence_id": evidence_id,
                    }
                    remediation = {
                        "phase": "REMEDIATION",
                        "operation": "DELETE_RECORD",
                        "system_id": system_id,
                        "resource_id": resource_id,
                        "state": "ABSENT",
                        "evidence_id": "",
                    }
                    verification = {
                        "phase": "VERIFICATION",
                        "operation": "VERIFY_RECORD_ABSENT",
                        "system_id": system_id,
                        "resource_id": resource_id,
                        "state": "ABSENT",
                        "evidence_id": "",
                    }
                else:
                    verification = {
                        "phase": "VERIFICATION",
                        "operation": "VERIFY_RECORD_ABSENT",
                        "system_id": system_id,
                        "resource_id": resource_id,
                        "state": "ABSENT",
                        "evidence_id": evidence_id,
                    }
            else:
                # Rule 05: Redact conversation
                if observed_state == "PRESENT":
                    finding = {
                        "phase": "FINDING",
                        "operation": "REPORT_EXPOSED_PII",
                        "system_id": system_id,
                        "resource_id": resource_id,
                        "state": "PRESENT",
                        "evidence_id": evidence_id,
                    }
                    remediation = {
                        "phase": "REMEDIATION",
                        "operation": "REDACT_RECORD",
                        "system_id": system_id,
                        "resource_id": resource_id,
                        "state": "REDACTED",
                        "evidence_id": "",
                    }
                    verification = {
                        "phase": "VERIFICATION",
                        "operation": "VERIFY_RECORD_REDACTED",
                        "system_id": system_id,
                        "resource_id": resource_id,
                        "state": "REDACTED",
                        "evidence_id": "",
                    }
                else:
                    verification = {
                        "phase": "VERIFICATION",
                        "operation": "VERIFY_RECORD_REDACTED",
                        "system_id": system_id,
                        "resource_id": resource_id,
                        "state": "REDACTED",
                        "evidence_id": evidence_id,
                    }

        elif system_id == "integration_service":
            if observed_state == "ACTIVE":
                finding = {
                    "phase": "FINDING",
                    "operation": "REPORT_ACTIVE_DATA_FLOW",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ACTIVE",
                    "evidence_id": evidence_id,
                }
                remediation = {
                    "phase": "REMEDIATION",
                    "operation": "DISABLE_DATA_FLOW",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "DISABLED",
                    "evidence_id": "",
                }
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_DATA_FLOW_DISABLED",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "DISABLED",
                    "evidence_id": "",
                }
            else:
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_DATA_FLOW_DISABLED",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "DISABLED",
                    "evidence_id": evidence_id,
                }

        elif system_id == "backup_service":
            if observed_state == "ACTIVE":
                finding = {
                    "phase": "FINDING",
                    "operation": "REPORT_RESTORE_RISK",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ACTIVE",
                    "evidence_id": evidence_id,
                }
                remediation = {
                    "phase": "REMEDIATION",
                    "operation": "BLOCK_RESTORE",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "BLOCKED",
                    "evidence_id": "",
                }
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RESTORE_BLOCKED",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "BLOCKED",
                    "evidence_id": "",
                }
            else:
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RESTORE_BLOCKED",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "BLOCKED",
                    "evidence_id": evidence_id,
                }

        elif system_id == "identity_service":
            # Rule 15: Account tombstone -> REDACT direct PII
            if observed_state == "PRESENT":
                finding = {
                    "phase": "FINDING",
                    "operation": "REPORT_EXPOSED_PII",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "PRESENT",
                    "evidence_id": evidence_id,
                }
                remediation = {
                    "phase": "REMEDIATION",
                    "operation": "REDACT_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "REDACTED",
                    "evidence_id": "",
                }
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_REDACTED",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "REDACTED",
                    "evidence_id": "",
                }
            else:
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_REDACTED",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "REDACTED",
                    "evidence_id": evidence_id,
                }

        elif system_id == "export_service":
            # Rule 09: Delete export
            if observed_state == "PRESENT":
                finding = {
                    "phase": "FINDING",
                    "operation": "REPORT_REMAINING_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "PRESENT",
                    "evidence_id": evidence_id,
                }
                remediation = {
                    "phase": "REMEDIATION",
                    "operation": "DELETE_RECORD",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": "",
                }
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": "",
                }
            else:
                verification = {
                    "phase": "VERIFICATION",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "state": "ABSENT",
                    "evidence_id": evidence_id,
                }

        elif system_id == "security_service":
            # Rule 12: Retain audit log
            verification = {
                "phase": "VERIFICATION",
                "operation": "VERIFY_RECORD_PRESENT",
                "system_id": system_id,
                "resource_id": resource_id,
                "state": "PRESENT",
                "evidence_id": evidence_id,
            }

        return finding, remediation, verification
