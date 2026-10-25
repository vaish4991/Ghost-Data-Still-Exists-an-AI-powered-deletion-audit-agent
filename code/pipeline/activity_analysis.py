"""Activity Analysis module for Ghost Data Still Exists.
Analyzes system_activity.csv to identify non-deletion requests, explicit identity-resource
links, deletion-worker operational batches, and data-flow sync/restore events.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from code.pipeline.ingestion import normalize_email, parse_iso


class ActivityAnalyzer:
    def __init__(self, activities: List[Dict[str, Any]]):
        self.activities = activities
        self.non_deletion_accounts: Set[str] = set()
        self.resource_links: Dict[str, Dict[str, str]] = {}
        self.deletion_worker_events: List[Dict[str, Any]] = []
        self._analyze_activities()

    def _analyze_activities(self):
        for a in self.activities:
            event_type = a["event_type"]
            details = a["details"]
            rid = a["resource_id"]

            if event_type == "CLASSIFY_REQUEST":
                if "non-deletion" in details or "no destructive action was authorized" in details:
                    self.non_deletion_accounts.add(rid)

            elif event_type == "LINK_RESOURCE_IDENTITY":
                # e.g. Data catalog linked search_428 (search_428) to g.silva76@gmail.com and user_13.
                # Extract email and user_id
                email_match = None
                user_match = None
                for token in details.replace(";", " ").replace(",", " ").split():
                    if "@" in token:
                        email_match = normalize_email(token)
                    elif token.startswith("user_"):
                        user_match = token.rstrip(".").rstrip(",")

                self.resource_links[rid] = {
                    "resource_id": rid,
                    "system_id": a["target_system"],
                    "email": email_match or "",
                    "user_id": user_match or "",
                    "details": details,
                }

            if a["source_system"] == "deletion_worker":
                self.deletion_worker_events.append(a)

    def is_non_deletion_request(self, request_text: str, account_id: Optional[str] = None) -> bool:
        """Check whether request text or classification indicates a non-deletion request."""
        if account_id and account_id in self.non_deletion_accounts:
            return True

        text = request_text.lower()

        non_del_phrases = [
            "leave the account active",
            "keep the account as it is",
            "leave my profile",
            "leave my purchase history",
            "continue using the service",
            "not asking for deletion",
            "do not close the account",
            "don't delete or change anything",
            "without removing any of my records",
            "remove me from marketing lists only",
            "information request, not a request to erase",
            "download my account information",
            "copy of last year's invoices",
            "please change the email address",
            "stop the promotional emails",
            "replace it with the new one and leave the account",
        ]

        for phrase in non_del_phrases:
            if phrase in text:
                return True

        return False


    def find_deletion_worker_batch(
        self, reported_dt: datetime, requested_dt: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Find deletion_worker activities associated with a request's reported execution."""
        batch = []
        for a in self.deletion_worker_events:
            diff = (reported_dt - a["event_dt"]).total_seconds()
            # Deletion operations run typically 0 to 2 hours before reported_at
            if -1800 <= diff <= 7200:
                batch.append((abs(diff), a))

        batch.sort(key=lambda x: x[0])
        return [item[1] for item in batch]
