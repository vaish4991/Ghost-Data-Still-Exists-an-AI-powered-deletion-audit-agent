"""Historical Identity Resolution module.
Resolves stable user IDs and all historical identifiers (emails, phones, hashes, names)
across current identity snapshots and audit logs.
"""

from typing import Any, Dict, List, Optional, Set
from code.pipeline.ingestion import normalize_email, normalize_phone, normalize_hash


class IdentityResolver:
    def __init__(self, user_identities: List[Dict[str, Any]], user_audit_log: List[Dict[str, Any]]):
        self.users_by_id: Dict[str, Dict[str, Any]] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.phone_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
        self._build_identity_graph(user_identities, user_audit_log)

    def _build_identity_graph(self, user_identities: List[Dict[str, Any]], user_audit_log: List[Dict[str, Any]]):
        # 1. Base snapshot from user_identities
        for u in user_identities:
            uid = u["user_id"]
            email = u["email"]
            phone = u["phone"]
            ehash = u["email_hash"]
            name = u["name"]

            self.users_by_id[uid] = {
                "user_id": uid,
                "current_name": name,
                "current_email": email,
                "current_phone": phone,
                "current_hash": ehash,
                "names": {name} if name else set(),
                "emails": {email} if email else set(),
                "phones": {phone} if phone else set(),
                "hashes": {ehash} if ehash else set(),
            }

            if email:
                self.email_to_uid[email] = uid
            if phone:
                self.phone_to_uid[phone] = uid
            if ehash:
                self.hash_to_uid[ehash] = uid

        # 2. Historical changes from user_audit_log
        for a in user_audit_log:
            uid = a["user_id"]
            if uid not in self.users_by_id:
                self.users_by_id[uid] = {
                    "user_id": uid,
                    "current_name": "",
                    "current_email": "",
                    "current_phone": "",
                    "current_hash": "",
                    "names": set(),
                    "emails": set(),
                    "phones": set(),
                    "hashes": set(),
                }

            field = a["field_name"]
            old_val = a["old_value"]
            new_val = a["new_value"]

            if field == "email":
                if old_val:
                    self.users_by_id[uid]["emails"].add(old_val)
                    self.email_to_uid[old_val] = uid
                if new_val:
                    self.users_by_id[uid]["emails"].add(new_val)
                    self.email_to_uid[new_val] = uid
            elif field == "phone":
                if old_val:
                    self.users_by_id[uid]["phones"].add(old_val)
                    self.phone_to_uid[old_val] = uid
                if new_val:
                    self.users_by_id[uid]["phones"].add(new_val)
                    self.phone_to_uid[new_val] = uid
            elif field == "email_hash":
                if old_val:
                    self.users_by_id[uid]["hashes"].add(old_val)
                    self.hash_to_uid[old_val] = uid
                if new_val:
                    self.users_by_id[uid]["hashes"].add(new_val)
                    self.hash_to_uid[new_val] = uid

    def resolve(self, email_or_id: str) -> Optional[Dict[str, Any]]:
        """Resolve a query string (email or user_id) to the canonical user profile."""
        norm_key = normalize_email(email_or_id)
        if norm_key in self.email_to_uid:
            uid = self.email_to_uid[norm_key]
            return self.users_by_id.get(uid)

        # Check direct user_id
        if email_or_id in self.users_by_id:
            return self.users_by_id[email_or_id]

        return None

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        return self.users_by_id.get(user_id)
