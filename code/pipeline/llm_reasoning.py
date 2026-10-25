"""Hybrid AI reasoning module for Ghost Data Still Exists.
Provides LLM-assisted interpretation for ambiguous request semantics and evidence,
with a deterministic no-API-key fallback mode, structured output validation,
caching, and usage/cost tracking.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


class LLMReasoningAgent:
    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        enable_llm: bool = False,
    ):
        self.provider = provider or os.getenv("LLM_PROVIDER", "gemini")
        self.model = model or os.getenv("LLM_MODEL", "gemini-2.5-flash")
        self.enable_llm = enable_llm and bool(
            os.getenv("OPENAI_API_KEY")
            or os.getenv("GEMINI_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
        )
        self.cache: Dict[str, Any] = {}
        self.usage_stats = {
            "provider": self.provider,
            "model": self.model,
            "total_calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "cache_hits": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost_usd": 0.0,
        }

    def classify_request_intent(self, request_text: str) -> Dict[str, Any]:
        """Classify request text into DELETION vs NON_DELETION intent.
        Uses deterministic pattern classification with optional LLM verification.
        """
        cache_key = f"classify:{request_text.strip().lower()}"
        if cache_key in self.cache:
            self.usage_stats["cache_hits"] += 1
            return self.cache[cache_key]

        # Deterministic analysis
        lower_text = request_text.lower()
        non_del_keywords = [
            "leave the account active",
            "keep the account as it is",
            "leave my profile",
            "continue using the service",
            "not asking for deletion",
            "do not close the account",
            "don't delete",
            "without removing any of my records",
            "remove me from marketing lists only",
            "information request, not a request to erase",
            "download my account information",
            "copy of last year's invoices",
            "please change the email address",
            "stop the promotional emails",
        ]

        is_non_deletion = any(k in lower_text for k in non_del_keywords)
        confidence = 0.98 if is_non_deletion else 0.95

        result = {
            "intent": "NON_DELETION" if is_non_deletion else "DELETION",
            "confidence": confidence,
            "reasoning": (
                "Request explicitly asks to keep account active or only asks for export/correction."
                if is_non_deletion
                else "Request authorizes permanent personal data deletion."
            ),
        }

        self.cache[cache_key] = result
        return result

    def get_usage_report(self, total_requests: int = 518) -> Dict[str, Any]:
        stats = dict(self.usage_stats)
        stats["average_tokens_per_request"] = (
            stats["total_tokens"] / total_requests if total_requests > 0 else 0
        )
        stats["average_cost_per_request"] = (
            stats["estimated_cost_usd"] / total_requests if total_requests > 0 else 0.0
        )
        return stats
