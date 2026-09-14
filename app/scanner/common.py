"""
Common utilities for scanner result formatting.
Provides a helper to wrap scanner output into the standardized result schema.
"""

from typing import Dict, Any


def format_check(base: Dict[str, Any], scanner_id: str, category: str) -> Dict[str, Any]:
    """Wrap a scanner's base result dict into the standardized schema.

    The project expects each scanner result to contain the following keys:
        id, name, category, status, score, max_score, summary, details,
        why_it_matters, recommendation, evidence

    ``base`` may already include some of these keys; missing ones are filled
    with sensible defaults.
    """
    result = {
        "id": scanner_id,
        "name": base.get("name", scanner_id.title()),
        "category": category,
        "status": base.get("status", "UNKNOWN"),
        "score": base.get("score", 0),
        "max_score": base.get("max_score", 10),
        "summary": base.get("summary", ""),
        "details": base.get("details", {}),
        "why_it_matters": base.get("why_it_matters", ""),
        "recommendation": base.get("recommendation", ""),
        "evidence": base.get("evidence", []),
    }
    return result
