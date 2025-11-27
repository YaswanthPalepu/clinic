# Standard library imports
import logging
import os
import re
from typing import Any, Dict

# Third party imports
import psutil

logger = logging.getLogger(__name__)


def get_system_metrics() -> Dict[str, Any]:
    """Get system performance metrics"""
    try:
        memory = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=1)
        disk = psutil.disk_usage("/")

        return {
            "memory_mb": memory.used / (1024 * 1024),
            "memory_percent": memory.percent,
            "cpu_percent": cpu_percent,
            "disk_percent": (disk.used / disk.total) * 100,
        }
    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        return {
            "memory_mb": 0,
            "memory_percent": 0,
            "cpu_percent": 0,
            "disk_percent": 0,
        }


def sanitize_clinical_text(text: str) -> str:
    """Sanitize clinical text for security"""
    if not text or not isinstance(text, str):
        return ""

    sanitized = re.sub(r"\s+", " ", text.strip())

    # Mask sensitive data
    sanitized = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]", sanitized)
    sanitized = re.sub(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "[PHONE]", sanitized)
    sanitized = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "[EMAIL]",
        sanitized,
    )
    sanitized = re.sub(r"\b\d{6,}\b", "[ID]", sanitized)

    max_length = int(os.getenv("MAX_SENTENCE_LENGTH", "1000"))
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized


def apply_hybrid_pipeline(predictions: list, sentences: list) -> list:
    """
    Apply rule-based post-processing to model predictions for hybrid classification.

    Args:
        predictions: List of model prediction dicts with 'label' and 'score'
        sentences: List of corresponding input sentences

    Returns:
        List of enhanced predictions with 'label', 'model_label', 'score', and 'rule_applied'
    """
    results = []
    conditional_triggers = re.compile(
        r"\b(if|should|in case|unless|when)\b", re.IGNORECASE
    )

    for pred, sentence in zip(predictions, sentences):
        model_label = pred["label"]
        final_label = model_label
        rule_applied = None

        # Rule 1: Detect conditional phrasing and override
        if conditional_triggers.search(sentence):
            final_label = "CONDITIONAL"
            rule_applied = "conditional_trigger"

        # Rule 2: Strengthen POSSIBLE detection for uncertainty words
        elif any(
            word in sentence.lower()
            for word in [
                "may",
                "might",
                "could",
                "possibly",
                "likely",
                "probable",
                "probably",
                "appears to",
                "suggests",
                "suspect",
                "potential",
                "possible",
            ]
        ):
            if model_label == "PRESENT":
                final_label = "POSSIBLE"
                rule_applied = "uncertainty_strengthening"

        results.append(
            {
                "label": final_label,
                "model_label": model_label,
                "score": pred["score"],
                "rule_applied": rule_applied,
            }
        )

    return results


def detect_conditional_phrases(sentence: str) -> bool:
    """Check if sentence contains conditional trigger words."""
    conditional_triggers = re.compile(
        r"\b(if|should|in case|unless|when)\b", re.IGNORECASE
    )
    return bool(conditional_triggers.search(sentence))


def detect_uncertainty_phrases(sentence: str) -> bool:
    """Check if sentence contains uncertainty words that might indicate possibility."""
    uncertainty_words = [
        "may",
        "might",
        "could",
        "possibly",
        "likely",
        "probable",
        "probably",
        "appears to",
        "suggests",
        "suspect",
        "potential",
        "possible",
    ]
    return any(word in sentence.lower() for word in uncertainty_words)
