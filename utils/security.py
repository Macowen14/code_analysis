import os
import re
import pathlib
import structlog
from typing import List
from datetime import datetime

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)


class SecurityError(Exception):
    pass


def sandboxed_path(original_path: str, target_dir: str) -> pathlib.Path:
    """Resolve path with security constraints to prevent path traversal."""
    resolved = pathlib.Path(original_path).resolve()
    target_resolved = pathlib.Path(target_dir).resolve(
        strict=True
    )  # Strictly check if the target exist

    # Prevent directory traversal
    if ".." in original_path:
        raise SecurityError("Path traversal detected")

    # Restrict to allowed directory (target_dir)
    if not str(resolved).startswith(str(target_resolved)):
        raise SecurityError(
            f"Path `{resolved}` is outside the allowed sandbox `{target_resolved}`"
        )

    # Check symlink depth
    if pathlib.Path(original_path).is_symlink():
        if pathlib.Path(original_path).readlink().is_absolute():
            raise SecurityError("Absolute symlink not allowed")

    return resolved


class SecurityLogger:
    def __init__(self):
        self.logger = structlog.get_logger()

    def log_file_access(self, path: str, mode: str):
        try:
            size = os.path.getsize(path) if os.path.exists(path) else 0
        except Exception:
            size = 0

        self.logger.info("file_access", action=f"file_{mode}", resource=path, size=size)

    def log_search_query(self, query: str):
        self.logger.info(
            "search_query", action="external_search", query_length=len(query)
        )

    def log_security_event(self, action: str, details: str):
        self.logger.warning("security_event", action=action, details=details)


class BehavioralMonitor:
    def __init__(self):
        self.sensitive_patterns = [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"-----BEGIN PRIVATE KEY-----",  # Private keys
            r'(?i)api_key[\s:=]+[\'"]?([a-zA-Z0-9_\-]+)[\'"]?',  # API Key
            r'(?i)password[\s:=]+[\'"]?([^\'"\s]+)[\'"]?',  # general passwords
        ]
        self.logger = SecurityLogger()

    def analyze_llm_interaction(self, prompt: str) -> bool:
        """Detect prompt injectionAttempts."""
        if "ignore previous" in prompt.lower() or "system prompt" in prompt.lower():
            self.logger.log_security_event(
                "prompt_injection_attempt", "Detected suspicious prompt override"
            )
            return True
        return False

    def redact_sensitive_data(self, text: str) -> str:
        """Redact sensitive data from text."""
        if not text:
            return ""
        redacted_text = text
        for pattern in self.sensitive_patterns:
            redacted_text = re.sub(pattern, "[REDACTED]", redacted_text)

        if redacted_text != text:
            self.logger.log_security_event(
                "data_redaction", "Sensitive data was redacted from output"
            )

        return redacted_text
