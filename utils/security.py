import os
import re
import sys
import socket
import ipaddress
import builtins
import inspect
import pathlib
import structlog
import statistics
from typing import List, Dict
from datetime import datetime
from collections import deque
from enum import Enum

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


class SecurityEvent(Enum):
    DNS_REBINDING = "dns_rebinding"
    PACKAGE_TAMPER = "package_tamper"
    PROMPT_INJECTION = "prompt_injection"
    NETWORK_ANOMALY = "network_anomaly"
    DEPENDENCY_ALERT = "dependency_alert"
    FILE_READ_ERROR = "file_read_error"
    FILE_WRITE_ERROR = "file_write_error"
    PREFLIGHT_ERROR = "preflight_error"
    PREFLIGHT_FAILED = "preflight_failed"
    LLM_ERROR = "llm_error"
    DATA_REDACTION = "data_redaction"
    RESTRICTED_IMPORT = "restricted_import"


def validate_local_hostname(hostname: str) -> bool:
    """Ensure hostname resolves to local/private IP only to prevent DNS rebinding."""
    try:
        ips = socket.getaddrinfo(hostname, None)
        for _, _, _, _, (ip, _) in ips:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private and not ip_obj.is_loopback:
                return False
        return True
    except:
        return False


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
        self.alert_thresholds = {
            SecurityEvent.DNS_REBINDING: 1,
            SecurityEvent.PACKAGE_TAMPER: 1,
            SecurityEvent.PROMPT_INJECTION: 3,
            SecurityEvent.RESTRICTED_IMPORT: 1,
        }
        self.event_counts = {event: 0 for event in SecurityEvent}

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

    def log_event(self, event: SecurityEvent, details: str, severity: str = "MEDIUM"):
        """Log security event with structured data and thresholding."""
        self.event_counts[event] += 1

        if self.event_counts[event] >= self.alert_thresholds.get(event, 5):
            severity = "CRITICAL"
            self._trigger_alert(event, details)

        self.logger.warning(
            "security_event",
            security_event=event.value,
            severity=severity,
            details=details,
            count=self.event_counts[event],
            pid=os.getpid(),
        )

    def _trigger_alert(self, event: SecurityEvent, details: str):
        """Mock alert transmission (e.g. SIEM/Syslog)."""
        # In a real system, this would push to Slack/PagerDuty or a SIEM.
        self.logger.error(
            "security_alert_triggered",
            event=event.value,
            details=details,
            action="IMMEDIATE_INVESTIGATION_REQUIRED",
        )

    def log_security_event(self, action: str, details: str):
        """Backwards compatibility for previous usages."""
        self.logger.warning("security_event", action=action, details=details)


class BehavioralMonitor:
    def __init__(self, logger: SecurityLogger):
        self.sensitive_patterns = [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"-----BEGIN PRIVATE KEY-----",  # Private keys
            r'(?i)api_key[\s:=]+[\'"]?([a-zA-Z0-9_\-]+)[\'"]?',  # API Key
            r'(?i)password[\s:=]+[\'"]?([^\'"\s]+)[\'"]?',  # general passwords
        ]
        self.logger = logger

    def redact_sensitive_data(self, text: str) -> str:
        """Redact sensitive data from text."""
        if not text:
            return ""
        redacted_text = text
        for pattern in self.sensitive_patterns:
            redacted_text = re.sub(pattern, "[REDACTED]", redacted_text)

        if redacted_text != text:
            self.logger.log_event(
                SecurityEvent.DATA_REDACTION, "Sensitive data was redacted from output"
            )

        return redacted_text


class PromptValidator:
    def __init__(self, logger: SecurityLogger):
        self.injection_patterns = [
            r"(?i)\bignore\b.*\bprevious\b.*\binstructions\b",
            r"(?i)\bdisregard\b.*\babove\b",
        ]
        self.max_prompt_length = 200000
        self.disallowed_tokens = ["<|endoftext|>", "<|im_start|>", "<|im_end|>"]
        self.logger = logger

    def validate(self, prompt: str) -> bool:
        if len(prompt) > self.max_prompt_length:
            return False

        for pattern in self.injection_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                self.logger.log_event(
                    SecurityEvent.PROMPT_INJECTION,
                    f"Matched injection pattern: {pattern}",
                )
                return False

        for token in self.disallowed_tokens:
            if token in prompt:
                self.logger.log_event(
                    SecurityEvent.PROMPT_INJECTION, "Disallowed control token found"
                )
                return False

        return True


class AnomalyDetector:
    def __init__(self, logger: SecurityLogger, window_size: int = 100):
        self.llm_requests = deque(maxlen=window_size)
        self.logger = logger

    def detect_llm_anomaly(self, prompt: str, dt_now: datetime) -> bool:
        """Detect anomalous LLM request behavior like rapid-fire DoS targeting."""
        self.llm_requests.append(dt_now)
        recent_requests = [r for r in self.llm_requests if (dt_now - r).seconds < 10]

        if len(recent_requests) > 20:
            self.logger.log_event(
                SecurityEvent.NETWORK_ANOMALY, "LLM Rapid Fire / DoS detected"
            )
            return True

        return False


class DependencyMonitor:
    def __init__(self, logger: SecurityLogger):
        self.import_watchlist = ["subprocess", "socket", "ctypes"]
        self.logger = logger

    def monitor_imports(self):
        """Hooks Python's import system to flag dangerous imports at runtime."""
        original_import = builtins.__import__

        def secured_import(name, *args, **kwargs):
            if name in self.import_watchlist:
                # Capture caller
                caller = inspect.stack()[1]
                caller_module = caller.frame.f_globals.get("__name__", "unknown")

                # Allow core python modules that use these naturally like 'os', but log explicit usages
                if not caller_module.startswith(
                    ("urllib", "http", "asyncio", "langchain", "langgraph")
                ):
                    self.logger.log_event(
                        SecurityEvent.RESTRICTED_IMPORT,
                        f"Restricted import attempt: {name} by {caller_module}",
                    )

            return original_import(name, *args, **kwargs)

        builtins.__import__ = secured_import
