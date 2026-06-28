"""Security audit logging helpers for TrustVault."""

import json
import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict

from config import constants


def log_security_event(event_type: str, user: str = "system", description: str = "",
                       severity: str = "INFO", **details: Any) -> bool:
    """Append a security-sensitive event to the JSON audit log."""
    event: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "user": user or "unknown",
        "ip_address": details.pop("ip_address", socket.gethostbyname(socket.gethostname())),
        "description": description,
        "severity": severity,
        "details": details,
    }

    try:
        audit_file = constants.AUDIT_LOG_FILE
        os.makedirs(os.path.dirname(os.path.abspath(audit_file)), exist_ok=True)
        logs = []
        if os.path.exists(audit_file) and os.path.getsize(audit_file) > 0:
            try:
                with open(audit_file, "r", encoding="utf-8-sig") as f:
                    loaded = json.load(f)
                if isinstance(loaded, list):
                    logs = loaded
            except (OSError, json.JSONDecodeError):
                logs = []

        logs.append(event)
        if len(logs) > 5000:
            logs = logs[-5000:]

        temp_path = audit_file + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, default=str)
        os.replace(temp_path, audit_file)
        return True
    except Exception as exc:
        print(f"Audit log write failed: {exc}")
        return False
