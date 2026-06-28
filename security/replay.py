"""Timestamp and nonce replay protection for TrustVault messages."""

import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from security.audit import log_security_event

NONCE_FILE = os.path.join("data", "nonce_cache.json")
DEFAULT_MAX_AGE_SECONDS = 300


def new_nonce() -> str:
    return secrets.token_urlsafe(24)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_cache() -> Dict[str, str]:
    if not os.path.exists(NONCE_FILE) or os.path.getsize(NONCE_FILE) == 0:
        return {}
    try:
        with open(NONCE_FILE, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: Dict[str, str]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(NONCE_FILE)), exist_ok=True)
    temp_path = NONCE_FILE + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)
    os.replace(temp_path, NONCE_FILE)


def check_and_store_nonce(nonce: str, timestamp: str, context: str,
                          max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS) -> Tuple[bool, str]:
    """Reject missing, expired, future, or previously used nonce/timestamp pairs."""
    if not nonce:
        log_security_event("REPLAY_REJECTED", description=f"Missing nonce for {context}", severity="WARNING")
        return False, "Missing replay nonce."
    if not timestamp:
        log_security_event("REPLAY_REJECTED", description=f"Missing timestamp for {context}", severity="WARNING")
        return False, "Missing replay timestamp."

    try:
        message_time = _parse_ts(timestamp)
    except ValueError:
        log_security_event("REPLAY_REJECTED", description=f"Invalid timestamp for {context}", severity="WARNING")
        return False, "Invalid replay timestamp."

    now = datetime.now(timezone.utc)
    age = now - message_time
    if age > timedelta(seconds=max_age_seconds):
        log_security_event("REPLAY_REJECTED", description=f"Expired timestamp for {context}", severity="WARNING")
        return False, "Replay timestamp has expired."
    if message_time - now > timedelta(seconds=30):
        log_security_event("REPLAY_REJECTED", description=f"Future timestamp for {context}", severity="WARNING")
        return False, "Replay timestamp is in the future."

    cache = _load_cache()
    cutoff = now - timedelta(seconds=max_age_seconds)
    cache = {
        stored_nonce: stored_ts
        for stored_nonce, stored_ts in cache.items()
        if _safe_is_recent(stored_ts, cutoff)
    }

    if nonce in cache:
        log_security_event("REPLAY_REJECTED", description=f"Reused nonce for {context}", severity="CRITICAL",
                           nonce=nonce)
        _save_cache(cache)
        return False, "Replay detected: nonce has already been used."

    cache[nonce] = message_time.isoformat()
    _save_cache(cache)
    return True, "Replay check passed."


def _safe_is_recent(timestamp: str, cutoff: datetime) -> bool:
    try:
        return _parse_ts(timestamp) >= cutoff
    except ValueError:
        return False
