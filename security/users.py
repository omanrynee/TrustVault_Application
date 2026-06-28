"""Multi-user account store for TrustVault."""

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

USER_FILE = os.path.join("data", "users.json")
PBKDF2_ITERATIONS = 200_000


def _load_users() -> Dict[str, dict]:
    if not os.path.exists(USER_FILE) or os.path.getsize(USER_FILE) == 0:
        return {}
    try:
        with open(USER_FILE, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_users(users: Dict[str, dict]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(USER_FILE)), exist_ok=True)
    temp_path = USER_FILE + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    os.replace(temp_path, USER_FILE)


def _hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return base64.b64encode(salt).decode(), base64.b64encode(digest).decode()


def create_or_update_user(username: str, password: str, role: str = "Operator",
                          email: str = "", cert_path: str = "", pkcs12_path: str = "") -> dict:
    if not username:
        raise ValueError("Username is required.")
    if not password:
        raise ValueError("Password is required.")

    users = _load_users()
    salt, password_hash = _hash_password(password)
    users[username] = {
        "username": username,
        "role": role,
        "email": email,
        "salt": salt,
        "password_hash": password_hash,
        "cert_path": cert_path,
        "pkcs12_path": pkcs12_path,
        "created_at": users.get(username, {}).get("created_at", datetime.now(timezone.utc).isoformat()),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }
    _save_users(users)
    return users[username]


def update_user_certificate(username: str, cert_path: str, pkcs12_path: str) -> None:
    users = _load_users()
    if username not in users:
        create_or_update_user(username, secrets.token_urlsafe(18), cert_path=cert_path, pkcs12_path=pkcs12_path)
        return
    users[username]["cert_path"] = cert_path
    users[username]["pkcs12_path"] = pkcs12_path
    users[username]["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_users(users)


def verify_password(username: str, password: str) -> bool:
    user = get_user(username)
    if not user or not user.get("active", True):
        return False
    try:
        salt = base64.b64decode(user["salt"])
        _, digest = _hash_password(password, salt)
        return secrets.compare_digest(digest, user["password_hash"])
    except Exception:
        return False


def get_user(username: str) -> Optional[dict]:
    return _load_users().get(username)


def list_users() -> List[dict]:
    return list(_load_users().values())
