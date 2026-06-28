import base64
import json
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

from security.hash_verifier import FileHashVerifier
from security.key_certificate import (
    ROOT_CA_CERT_FILE,
    authenticate_with_certificate,
    ensure_root_ca,
    generate_certificate,
    is_revoked,
    revoke_certificate,
    validate_certificate,
)
from security.signing import sign_file, verify_file, sign_message, verify_message
from security.encryption import encrypt_file, decrypt_file, encrypt_message, decrypt_message


@pytest.fixture()
def isolated_workspace(tmp_path, monkeypatch):
    import config.constants as C
    import security.replay as replay
    import security.users as users

    for folder in ("keys", "certs", "data", "logs", "monitored"):
        (tmp_path / folder).mkdir()

    monkeypatch.setattr(C, "KEY_DIR", str(tmp_path / "keys"), raising=False)
    monkeypatch.setattr(C, "CERT_DIR", str(tmp_path / "certs"), raising=False)
    monkeypatch.setattr(C, "DATA_DIR", str(tmp_path / "data"), raising=False)
    monkeypatch.setattr(C, "LOG_DIR", str(tmp_path / "logs"), raising=False)
    monkeypatch.setattr(C, "REVOKED_FILE", str(tmp_path / "data" / "revoked.json"), raising=False)
    monkeypatch.setattr(C, "AUDIT_LOG_FILE", str(tmp_path / "logs" / "audit_log.json"), raising=False)
    monkeypatch.setattr(replay, "NONCE_FILE", str(tmp_path / "data" / "nonce_cache.json"), raising=False)
    monkeypatch.setattr(users, "USER_FILE", str(tmp_path / "data" / "users.json"), raising=False)
    return tmp_path


@pytest.fixture()
def alice(isolated_workspace):
    ok, msg = generate_certificate("alice", password="alice-pass", key_algorithm="RSA")
    assert ok, msg
    return {
        "name": "alice",
        "password": "alice-pass",
        "cert": str(isolated_workspace / "certs" / "alice.pem"),
        "p12": str(isolated_workspace / "keys" / "alice.p12"),
    }


@pytest.fixture()
def bob(isolated_workspace):
    ok, msg = generate_certificate("bob", password="bob-pass", key_algorithm="RSA")
    assert ok, msg
    return {
        "name": "bob",
        "password": "bob-pass",
        "cert": str(isolated_workspace / "certs" / "bob.pem"),
        "p12": str(isolated_workspace / "keys" / "bob.p12"),
    }


@pytest.fixture()
def erin_ec(isolated_workspace):
    ok, msg = generate_certificate("erin", password="erin-pass", key_algorithm="EC")
    assert ok, msg
    return {
        "name": "erin",
        "password": "erin-pass",
        "cert": str(isolated_workspace / "certs" / "erin.pem"),
        "p12": str(isolated_workspace / "keys" / "erin.p12"),
    }


def write(path: Path, text="sensitive content") -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_root_ca_and_ca_signed_certificate_validation(isolated_workspace, alice):
    _ca_key, ca_cert = ensure_root_ca()
    assert ca_cert.subject == ca_cert.issuer
    assert (isolated_workspace / "certs" / ROOT_CA_CERT_FILE).exists()

    ok, message = validate_certificate(alice["cert"])
    assert ok, message


def test_secure_key_storage_requires_password_and_pkcs12_only(isolated_workspace):
    ok, message = generate_certificate("nopass", password=None)
    assert not ok
    assert "password" in message.lower()

    ok, message = generate_certificate("carol", password="carol-pass", export_pkcs12=False)
    assert ok, message
    assert (isolated_workspace / "keys" / "carol.p12").exists()
    assert not (isolated_workspace / "keys" / "carol_private.key").exists()

    p12_data = (isolated_workspace / "keys" / "carol.p12").read_bytes()
    key, cert, chain = load_key_and_certificates(p12_data, b"carol-pass")
    assert key is not None
    assert cert is not None
    assert chain


def test_certificate_based_authentication_challenge_response(alice):
    ok, message = authenticate_with_certificate("alice", "alice-pass", alice["p12"], "alice-pass")
    assert ok, message

    ok, message = authenticate_with_certificate("alice", "wrong", alice["p12"], "alice-pass")
    assert not ok


def test_revoked_certificate_rejected_for_auth_and_verification(isolated_workspace, alice):
    target = write(isolated_workspace / "monitored" / "signed.txt")
    sig_path = str(target) + ".sig"
    ok, message = sign_file(str(target), alice["p12"], sig_path, password=alice["password"])
    assert ok, message

    ok, message = revoke_certificate("alice")
    assert ok, message
    assert is_revoked("alice")

    ok, message = verify_file(str(target), alice["cert"], sig_path)
    assert not ok
    assert "revoked" in message.lower()

    ok, message = authenticate_with_certificate("alice", "alice-pass", alice["p12"], "alice-pass")
    assert not ok
    assert "revoked" in message.lower()


def test_digital_signature_creation_verification_and_multi_user_rejection(isolated_workspace, alice, bob):
    target = write(isolated_workspace / "monitored" / "multi.txt", "alice owns this")
    sig_path = str(target) + ".sig"

    ok, message = sign_file(str(target), alice["p12"], sig_path, password=alice["password"])
    assert ok, message

    ok, message = verify_file(str(target), alice["cert"], sig_path)
    assert ok, message

    ok, message = verify_file(str(target), bob["cert"], sig_path)
    assert not ok


def test_signature_replay_protection(isolated_workspace, alice):
    target = write(isolated_workspace / "monitored" / "replay.txt")
    sig_path = str(target) + ".sig"
    ok, message = sign_file(str(target), alice["p12"], sig_path, password=alice["password"])
    assert ok, message

    ok, message = verify_file(str(target), alice["cert"], sig_path)
    assert ok, message
    ok, message = verify_file(str(target), alice["cert"], sig_path)
    assert not ok
    assert "replay" in message.lower() or "nonce" in message.lower()


def test_rsa_hybrid_file_encryption_round_trip(isolated_workspace, alice):
    target = write(isolated_workspace / "monitored" / "secret.txt", "classified")
    enc_path = str(target) + ".enc"
    dec_path = str(target) + ".dec"

    ok, message = encrypt_file(str(target), alice["cert"], enc_path)
    assert ok, message
    assert json.loads(Path(enc_path).read_text())["version"] == "SecureFIM-Hybrid-v1"

    ok, message = decrypt_file(enc_path, alice["p12"], dec_path, password=alice["password"])
    assert ok, message
    assert Path(dec_path).read_text(encoding="utf-8") == "classified"


def test_forward_secrecy_ecdh_encryption_round_trip(isolated_workspace, erin_ec):
    target = write(isolated_workspace / "monitored" / "fs.txt", "forward secret")
    enc_path = str(target) + ".enc"
    dec_path = str(target) + ".dec"

    ok, message = encrypt_file(str(target), erin_ec["cert"], enc_path)
    assert ok, message
    envelope = json.loads(Path(enc_path).read_text())
    assert envelope["version"] == "TrustVault-ECDH-v1"
    assert envelope["kdf"] == "ECDH-HKDF-SHA256"
    assert "ephemeral_public_key" in envelope

    ok, message = decrypt_file(enc_path, erin_ec["p12"], dec_path, password=erin_ec["password"])
    assert ok, message
    assert Path(dec_path).read_text(encoding="utf-8") == "forward secret"


def test_message_encryption_replay_protection(alice):
    ok, envelope = encrypt_message("hello", alice["cert"])
    assert ok, envelope
    ok, message = decrypt_message(envelope, alice["p12"], password=alice["password"])
    assert ok, message
    assert message == "hello"
    ok, message = decrypt_message(envelope, alice["p12"], password=alice["password"])
    assert not ok


def test_message_signing_round_trip(alice):
    ok, signature = sign_message("approve", alice["p12"], password=alice["password"])
    assert ok, signature
    ok, message = verify_message("approve", alice["cert"], signature)
    assert ok, message


def test_hash_verifier_detects_tampering(isolated_workspace):
    target = write(isolated_workspace / "monitored" / "hash.txt", "v1")
    verifier = FileHashVerifier(hash_db_file=str(isolated_workspace / "data" / "hashes.json"))
    ok, message = verifier.register_file(str(target))
    assert ok, message
    target.write_text("v2", encoding="utf-8")
    status, _message, info = verifier.verify_file(str(target), trigger_alert=False)
    assert status == "TAMPERED"
    assert info["original_hash"] != info["current_hash"]


def test_ransomware_and_anomaly_compatibility(isolated_workspace):
    from security.ransomware_detector import RansomwareDetector
    from security.anomaly_detector import AnomalyDetector

    detector = RansomwareDetector()
    for i in range(20):
        detector.check_mass_rename(f"file_{i}.docx", f"file_{i}.encrypted")
    assert detector.get_detection_stats()["alert_count"] > 0

    anomaly = AnomalyDetector(use_ml=False, state_file=str(isolated_workspace / "data" / "anomaly.json"))
    for i in range(12):
        anomaly.process_event("CREATED", f"burst_{i}.tmp")
    assert anomaly.get_statistics()["total_events"] >= 12
