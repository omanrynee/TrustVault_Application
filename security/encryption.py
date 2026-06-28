"""
Hybrid Encryption Module for TrustVault
==========================================
Implements confidentiality using hybrid encryption:
  - AES-256-GCM  (symmetric, data encryption)  — fast, authenticated
  - RSA-OAEP     (asymmetric, key encapsulation) — secures the AES key

Flow:
  Encrypt:  random AES-256 key + IV  →  AES-GCM encrypt plaintext
            RSA-OAEP encrypt(AES key) → bundle { enc_key | nonce | tag | ciphertext }
  Decrypt:  RSA-OAEP decrypt(enc_key) → AES-256 key
            AES-GCM decrypt(ciphertext) → plaintext

All output is stored in a self-describing JSON envelope so the format
is transparent and easy to parse in any language.

Public API:
  encrypt_file(filepath, cert_or_pubkey_path, out_path)
  decrypt_file(enc_path, private_key_path, out_path, password)
  encrypt_message(message, cert_or_pubkey_path)
  decrypt_message(envelope_b64, private_key_path, password)
"""

import os
import json
import base64
import struct
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from security.audit import log_security_event
from security.key_certificate import validate_certificate
from security.replay import check_and_store_nonce, new_nonce, utc_now_iso

# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

_RSA_OAEP_PADDING = asym_padding.OAEP(
    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def _load_public_key(cert_or_pubkey_path: str):
    """Load an RSA public key from a PEM certificate or PEM public key file."""
    with open(cert_or_pubkey_path, "rb") as f:
        data = f.read()

    if b"CERTIFICATE" in data:
        cert = x509.load_pem_x509_certificate(data, default_backend())
        ok, message = validate_certificate(cert)
        if not ok:
            raise ValueError(message)
        return cert.public_key()

    if b"PUBLIC KEY" in data:
        return serialization.load_pem_public_key(data, backend=default_backend())

    raise ValueError(f"Cannot parse public key from {cert_or_pubkey_path}.")


def _load_private_key(key_path: str, password: Optional[str] = None):
    """Load an RSA private key from PEM or PKCS#12 bundle."""
    if not password:
        raise ValueError("A private-key password is required.")
    password_bytes = password.encode() if isinstance(password, str) else password
    ext = os.path.splitext(key_path)[1].lower()

    if ext in (".p12", ".pfx"):
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        with open(key_path, "rb") as f:
            raw = f.read()
        private_key, cert, _ = load_key_and_certificates(raw, password_bytes, default_backend())
        if cert:
            ok, message = validate_certificate(cert)
            if not ok:
                raise ValueError(message)
        return private_key

    with open(key_path, "rb") as f:
        raw = f.read()
    return serialization.load_pem_private_key(raw, password=password_bytes, backend=default_backend())


def _aes_gcm_encrypt(plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    """AES-256-GCM encrypt.

    Returns:
        (aes_key, nonce, ciphertext_with_tag)
        The GCM authentication tag is appended to the ciphertext by AESGCM.
    """
    aes_key = os.urandom(32)   # 256 bits
    nonce   = os.urandom(12)   # 96-bit nonce (GCM standard)
    aesgcm  = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return aes_key, nonce, ciphertext


def _aes_gcm_decrypt(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """AES-256-GCM decrypt and authenticate.

    Raises ValueError if authentication fails (tampered ciphertext).
    """
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def _build_envelope(enc_key: bytes, nonce: bytes, ciphertext: bytes, meta: dict) -> dict:
    """Pack all encrypted artefacts into a JSON-serialisable envelope."""
    return {
        "version":    "SecureFIM-Hybrid-v1",
        "kdf":        "RSA-OAEP-SHA256",
        "cipher":     "AES-256-GCM",
        "enc_key":    base64.b64encode(enc_key).decode(),
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "created_at": utc_now_iso(),
        "replay_nonce": new_nonce(),
        **meta,
    }


def _parse_envelope(envelope: dict) -> Tuple[bytes, bytes, bytes]:
    """Unpack an envelope dictionary into raw crypto components."""
    enc_key    = base64.b64decode(envelope["enc_key"])
    nonce      = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    return enc_key, nonce, ciphertext


def _derive_ecdh_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"TrustVault ECDH forward secrecy",
        backend=default_backend(),
    ).derive(shared_secret)


def _ecdh_encrypt(plaintext: bytes, recipient_public_key) -> Tuple[dict, int]:
    ephemeral_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)
    salt = os.urandom(16)
    aes_key = _derive_ecdh_key(shared_secret, salt)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, associated_data=None)
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "version": "TrustVault-ECDH-v1",
        "kdf": "ECDH-HKDF-SHA256",
        "cipher": "AES-256-GCM",
        "ephemeral_public_key": base64.b64encode(ephemeral_public).decode(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "created_at": utc_now_iso(),
        "replay_nonce": new_nonce(),
    }, len(ciphertext)


def _ecdh_decrypt(envelope: dict, private_key) -> bytes:
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("ECDH forward-secrecy envelopes require an EC private key.")
    ephemeral_public = serialization.load_pem_public_key(
        base64.b64decode(envelope["ephemeral_public_key"]),
        backend=default_backend(),
    )
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
    aes_key = _derive_ecdh_key(shared_secret, base64.b64decode(envelope["salt"]))
    return AESGCM(aes_key).decrypt(
        base64.b64decode(envelope["nonce"]),
        base64.b64decode(envelope["ciphertext"]),
        associated_data=None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# File encryption / decryption
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_file(
    filepath: str,
    cert_or_pubkey_path: str,
    out_path: Optional[str] = None,
) -> Tuple[bool, str]:
    """Encrypt a file using AES-256-GCM + RSA-OAEP key encapsulation.

    The encrypted output is a JSON file (*.enc*) containing the RSA-encrypted
    AES key, the GCM nonce, and the ciphertext — all base64-encoded.

    Args:
        filepath:            Path to the plaintext file.
        cert_or_pubkey_path: Recipient's X.509 certificate (.pem) or public key.
        out_path:            Output path.  Defaults to ``<filepath>.enc``.

    Returns:
        (True, success_message) or (False, error_message).
    """
    try:
        if not os.path.exists(filepath):
            return False, f"File not found: {filepath}"
        if not os.path.exists(cert_or_pubkey_path):
            return False, f"Public key / certificate not found: {cert_or_pubkey_path}"

        # Read plaintext
        with open(filepath, "rb") as f:
            plaintext = f.read()
        original_size = len(plaintext)

        public_key = _load_public_key(cert_or_pubkey_path)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            envelope, _cipher_len = _ecdh_encrypt(plaintext, public_key)
            envelope.update({
                "original_filename": os.path.basename(filepath),
                "original_size": original_size,
                "encrypted_for": os.path.basename(cert_or_pubkey_path),
            })
            algorithm_label = "AES-256-GCM + ephemeral ECDH-HKDF-SHA256"
        else:
            aes_key, nonce, ciphertext = _aes_gcm_encrypt(plaintext)
            enc_key = public_key.encrypt(aes_key, _RSA_OAEP_PADDING)
            envelope = _build_envelope(enc_key, nonce, ciphertext, meta={
                "original_filename": os.path.basename(filepath),
                "original_size":     original_size,
                "encrypted_for":     os.path.basename(cert_or_pubkey_path),
            })
            algorithm_label = "AES-256-GCM + RSA-OAEP-SHA256"

        # Write
        if out_path is None:
            out_path = filepath + ".enc"
        with open(out_path, "w") as f:
            json.dump(envelope, f, indent=2)

        log_security_event("FILE_ENCRYPTED", description="File encrypted",
                           file_path=filepath, output_path=out_path, recipient=cert_or_pubkey_path)

        return True, (
            f"File encrypted successfully.\n"
            f"Algorithm       : {algorithm_label}\n"
            f"Original file   : {filepath} ({original_size:,} bytes)\n"
            f"Encrypted file  : {out_path} ({os.path.getsize(out_path):,} bytes)"
        )

    except Exception as exc:
        return False, f"Encryption failed: {exc}"


def decrypt_file(
    enc_path: str,
    private_key_path: str,
    out_path: Optional[str] = None,
    password: Optional[str] = None,
) -> Tuple[bool, str]:
    """Decrypt a hybrid-encrypted .enc file.

    Args:
        enc_path:         Path to the JSON .enc envelope.
        private_key_path: Recipient's PEM private key or PKCS#12 bundle.
        out_path:         Output path for the recovered plaintext.  Defaults to
                          stripping the trailing ``.enc`` extension.
        password:         Key passphrase.

    Returns:
        (True, success_message) or (False, error_message).
    """
    try:
        if not os.path.exists(enc_path):
            return False, f"Encrypted file not found: {enc_path}"
        if not os.path.exists(private_key_path):
            return False, f"Private key not found: {private_key_path}"

        # Load envelope
        with open(enc_path, "r") as f:
            envelope = json.load(f)

        if envelope.get("version") not in ("SecureFIM-Hybrid-v1", "TrustVault-ECDH-v1"):
            return False, "Unrecognised encryption envelope version."
        replay_ok, replay_message = check_and_store_nonce(
            envelope.get("replay_nonce", ""),
            envelope.get("created_at", ""),
            context=f"encrypted-file:{os.path.abspath(enc_path)}",
        )
        if not replay_ok:
            return False, replay_message

        original_filename = envelope.get("original_filename", "decrypted_file")

        private_key = _load_private_key(private_key_path, password)

        try:
            if envelope.get("version") == "TrustVault-ECDH-v1":
                plaintext = _ecdh_decrypt(envelope, private_key)
            else:
                enc_key, nonce, ciphertext = _parse_envelope(envelope)
                aes_key = private_key.decrypt(enc_key, _RSA_OAEP_PADDING)
                plaintext = _aes_gcm_decrypt(aes_key, nonce, ciphertext)
        except Exception:
            return False, (
                "Decryption FAILED — ciphertext authentication error.\n"
                "The encrypted file may have been tampered with, or the wrong private key was used."
            )

        # Determine output path
        if out_path is None:
            if enc_path.endswith(".enc"):
                out_path = enc_path[:-4]          # strip .enc
            else:
                out_path = enc_path + ".dec"

        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(plaintext)

        log_security_event("FILE_DECRYPTED", description="File decrypted",
                           encrypted_path=enc_path, output_path=out_path)

        return True, (
            f"File decrypted successfully.\n"
            f"Original name   : {original_filename}\n"
            f"Output file     : {out_path} ({len(plaintext):,} bytes)"
        )

    except Exception as exc:
        return False, f"Decryption failed: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Message (in-memory) encryption
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_message(
    message: str,
    cert_or_pubkey_path: str,
) -> Tuple[bool, str]:
    """Encrypt a text message and return a compact base64-encoded envelope.

    The envelope is a base64-encoded JSON string that can be safely transmitted
    over text channels.  Only the holder of the matching RSA private key can
    decrypt it.

    Returns:
        (True, base64_envelope) or (False, error_message).
    """
    try:
        plaintext  = message.encode("utf-8")
        public_key = _load_public_key(cert_or_pubkey_path)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            envelope, _cipher_len = _ecdh_encrypt(plaintext, public_key)
            envelope["type"] = "message"
        else:
            aes_key, nonce, ciphertext = _aes_gcm_encrypt(plaintext)
            enc_key = public_key.encrypt(aes_key, _RSA_OAEP_PADDING)
            envelope = _build_envelope(enc_key, nonce, ciphertext, meta={
                "type": "message",
            })
        envelope_b64 = base64.b64encode(json.dumps(envelope).encode()).decode()
        log_security_event("MESSAGE_ENCRYPTED", description="Message encrypted",
                           recipient=cert_or_pubkey_path)
        return True, envelope_b64

    except Exception as exc:
        return False, f"Message encryption failed: {exc}"


def decrypt_message(
    envelope_b64: str,
    private_key_path: str,
    password: Optional[str] = None,
) -> Tuple[bool, str]:
    """Decrypt a base64-encoded encrypted message envelope.

    Args:
        envelope_b64:     Output from encrypt_message().
        private_key_path: Recipient's PEM private key or PKCS#12 bundle.
        password:         Key passphrase.

    Returns:
        (True, plaintext_message) or (False, error_message).
    """
    try:
        envelope    = json.loads(base64.b64decode(envelope_b64).decode())
        replay_ok, replay_message = check_and_store_nonce(
            envelope.get("replay_nonce", ""),
            envelope.get("created_at", ""),
            context="encrypted-message",
        )
        if not replay_ok:
            return False, replay_message
        private_key = _load_private_key(private_key_path, password)

        try:
            if envelope.get("version") == "TrustVault-ECDH-v1":
                plaintext = _ecdh_decrypt(envelope, private_key)
            else:
                enc_key, nonce, ciphertext = _parse_envelope(envelope)
                aes_key = private_key.decrypt(enc_key, _RSA_OAEP_PADDING)
                plaintext = _aes_gcm_decrypt(aes_key, nonce, ciphertext)
        except Exception:
            return False, (
                "Message decryption FAILED — authentication tag mismatch.\n"
                "The message may have been tampered with, or the wrong private key was used."
            )

        log_security_event("MESSAGE_DECRYPTED", description="Message decrypted")
        return True, plaintext.decode("utf-8")

    except Exception as exc:
        return False, f"Message decryption failed: {exc}"
