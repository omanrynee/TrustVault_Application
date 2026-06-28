"""
Digital Signature Module for TrustVault
==========================================
Provides RSA-PSS and ECDSA file/message signing and verification.

Algorithms:
  - RSA-PSS  with SHA-256  (default, PKCS#1 v2.1 probabilistic padding)
  - ECDSA    with SHA-256  (compact keys, alternative option)

Public API:
  sign_file(filepath, private_key_path, sig_path, password, algorithm)
  verify_file(filepath, cert_or_pubkey_path, sig_path, algorithm)
  sign_message(message, private_key_path, password, algorithm)
  verify_message(message, cert_or_pubkey_path, signature_b64, algorithm)
  get_signature_info(sig_path)
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from security.audit import log_security_event
from security.key_certificate import certificate_common_name, validate_certificate
from security.replay import check_and_store_nonce, new_nonce, utc_now_iso

# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_private_key(key_path: str, password: Optional[str] = None):
    """Load a private key from a PEM or PKCS#12 file.

    Args:
        key_path:  Path to a PEM-encoded private key or a .p12/.pfx PKCS#12 bundle.
        password:  Passphrase for encrypted keys (str).  Pass None for unprotected keys.

    Returns:
        A private-key object (RSAPrivateKey or EllipticCurvePrivateKey).
    """
    if not password:
        raise ValueError("A private-key password is required.")
    password_bytes = password.encode() if isinstance(password, str) else password

    ext = os.path.splitext(key_path)[1].lower()

    if ext in (".p12", ".pfx"):
        # PKCS#12 bundle
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        with open(key_path, "rb") as f:
            data = f.read()
        private_key, cert, _chain = load_key_and_certificates(data, password_bytes, default_backend())
        if cert:
            ok, message = validate_certificate(cert)
            if not ok:
                raise ValueError(message)
        return private_key
    else:
        # PEM / DER
        with open(key_path, "rb") as f:
            key_data = f.read()
        return serialization.load_pem_private_key(key_data, password=password_bytes, backend=default_backend())


def _load_public_key(key_or_cert_path: str):
    """Load a public key from a PEM public key file or an X.509 certificate.

    The function auto-detects whether the PEM block is a certificate or a raw
    public key, so callers can pass either format interchangeably.

    Returns:
        A public-key object (RSAPublicKey or EllipticCurvePublicKey).
    """
    with open(key_or_cert_path, "rb") as f:
        data = f.read()

    # Try X.509 certificate first (contains the public key)
    if b"CERTIFICATE" in data:
        cert = x509.load_pem_x509_certificate(data, default_backend())
        ok, message = validate_certificate(cert)
        if not ok:
            raise ValueError(message)
        return cert.public_key()

    # Try raw public key
    if b"PUBLIC KEY" in data:
        return serialization.load_pem_public_key(data, backend=default_backend())

    raise ValueError(f"Unrecognised PEM content in {key_or_cert_path}. "
                     "Expected a CERTIFICATE or PUBLIC KEY block.")


def _compute_file_digest(filepath: str) -> bytes:
    """Compute the SHA-256 digest of a file in streaming fashion (handles large files)."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)  # 64 KB chunks
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.digest()


# ─────────────────────────────────────────────────────────────────────────────
# Signing
# ─────────────────────────────────────────────────────────────────────────────

def _rsa_sign(data: bytes, private_key: RSAPrivateKey) -> bytes:
    """Sign raw bytes with RSA-PSS / SHA-256."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def _ecdsa_sign(data: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    """Sign raw bytes with ECDSA / SHA-256."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def sign_file(
    filepath: str,
    private_key_path: str,
    sig_path: Optional[str] = None,
    password: Optional[str] = None,
    algorithm: str = "RSA-PSS",
) -> Tuple[bool, str]:
    """Sign a file and write a detached JSON signature file.

    The signature file (<filepath>.sig or *sig_path*) is a JSON document
    containing:
      - algorithm    : "RSA-PSS" or "ECDSA"
      - file_hash    : hex-encoded SHA-256 digest of the signed file
      - signature    : base64-encoded raw signature bytes
      - signed_at    : ISO-8601 UTC timestamp
      - filename     : basename of the signed file

    Args:
        filepath:         Path to the file to sign.
        private_key_path: Path to PEM private key or PKCS#12 bundle.
        sig_path:         Destination for the .sig JSON file.  Defaults to
                          ``<filepath>.sig``.
        password:         Key passphrase (None for unencrypted keys).
        algorithm:        "RSA-PSS" (default) or "ECDSA".

    Returns:
        (True, success_message) or (False, error_message).
    """
    try:
        if not os.path.exists(filepath):
            return False, f"File not found: {filepath}"
        if not os.path.exists(private_key_path):
            return False, f"Private key not found: {private_key_path}"

        # Load key
        private_key = _load_private_key(private_key_path, password)

        # Digest
        file_digest = _compute_file_digest(filepath)

        # Sign
        algo_upper = algorithm.upper()
        if algo_upper == "RSA-PSS":
            if not isinstance(private_key, RSAPrivateKey):
                return False, "RSA-PSS requires an RSA private key."
            raw_sig = _rsa_sign(file_digest, private_key)
        elif algo_upper == "ECDSA":
            if not isinstance(private_key, EllipticCurvePrivateKey):
                return False, "ECDSA requires an EC private key."
            raw_sig = _ecdsa_sign(file_digest, private_key)
        else:
            return False, f"Unsupported algorithm: {algorithm}. Use 'RSA-PSS' or 'ECDSA'."

        # Build detached signature document
        sig_doc = {
            "algorithm":  algo_upper,
            "file_hash":  file_digest.hex(),
            "signature":  base64.b64encode(raw_sig).decode(),
            "signed_at":  utc_now_iso(),
            "nonce":      new_nonce(),
            "filename":   os.path.basename(filepath),
        }

        # Write
        if sig_path is None:
            sig_path = filepath + ".sig"
        with open(sig_path, "w") as f:
            json.dump(sig_doc, f, indent=2)

        log_security_event("SIGNATURE_CREATED", description="File signed",
                           file_path=filepath, signature_path=sig_path, algorithm=algo_upper)

        return True, (
            f"File signed successfully.\n"
            f"Algorithm : {algo_upper}\n"
            f"File      : {filepath}\n"
            f"Signature : {sig_path}\n"
            f"SHA-256   : {file_digest.hex()}"
        )

    except Exception as exc:
        return False, f"Signing failed: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Verification
# ─────────────────────────────────────────────────────────────────────────────

def _rsa_verify(data: bytes, signature: bytes, public_key: RSAPublicKey) -> None:
    """Raise InvalidSignature if the RSA-PSS signature does not match."""
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def _ecdsa_verify(data: bytes, signature: bytes, public_key: EllipticCurvePublicKey) -> None:
    """Raise InvalidSignature if the ECDSA signature does not match."""
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))


def verify_file(
    filepath: str,
    cert_or_pubkey_path: str,
    sig_path: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> Tuple[bool, str]:
    """Verify a detached file signature.

    Args:
        filepath:            Path to the file whose integrity is to be verified.
        cert_or_pubkey_path: Path to the signer's X.509 certificate (.pem) or
                             PEM public key file.
        sig_path:            Path to the .sig JSON file.  Defaults to
                             ``<filepath>.sig``.
        algorithm:           Override algorithm (usually read from the .sig file).

    Returns:
        (True, success_message) or (False, failure_message).
    """
    try:
        if sig_path is None:
            sig_path = filepath + ".sig"

        if not os.path.exists(filepath):
            return False, f"File not found: {filepath}"
        if not os.path.exists(sig_path):
            return False, f"Signature file not found: {sig_path}"
        if not os.path.exists(cert_or_pubkey_path):
            return False, f"Public key / certificate not found: {cert_or_pubkey_path}"

        # Read signature document
        with open(sig_path, "r") as f:
            sig_doc = json.load(f)

        stored_algo = algorithm or sig_doc.get("algorithm", "RSA-PSS")
        stored_hash = sig_doc.get("file_hash", "")
        raw_sig     = base64.b64decode(sig_doc["signature"])
        signed_at   = sig_doc.get("signed_at", "unknown")
        replay_ok, replay_message = check_and_store_nonce(
            sig_doc.get("nonce", ""),
            signed_at,
            context=f"signature:{os.path.abspath(sig_path)}",
        )
        if not replay_ok:
            return False, replay_message
        orig_name   = sig_doc.get("filename", "unknown")

        # Re-digest the current file
        current_digest = _compute_file_digest(filepath)
        current_hex    = current_digest.hex()

        # Step 1: integrity check – does the file hash still match?
        if current_hex != stored_hash:
            return False, (
                "VERIFICATION FAILED — File has been TAMPERED with after signing!\n"
                f"Expected hash : {stored_hash}\n"
                f"Current hash  : {current_hex}"
            )

        # Step 2: cryptographic signature check
        public_key = _load_public_key(cert_or_pubkey_path)

        algo_upper = stored_algo.upper()
        if algo_upper == "RSA-PSS":
            _rsa_verify(current_digest, raw_sig, public_key)
        elif algo_upper == "ECDSA":
            _ecdsa_verify(current_digest, raw_sig, public_key)
        else:
            return False, f"Unsupported algorithm in signature file: {stored_algo}"

        log_security_event("SIGNATURE_VERIFIED", description="File signature verified",
                           file_path=filepath, signature_path=sig_path, certificate=cert_or_pubkey_path)
        return True, (
            f"Signature VALID.\n"
            f"Algorithm   : {algo_upper}\n"
            f"File        : {filepath}\n"
            f"Signed at   : {signed_at}\n"
            f"Original    : {orig_name}\n"
            f"SHA-256     : {current_hex}"
        )

    except InvalidSignature:
        log_security_event("SIGNATURE_VERIFICATION_FAILED", description="Invalid file signature",
                           severity="WARNING", file_path=filepath, signature_path=sig_path)
        return False, (
            "VERIFICATION FAILED — Cryptographic signature is INVALID.\n"
            "The file content matches the hash but the signature cannot be verified "
            "with the provided public key. The signature may be forged or the wrong "
            "key was supplied."
        )
    except Exception as exc:
        return False, f"Verification error: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Message (in-memory) signing
# ─────────────────────────────────────────────────────────────────────────────

def sign_message(
    message: str,
    private_key_path: str,
    password: Optional[str] = None,
    algorithm: str = "RSA-PSS",
) -> Tuple[bool, str]:
    """Sign an arbitrary text message and return a base64-encoded signature.

    The message is UTF-8 encoded before signing, ensuring consistent byte
    representation across platforms.

    Args:
        message:          The plaintext message to sign.
        private_key_path: Path to PEM private key or PKCS#12 bundle.
        password:         Key passphrase.
        algorithm:        "RSA-PSS" or "ECDSA".

    Returns:
        (True, base64_signature) or (False, error_message).
    """
    try:
        private_key = _load_private_key(private_key_path, password)
        msg_bytes   = message.encode("utf-8")

        algo_upper = algorithm.upper()
        if algo_upper == "RSA-PSS":
            if not isinstance(private_key, RSAPrivateKey):
                return False, "RSA-PSS requires an RSA private key."
            raw_sig = _rsa_sign(msg_bytes, private_key)
        elif algo_upper == "ECDSA":
            if not isinstance(private_key, EllipticCurvePrivateKey):
                return False, "ECDSA requires an EC private key."
            raw_sig = _ecdsa_sign(msg_bytes, private_key)
        else:
            return False, f"Unsupported algorithm: {algorithm}"

        payload = {
            "algorithm": algo_upper,
            "signature": base64.b64encode(raw_sig).decode(),
            "signed_at": utc_now_iso(),
            "nonce": new_nonce(),
        }
        log_security_event("MESSAGE_SIGNED", description="Message signed", algorithm=algo_upper)
        return True, base64.b64encode(json.dumps(payload).encode("utf-8")).decode()

    except Exception as exc:
        return False, f"Message signing failed: {exc}"


def verify_message(
    message: str,
    cert_or_pubkey_path: str,
    signature_b64: str,
    algorithm: str = "RSA-PSS",
) -> Tuple[bool, str]:
    """Verify a base64-encoded message signature.

    Args:
        message:             The original plaintext message.
        cert_or_pubkey_path: Path to X.509 certificate or PEM public key.
        signature_b64:       base64-encoded signature produced by sign_message().
        algorithm:           "RSA-PSS" or "ECDSA".

    Returns:
        (True, success_message) or (False, failure_message).
    """
    try:
        public_key = _load_public_key(cert_or_pubkey_path)
        msg_bytes  = message.encode("utf-8")
        decoded = base64.b64decode(signature_b64)
        try:
            sig_doc = json.loads(decoded.decode("utf-8"))
            raw_sig = base64.b64decode(sig_doc["signature"])
            algorithm = sig_doc.get("algorithm", algorithm)
            replay_ok, replay_message = check_and_store_nonce(
                sig_doc.get("nonce", ""),
                sig_doc.get("signed_at", ""),
                context="message-signature",
            )
            if not replay_ok:
                return False, replay_message
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError):
            raw_sig = decoded

        algo_upper = algorithm.upper()
        if algo_upper == "RSA-PSS":
            _rsa_verify(msg_bytes, raw_sig, public_key)
        elif algo_upper == "ECDSA":
            _ecdsa_verify(msg_bytes, raw_sig, public_key)
        else:
            return False, f"Unsupported algorithm: {algorithm}"

        log_security_event("MESSAGE_SIGNATURE_VERIFIED", description="Message signature verified",
                           certificate=cert_or_pubkey_path)
        return True, f"Message signature VALID ({algo_upper})."

    except InvalidSignature:
        log_security_event("MESSAGE_SIGNATURE_FAILED", description="Invalid message signature",
                           severity="WARNING", certificate=cert_or_pubkey_path)
        return False, (
            "Message signature INVALID. "
            "The signature cannot be verified with the provided public key."
        )
    except Exception as exc:
        return False, f"Message verification error: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def get_signature_info(sig_path: str) -> Tuple[bool, dict]:
    """Return metadata from a .sig JSON file without verifying the signature.

    Useful for displaying signature details in the GUI before running the
    full verification step.

    Returns:
        (True, info_dict) or (False, {"error": message}).
    """
    try:
        with open(sig_path, "r") as f:
            sig_doc = json.load(f)
        return True, {
            "algorithm":  sig_doc.get("algorithm", "unknown"),
            "signed_at":  sig_doc.get("signed_at", "unknown"),
            "filename":   sig_doc.get("filename", "unknown"),
            "file_hash":  sig_doc.get("file_hash", "unknown"),
            "sig_path":   sig_path,
        }
    except Exception as exc:
        return False, {"error": str(exc)}
