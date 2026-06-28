"""
Root-CA backed key and certificate management for TrustVault.

Private keys are generated as password-protected PKCS#12 bundles only. User
certificates are signed by the local TrustVault Root CA and are validated
before cryptographic operations.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from config import constants
from security.audit import log_security_event
from security import users as user_store

ROOT_CA_NAME = "TrustVault Root CA"
ROOT_CA_KEY_FILE = "trustvault_root_ca.p12"
ROOT_CA_CERT_FILE = "trustvault_root_ca.pem"
ROOT_CA_PASSWORD_ENV = "TRUSTVAULT_CA_PASSWORD"
DEFAULT_ROOT_CA_PASSWORD = "TrustVaultRootCA-Change-Me"


def _cert_dir() -> str:
    return constants.CERT_DIR


def _key_dir() -> str:
    return constants.KEY_DIR


def _revoked_file() -> str:
    return constants.REVOKED_FILE


def _ca_key_path() -> str:
    return os.path.join(_key_dir(), ROOT_CA_KEY_FILE)


def _ca_cert_path() -> str:
    return os.path.join(_cert_dir(), ROOT_CA_CERT_FILE)


def _ca_password() -> bytes:
    return os.environ.get(ROOT_CA_PASSWORD_ENV, DEFAULT_ROOT_CA_PASSWORD).encode("utf-8")


def _ensure_dirs() -> None:
    os.makedirs(_key_dir(), exist_ok=True)
    os.makedirs(_cert_dir(), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(_revoked_file())), exist_ok=True)


def ensure_root_ca() -> Tuple[object, x509.Certificate]:
    """Create or load the local Root CA private key and certificate."""
    _ensure_dirs()
    key_path = _ca_key_path()
    cert_path = _ca_cert_path()
    password = _ca_password()

    if os.path.exists(key_path) and os.path.exists(cert_path):
        with open(key_path, "rb") as f:
            ca_key, _cert, _chain = pkcs12.load_key_and_certificates(f.read(), password, default_backend())
        with open(cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return ca_key, ca_cert

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    now = datetime.now(timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ROOT_CA_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TrustVault"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    p12_data = pkcs12.serialize_key_and_certificates(
        name=ROOT_CA_NAME.encode("utf-8"),
        key=ca_key,
        cert=ca_cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    with open(key_path, "wb") as f:
        f.write(p12_data)
    with open(cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    log_security_event("ROOT_CA_CREATED", description="TrustVault Root CA created", cert_path=cert_path)
    return ca_key, ca_cert


def generate_certificate(name: str, password: Optional[str] = None, validity_days: int = 365,
                         export_pkcs12: bool = True, key_algorithm: str = "RSA") -> Tuple[bool, str]:
    """Generate a password-protected PKCS#12 keystore and CA-signed X.509 cert."""
    try:
        if not password:
            return False, "A private-key password is required. Unencrypted key generation is disabled."
        _ensure_dirs()
        ca_key, ca_cert = ensure_root_ca()

        if key_algorithm.upper() in ("EC", "ECC", "ECDSA"):
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            key_label = "EC P-256"
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            key_label = "RSA-2048"

        public_key = private_key.public_key()
        now = datetime.now(timezone.utc)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TrustVault"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=isinstance(private_key, ec.EllipticCurvePrivateKey),
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ExtendedKeyUsageOID.CODE_SIGNING,
            ]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        cert_path = os.path.join(_cert_dir(), f"{name}.pem")
        p12_path = os.path.join(_key_dir(), f"{name}.p12")
        pub_key_path = os.path.join(_key_dir(), f"{name}_public.pem")

        p12_data = pkcs12.serialize_key_and_certificates(
            name=name.encode("utf-8"),
            key=private_key,
            cert=cert,
            cas=[ca_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
        with open(p12_path, "wb") as f:
            f.write(p12_data)
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(pub_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

        existing_user = user_store.get_user(name) or {}
        user_store.create_or_update_user(
            name,
            password,
            role=existing_user.get("role", "Operator"),
            email=existing_user.get("email", ""),
            cert_path=cert_path,
            pkcs12_path=p12_path,
        )
        log_security_event("CERTIFICATE_GENERATED", user=name, description="CA-signed certificate generated",
                           key_algorithm=key_label, cert_path=cert_path, pkcs12_path=p12_path)
        try:
            from alerts.alert_manager import AlertManager
            AlertManager.certificate_generated(name, cert_path)
        except Exception as e:
            print(f"AlertManager error: {e}")
        return True, (
            f"Certificate generated for '{name}'.\n"
            f"Key algorithm   : {key_label}\n"
            f"Issuer          : {ROOT_CA_NAME}\n"
            f"Private keystore: {p12_path}\n"
            f"Certificate     : {cert_path}\n"
            f"Root CA         : {_ca_cert_path()}\n"
        )
    except Exception as exc:
        return False, f"Failed to generate certificate: {exc}"


def revoke_certificate(name: str) -> Tuple[bool, str]:
    revoked = _load_revoked()
    if _revoked_contains(revoked, name):
        return False, f"Certificate for '{name}' is already revoked."

    cert_path = os.path.join(_cert_dir(), f"{name}.pem")
    serial = None
    if os.path.exists(cert_path):
        try:
            serial = str(load_certificate(cert_path).serial_number)
        except Exception:
            serial = None

    revoked.append({
        "username": name,
        "serial_number": serial,
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "revoked_by": "system",
    })
    _save_revoked(revoked)
    log_security_event("CERTIFICATE_REVOKED", user=name, description="Certificate revoked",
                       severity="WARNING", serial_number=serial)
    try:
        from alerts.alert_manager import AlertManager
        AlertManager.certificate_revoked(name)
    except Exception as e:
        print(f"AlertManager error: {e}")
    return True, f"Certificate revoked for '{name}'."


def is_revoked(name_or_cert) -> bool:
    try:
        cert = name_or_cert if isinstance(name_or_cert, x509.Certificate) else None
        name = certificate_common_name(cert) if cert else str(name_or_cert)
        serial = str(cert.serial_number) if cert else None
    except Exception:
        name = str(name_or_cert)
        serial = None

    for entry in _load_revoked():
        if isinstance(entry, str) and entry.lower() == name.lower():
            return True
        if isinstance(entry, dict):
            entry_name = entry.get("username")
            entry_serial = entry.get("serial_number")
            if isinstance(entry_name, str) and entry_name.lower() == name.lower():
                return True
            if serial and entry_serial and str(entry_serial) == serial:
                return True
    return False


def unrevoke_certificate(name: str) -> Tuple[bool, str]:
    revoked = _load_revoked()
    updated = []
    removed = False
    for entry in revoked:
        entry_name = entry.get("username") if isinstance(entry, dict) else entry
        if isinstance(entry_name, str) and entry_name.lower() == name.lower():
            removed = True
            continue
        updated.append(entry)
    if not removed:
        return False, f"'{name}' is not in the revocation list."
    _save_revoked(updated)
    return True, f"Certificate reinstated for '{name}'."


def list_certificates() -> Tuple[List[str], List]:
    certs = []
    if os.path.exists(_cert_dir()):
        certs = [f for f in os.listdir(_cert_dir()) if f.endswith(".pem") and f != ROOT_CA_CERT_FILE]
    return certs, _load_revoked()


def load_private_key(name: str, password: Optional[str] = None):
    p12_path = os.path.join(_key_dir(), f"{name}.p12")
    if os.path.exists(p12_path):
        return load_private_key_from_path(p12_path, password)
    raise FileNotFoundError(f"No PKCS#12 keystore found for '{name}' in {_key_dir()}.")


def load_private_key_from_path(key_path: str, password: Optional[str] = None):
    if not password:
        raise ValueError("A keystore password is required.")
    ext = os.path.splitext(key_path)[1].lower()
    password_bytes = password.encode("utf-8") if isinstance(password, str) else password
    if ext in (".p12", ".pfx"):
        with open(key_path, "rb") as f:
            key, cert, _chain = pkcs12.load_key_and_certificates(f.read(), password_bytes, default_backend())
        if cert:
            ok, message = validate_certificate(cert)
            if not ok:
                raise ValueError(message)
        return key

    # Legacy compatibility for old encrypted PEM keys; new generation never writes these.
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password_bytes, backend=default_backend())


def load_certificate(cert_path: str) -> x509.Certificate:
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def load_public_cert_path(name: str) -> str:
    cert_path = os.path.join(_cert_dir(), f"{name}.pem")
    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Certificate not found for '{name}' at {cert_path}.")
    return cert_path


def certificate_common_name(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def validate_certificate(cert_or_path, check_revocation: bool = True) -> Tuple[bool, str]:
    """Validate expiry, issuer, CA signature, trust chain, and revocation."""
    try:
        cert = load_certificate(cert_or_path) if isinstance(cert_or_path, str) else cert_or_path
        _ca_key, ca_cert = ensure_root_ca()

        now = datetime.now(timezone.utc)
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        if now < not_before:
            return False, "Certificate is not yet valid."
        if now > not_after:
            return False, "Certificate has expired."
        if cert.issuer != ca_cert.subject:
            return False, "Certificate issuer is not the trusted TrustVault Root CA."

        ca_public_key = ca_cert.public_key()
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        else:
            ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))

        if check_revocation and is_revoked(cert):
            return False, "Certificate has been revoked."
        return True, "Certificate is trusted and valid."
    except InvalidSignature:
        return False, "Certificate signature verification failed."
    except Exception as exc:
        return False, f"Certificate validation failed: {exc}"


def authenticate_with_certificate(username: str, password: str, pkcs12_path: str,
                                  keystore_password: str = None) -> Tuple[bool, str]:
    """Authenticate a user with account password plus PKCS#12 challenge response."""
    try:
        if not user_store.verify_password(username, password):
            log_security_event("AUTH_FAILED", user=username, description="Invalid account password", severity="WARNING")
            try:
                from alerts.alert_manager import AlertManager
                AlertManager.login_failed(username, "Invalid account password")
            except Exception as e:
                print(f"AlertManager error: {e}")
            return False, "Invalid username or password."

        keystore_password = keystore_password or password
        with open(pkcs12_path, "rb") as f:
            private_key, cert, _chain = pkcs12.load_key_and_certificates(
                f.read(), keystore_password.encode("utf-8"), default_backend()
            )
        if private_key is None or cert is None:
            return False, "PKCS#12 bundle must contain a private key and certificate."

        cn = certificate_common_name(cert)
        if cn.lower() != username.lower():
            log_security_event("AUTH_FAILED", user=username, description="Certificate CN mismatch",
                               severity="CRITICAL", certificate_cn=cn)
            try:
                from alerts.alert_manager import AlertManager
                AlertManager.login_failed(username, "Certificate CN mismatch")
            except Exception as e:
                print(f"AlertManager error: {e}")
            return False, "Certificate does not belong to this user."

        ok, message = validate_certificate(cert)
        if not ok:
            log_security_event("AUTH_FAILED", user=username, description=message, severity="CRITICAL")
            try:
                from alerts.alert_manager import AlertManager
                AlertManager.login_failed(username, message)
            except Exception as e:
                print(f"AlertManager error: {e}")
            return False, message

        challenge = os.urandom(32)
        signature = _sign_challenge(private_key, challenge)
        _verify_challenge(cert.public_key(), challenge, signature)
        log_security_event("LOGIN_SUCCESS", user=username, description="Certificate authentication succeeded")
        try:
            from alerts.alert_manager import AlertManager
            AlertManager.login_successful(username)
        except Exception as e:
            print(f"AlertManager error: {e}")
        return True, "Certificate authentication succeeded."
    except Exception as exc:
        log_security_event("AUTH_FAILED", user=username, description=str(exc), severity="WARNING")
        try:
            from alerts.alert_manager import AlertManager
            AlertManager.login_failed(username, str(exc))
        except Exception as e:
            print(f"AlertManager error: {e}")
        return False, f"Certificate authentication failed: {exc}"


def _sign_challenge(private_key, challenge: bytes) -> bytes:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(challenge, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ), hashes.SHA256())
    return private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))


def _verify_challenge(public_key, challenge: bytes, signature: bytes) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, challenge, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ), hashes.SHA256())
    else:
        public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))


def _revoked_contains(revoked: List, name: str) -> bool:
    return any(
        (isinstance(entry, str) and entry.lower() == name.lower()) or
        (isinstance(entry, dict) and str(entry.get("username", "")).lower() == name.lower())
        for entry in revoked
    )


def _load_revoked() -> list:
    path = _revoked_file()
    if os.path.exists(path) and os.path.getsize(path) > 0:
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _save_revoked(revoked: list) -> None:
    path = _revoked_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    temp_path = path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(revoked, f, indent=2)
    os.replace(temp_path, path)


class CertificateManager:
    @staticmethod
    def generate(name: str, password: Optional[str] = None,
                 validity_days: int = 365, export_pkcs12: bool = True) -> Tuple[bool, str]:
        return generate_certificate(name, password, validity_days, export_pkcs12)

    @staticmethod
    def revoke(name: str) -> Tuple[bool, str]:
        return revoke_certificate(name)

    @staticmethod
    def list_all() -> Tuple[List[str], List]:
        return list_certificates()
