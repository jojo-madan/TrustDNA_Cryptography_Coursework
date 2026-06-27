"""
TrustDNA v2.0 — Certificate Authority (ca.py)
==============================================
Implements the Hospital Certificate Authority (CA) — the root of trust
for the entire TrustDNA PKI system.

Cryptographic operations:
  - RSA-2048 key pair generation (CA root key)
  - X.509 v3 self-signed root certificate
  - X.509 v3 certificate issuance for users (signed by CA)
  - SHA-256 digest for all signatures
  - PKCS#12 password-protected keystore for CA private key
  - Certificate Revocation List (CRL) management
  - Certificate expiry validation
  - CRL-based revocation checking

Author: TrustDNA Project
Module: ca.py
"""

import os
import json
import datetime
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import CertificateBuilder, CertificateRevocationListBuilder
from cryptography.x509 import RevokedCertificateBuilder

# ── Directory layout ──
BASE_DIR   = os.path.dirname(__file__)
CA_DIR     = os.path.join(BASE_DIR, "ca")
KEYS_DIR   = os.path.join(BASE_DIR, "keys")
CERTS_DIR  = os.path.join(BASE_DIR, "certs")

for d in [CA_DIR, KEYS_DIR, CERTS_DIR]:
    os.makedirs(d, exist_ok=True)

# ── File paths ──
CA_KEY_PATH      = os.path.join(CA_DIR, "ca_private.pem")
CA_CERT_PATH     = os.path.join(CA_DIR, "ca_cert.pem")
CA_P12_PATH      = os.path.join(CA_DIR, "ca_keystore.p12")
CA_CRL_PATH      = os.path.join(CA_DIR, "ca_crl.pem")
CA_CRL_JSON_PATH = os.path.join(CA_DIR, "crl_entries.json")

# ── CA configuration ──
CA_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,             "NP"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "Bagmati"),
    x509.NameAttribute(NameOID.LOCALITY_NAME,            "Kathmandu"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "TrustDNA Hospital Authority"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI Division"),
    x509.NameAttribute(NameOID.COMMON_NAME,              "TrustDNA Root CA"),
])

CA_VALIDITY_YEARS = 10
USER_VALIDITY_YEARS = 2

# In-memory cache of loaded CA objects
_ca_key  = None
_ca_cert = None


# ════════════════════════════════════════════════════════════
# SETUP — Generate CA root key pair and self-signed certificate
# ════════════════════════════════════════════════════════════

def setup_ca(password: str = "TrustDNA@CA2026") -> x509.Certificate:
    """
    Generate the Hospital Certificate Authority root key pair and
    self-signed X.509 v3 certificate.

    The CA private key is stored in two forms:
      1. Unencrypted PEM (for programmatic loading within the container)
      2. PKCS#12 keystore (password-protected, for export / backup)

    This function is idempotent — if the CA already exists it returns
    the existing certificate without regenerating.

    Parameters:
        password (str): Password used to encrypt the PKCS#12 keystore

    Returns:
        x509.Certificate: The CA root certificate
    """
    global _ca_key, _ca_cert

    if os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH):
        print("[CA] Certificate Authority already initialised — loading existing CA")
        _ca_cert = load_ca_certificate()
        _ca_key  = _load_ca_private_key()
        return _ca_cert

    print("[CA] Generating RSA-2048 root key pair...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    now = datetime.datetime.now(datetime.timezone.utc)

    print("[CA] Building self-signed X.509 v3 root certificate...")
    ca_cert = (
        CertificateBuilder()
        .subject_name(CA_SUBJECT)
        .issuer_name(CA_SUBJECT)                         # Self-signed: issuer == subject
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * CA_VALIDITY_YEARS))
        # ── X.509 v3 extensions ──
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,                               # CA:TRUE — can issue certs
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # ── Save unencrypted PEM (used internally) ──
    with open(CA_KEY_PATH, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(CA_CERT_PATH, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # ── Save PKCS#12 keystore (password-protected export) ──
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"TrustDNA Root CA",
        key=ca_key,
        cert=ca_cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    with open(CA_P12_PATH, "wb") as f:
        f.write(p12_data)

    # ── Initialise empty CRL ──
    _init_empty_crl(ca_key, ca_cert)

    _ca_key  = ca_key
    _ca_cert = ca_cert

    print(f"[CA] Root CA initialised — serial={ca_cert.serial_number}")
    print(f"[CA] Valid until: {ca_cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
    return ca_cert


# ════════════════════════════════════════════════════════════
# CERTIFICATE ISSUANCE
# ════════════════════════════════════════════════════════════

def issue_certificate(
    username: str,
    role: str,
    public_key,
) -> x509.Certificate:
    """
    Issue an X.509 v3 certificate for a registered user.

    The CA signs the user's RSA public key, binding it to their
    identity (username) and role (Lab Technician / Doctor / Pharmacist).

    The certificate includes:
      - Subject with CN=username, O=role
      - Authority Key Identifier (links to CA)
      - Subject Key Identifier
      - Key Usage appropriate to role
      - Extended Key Usage (clientAuth)
      - CRL Distribution Point (where to check revocation)

    Parameters:
        username   (str): User's full name
        role       (str): One of LabTechnician, Doctor, Pharmacist
        public_key     : RSA public key object

    Returns:
        x509.Certificate: Signed user certificate
    """
    ca_key  = _load_ca_private_key()
    ca_cert = load_ca_certificate()

    now = datetime.datetime.now(datetime.timezone.utc)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "TrustDNA Hospital Authority"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
        x509.NameAttribute(NameOID.COMMON_NAME,              username),
    ])

    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * USER_VALIDITY_YEARS))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,                 # Non-repudiation
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_path = os.path.join(CERTS_DIR, f"{username}_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[CA] Certificate issued for {username} ({role}) — serial={cert.serial_number}")
    return cert


# ════════════════════════════════════════════════════════════
# CERTIFICATE VALIDATION
# ════════════════════════════════════════════════════════════

def validate_certificate(cert: x509.Certificate) -> tuple[bool, str]:
    """
    Validate a user certificate against the CA.

    Checks performed:
      1. CA signature — was this cert signed by our CA?
      2. Certificate expiry — is it still within the validity period?
      3. CRL revocation — has it been revoked?

    Parameters:
        cert (x509.Certificate): Certificate to validate

    Returns:
        (bool, str): (is_valid, reason_message)
    """
    ca_cert = load_ca_certificate()

    # ── Check 1: CA signature ──
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:
        return False, "Certificate signature is invalid — not signed by TrustDNA CA"

    # ── Check 2: Expiry ──
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < cert.not_valid_before_utc:
        return False, f"Certificate not yet valid (valid from {cert.not_valid_before_utc})"
    if now > cert.not_valid_after_utc:
        return False, f"Certificate EXPIRED on {cert.not_valid_after_utc}"

    # ── Check 3: CRL revocation ──
    revoked = _get_crl_entries()
    serial_str = str(cert.serial_number)
    if serial_str in revoked:
        reason = revoked[serial_str].get("reason", "unspecified")
        return False, f"Certificate REVOKED — serial={serial_str}, reason={reason}"

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    name = cn[0].value if cn else "unknown"
    return True, f"Certificate for '{name}' is valid — CA chain, expiry, and CRL all passed"


# ════════════════════════════════════════════════════════════
# CERTIFICATE REVOCATION
# ════════════════════════════════════════════════════════════

def revoke_certificate(serial_number: int, reason: str = "unspecified") -> bool:
    """
    Revoke a certificate by adding it to the CRL.

    The revocation is recorded in:
      1. crl_entries.json (fast lookup dictionary)
      2. ca_crl.pem (standard X.509 CRL format, regenerated)

    Parameters:
        serial_number (int): Certificate serial number to revoke
        reason        (str): Reason string (e.g. "keyCompromise", "cessationOfOperation")

    Returns:
        bool: True if successful
    """
    serial_str = str(serial_number)
    revoked    = _get_crl_entries()

    if serial_str in revoked:
        print(f"[CA] Certificate {serial_str} is already revoked")
        return True

    revoked[serial_str] = {
        "serial"    : serial_str,
        "reason"    : reason,
        "revoked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    with open(CA_CRL_JSON_PATH, "w") as f:
        json.dump(revoked, f, indent=2)

    # Regenerate the standard PEM CRL
    _regenerate_crl(revoked)

    print(f"[CA] Certificate {serial_str} revoked — reason: {reason}")
    return True


def is_revoked(serial_number: int) -> bool:
    """Quick check: is this certificate serial on the CRL?"""
    return str(serial_number) in _get_crl_entries()


# ════════════════════════════════════════════════════════════
# LOADERS
# ════════════════════════════════════════════════════════════

def load_ca_certificate() -> x509.Certificate:
    """Load the CA root certificate from disk."""
    global _ca_cert
    if _ca_cert:
        return _ca_cert
    if not os.path.exists(CA_CERT_PATH):
        raise FileNotFoundError("CA not initialised — call setup_ca() first")
    with open(CA_CERT_PATH, "rb") as f:
        _ca_cert = x509.load_pem_x509_certificate(f.read())
    return _ca_cert


def load_user_certificate(username: str) -> x509.Certificate:
    """Load a user's certificate from disk."""
    cert_path = os.path.join(CERTS_DIR, f"{username}_cert.pem")
    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"No certificate found for user: {username}")
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def get_certificate_info(cert: x509.Certificate) -> dict:
    """Return a dictionary of human-readable certificate fields."""
    cn  = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    return {
        "subject"        : cert.subject.rfc4514_string(),
        "issuer"         : cert.issuer.rfc4514_string(),
        "serial_number"  : str(cert.serial_number),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after" : cert.not_valid_after_utc.isoformat(),
        "common_name"    : cn[0].value  if cn  else "",
        "role"           : org[0].value if org else "",
    }


# ════════════════════════════════════════════════════════════
# PRIVATE HELPERS
# ════════════════════════════════════════════════════════════

def _load_ca_private_key():
    """Load the CA private key from PEM file."""
    global _ca_key
    if _ca_key:
        return _ca_key
    if not os.path.exists(CA_KEY_PATH):
        raise FileNotFoundError("CA private key not found — call setup_ca() first")
    with open(CA_KEY_PATH, "rb") as f:
        _ca_key = serialization.load_pem_private_key(f.read(), password=None)
    return _ca_key


def _get_crl_entries() -> dict:
    """Load the CRL JSON entries dictionary."""
    if not os.path.exists(CA_CRL_JSON_PATH):
        return {}
    with open(CA_CRL_JSON_PATH, "r") as f:
        return json.load(f)


def _init_empty_crl(ca_key, ca_cert):
    """Initialise an empty CRL signed by the CA."""
    with open(CA_CRL_JSON_PATH, "w") as f:
        json.dump({}, f)
    _regenerate_crl({})


def _regenerate_crl(revoked_entries: dict):
    """Rebuild and sign the X.509 CRL from the current revocation entries."""
    ca_key  = _load_ca_private_key()
    ca_cert = load_ca_certificate()

    now  = datetime.datetime.now(datetime.timezone.utc)
    next_update = now + datetime.timedelta(days=7)

    builder = (
        CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    for serial_str, entry in revoked_entries.items():
        revoked_cert = (
            RevokedCertificateBuilder()
            .serial_number(int(serial_str))
            .revocation_date(datetime.datetime.fromisoformat(entry["revoked_at"]))
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(ca_key, hashes.SHA256())

    with open(CA_CRL_PATH, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
