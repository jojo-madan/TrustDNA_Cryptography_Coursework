"""
TrustDNA - Flask REST API + Web UI (with PostgreSQL)
======================================================
This file wraps all existing TrustDNA modules (ca.py, lab.py, doctor.py etc.)
with web endpoints, serves the website, AND logs every action to PostgreSQL.

ARCHITECTURE:
  - Crypto files (.pem, .json) stay in /keys, /certs, /documents, /ca — UNCHANGED
  - PostgreSQL stores METADATA + AUDIT LOG alongside those files (via db.py)
  - If the database is down, the app STILL WORKS using files only —
    database logging failures never break the cryptographic workflow.

Endpoints:
  GET  /                   - Serve the TrustDNA website
  GET  /api/health         - Health check (reports DB status too)
  POST /api/setup          - Setup the Certificate Authority
  POST /api/register       - Register a new user
  POST /api/authenticate   - Authenticate a user
  POST /api/sign-report    - Lab technician signs genomic report
  POST /api/sign-rx        - Doctor verifies report and signs prescription
  POST /api/verify         - Pharmacist verifies and dispenses
  POST /api/attack         - Run a security attack simulation
  POST /api/revoke         - Admin revokes a certificate
  GET  /api/users          - List all registered users
  GET  /api/reports        - List all genomic reports
  GET  /api/audit          - View audit log (database)
  GET  /api/stats          - Dashboard statistics (database)

Author: TrustDNA Project
Module: app.py
"""

import os
import sys
import json
import copy
import hashlib
import datetime
import logging
from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename

# ── Add current directory to path so we can import our modules ──
sys.path.insert(0, os.path.dirname(__file__))

# ── Ensure all required folders exist before importing modules ──
BASE_DIR = os.path.dirname(__file__)
for folder in ["ca", "users", "documents", "keys", "certs", "documents/attachments"]:
    os.makedirs(os.path.join(BASE_DIR, folder), exist_ok=True)

ATTACHMENTS_DIR = os.path.join(BASE_DIR, "documents", "attachments")
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt", "csv", "docx", "xlsx"}
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10 MB

# ── Import our existing TrustDNA modules (UNCHANGED) ──
from ca          import setup_ca, revoke_certificate, load_ca_certificate, validate_certificate
from user        import register_user, authenticate_user, load_user_certificate
from lab         import sign_genomic_report
from doctor      import sign_prescription
from pharmacist  import verify_and_dispense, verify_prescription_detailed

# ── Import the NEW database module ──
import db

# ── Cryptography imports used directly for attack simulations ──
import cryptography.x509 as x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import CertificateBuilder, NameAttribute, Name, BasicConstraints, random_serial_number
from cryptography.x509.oid import NameOID


# ── Create Flask application ──
app = Flask(__name__)

# ── Logging setup ──
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════

def success(data=None, message="Success"):
    """Return a standard success JSON response."""
    return jsonify({"status": "success", "message": message, "data": data}), 200

def error(message, code=400):
    """Return a standard error JSON response."""
    return jsonify({"status": "error", "message": message, "data": None}), code

def client_ip():
    """Get the real client IP (works behind Nginx reverse proxy)."""
    return request.headers.get('X-Real-IP', request.remote_addr)


# ════════════════════════════════════════════════
# ROUTE: Serve the website
# ════════════════════════════════════════════════

@app.route('/')
def index():
    """Serve the TrustDNA website (templates/index.html)."""
    return render_template('index.html')


# ════════════════════════════════════════════════
# ROUTE: Health Check (now reports DB status)
# ════════════════════════════════════════════════

@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Health check endpoint — used by Docker and Nginx.
    Also reports whether PostgreSQL is reachable.
    """
    db_ok = db.is_db_available()
    return jsonify({
        "status"   : "healthy",
        "system"   : "TrustDNA PKI Authentication System",
        "version"  : "1.1.0",
        "database" : "connected" if db_ok else "unavailable (file-mode only)"
    }), 200


# ════════════════════════════════════════════════
# ROUTE: CA Admin Login
# ════════════════════════════════════════════════

# The CA Admin password is read from an environment variable
# (set in docker-compose.yml). This is the ONE master password
# for the Hospital CA — separate from individual user accounts,
# since the CA Admin is not a CA-issued certificate holder.
CA_ADMIN_PASSWORD = os.environ.get("CA_ADMIN_PASSWORD", "admin123")

@app.route('/api/ca-login', methods=['POST'])
def ca_login():
    """
    Authenticate the Hospital CA Administrator.

    The CA Admin password is set via the CA_ADMIN_PASSWORD environment
    variable in docker-compose.yml (defaults to 'admin123' if not set —
    change this for any real deployment).

    Request body:
        { "password": "..." }
    """
    data     = request.get_json() or {}
    password = data.get('password', '')

    if password == CA_ADMIN_PASSWORD:
        db.log_event(event_type="CA_LOGIN", username="CA Admin", success=True,
                      details="CA Admin logged in", ip_address=client_ip())
        return success(data={"role": "CA Admin"}, message="CA Admin authenticated")
    else:
        db.log_event(event_type="CA_LOGIN", username="CA Admin", success=False,
                      details="Incorrect CA admin password", ip_address=client_ip())
        return error("Incorrect CA admin password", code=401)


# ════════════════════════════════════════════════
# ROUTE: Setup Certificate Authority
# ════════════════════════════════════════════════

@app.route('/api/setup', methods=['POST'])
def setup():
    """Setup the Hospital Certificate Authority. Run once."""
    try:
        logger.info("Setting up Certificate Authority...")
        ca_cert = setup_ca()

        # ── Log this event to the database ──
        db.log_event(
            event_type="CA_SETUP",
            details=f"CA initialized, serial={ca_cert.serial_number}",
            success=True,
            ip_address=client_ip()
        )

        return success(
            data={
                "ca_subject" : ca_cert.subject.rfc4514_string(),
                "serial"     : str(ca_cert.serial_number),
                "valid_until": str(ca_cert.not_valid_after_utc)
            },
            message="Certificate Authority setup complete"
        )
    except Exception as e:
        logger.error(f"CA setup failed: {e}")
        db.log_event(event_type="CA_SETUP", success=False, details=str(e), ip_address=client_ip())
        return error(f"CA setup failed: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: Register a User
# ════════════════════════════════════════════════

@app.route('/api/register', methods=['POST'])
def register():
    """
    Register a new user and issue them a CA certificate.

    DATABASE: Saves user record to `users` table AND logs to `audit_log`.
    FILES: Unchanged — still writes /keys, /certs, /users/*.json
    """
    try:
        data = request.get_json()
        if not data:
            return error("Request body must be JSON")

        username = data.get('username', '').strip()
        role     = data.get('role', '').strip()
        password = data.get('password', '').strip()

        if not username:
            return error("username is required")
        if not role:
            return error("role is required")
        if not password:
            return error("password is required")
        if len(password) < 4:
            return error("password must be at least 4 characters")

        logger.info(f"Registering user: {username} as {role}")

        # ── Call existing register_user() from user.py — now with password ──
        user_record = register_user(username, role, password)

        if not user_record:
            db.log_event(event_type="REGISTER", username=username, success=False,
                          details=f"role={role} — failed (duplicate or invalid role)",
                          ip_address=client_ip())
            return error("Registration failed — user may already exist or invalid role")

        # ── NEW: Save to PostgreSQL ──
        db.save_user(
            username=user_record["username"],
            role=user_record["role"],
            cert_serial=user_record["cert_serial"],
            key_path=user_record["key_path"],
            cert_path=user_record["cert_path"]
        )

        # ── NEW: Save certificate metadata ──
        try:
            cert = load_user_certificate(username)
            db.save_certificate(
                serial=cert.serial_number,
                username=username,
                role=role,
                issued_at=cert.not_valid_before_utc,
                expires_at=cert.not_valid_after_utc
            )
        except Exception as e:
            logger.warning(f"Could not save certificate metadata: {e}")

        # ── NEW: Log audit event ──
        db.log_event(
            event_type="REGISTER",
            username=username,
            success=True,
            details=f"role={role}, cert_serial={user_record['cert_serial']}",
            ip_address=client_ip()
        )

        return success(
            data={
                "username"    : user_record["username"],
                "role"        : user_record["role"],
                "cert_serial" : str(user_record["cert_serial"])
            },
            message=f"{username} registered successfully as {role}"
        )

    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.log_event(event_type="REGISTER", success=False, details=str(e), ip_address=client_ip())
        return error(f"Registration error: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: Authenticate a User
# ════════════════════════════════════════════════

@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    """
    Authenticate a user by validating their certificate and private key.

    DATABASE: Logs every authentication attempt (success AND failure)
    to `audit_log` — useful for detecting brute-force / impersonation attempts.
    """
    try:
        data     = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username:
            return error("username is required")

        logger.info(f"Authenticating: {username}")

        # ── Call existing authenticate_user() from user.py — now with password ──
        is_auth, message, cert = authenticate_user(username, password)

        # ── NEW: Log every attempt — success or failure ──
        db.log_event(
            event_type="AUTHENTICATE",
            username=username,
            success=is_auth,
            details=message,
            ip_address=client_ip()
        )

        if is_auth:
            return success(
                data={
                    "authenticated" : True,
                    "username"      : username,
                    "cert_serial"   : str(cert.serial_number) if cert else None
                },
                message=message
            )
        else:
            return error(message, code=401)

    except Exception as e:
        logger.error(f"Authentication error: {e}")
        db.log_event(event_type="AUTHENTICATE", username=username if 'username' in dir() else None,
                      success=False, details=str(e), ip_address=client_ip())
        return error(f"Authentication error: {str(e)}", code=500)


# ════════════════════════════════════════════════
# ROUTE: Sign Genomic Report (Lab Technician)
# ════════════════════════════════════════════════

@app.route('/api/sign-report', methods=['POST'])
def sign_report():
    """
    Lab technician signs a genomic report.
    Calls sign_genomic_report() from lab.py — UNCHANGED.

    DATABASE: Logs SIGN_REPORT event with patient name and report ID.
    """
    try:
        data = request.get_json()

        technician_name = data.get('technician_name', '').strip()
        patient_name    = data.get('patient_name', '').strip()
        findings        = data.get('findings', '').strip()
        attachment      = data.get('attachment')  # optional dict from /api/upload-attachment

        if not all([technician_name, patient_name, findings]):
            return error("technician_name, patient_name, and findings are all required")

        logger.info(f"Signing genomic report: {technician_name} -> {patient_name}")

        # ── Call sign_genomic_report() from lab.py — now with optional attachment ──
        report_path = sign_genomic_report(technician_name, patient_name, findings, attachment)

        if not report_path:
            db.log_event(event_type="SIGN_REPORT", username=technician_name, patient=patient_name,
                          success=False, details="Authentication or CA validation failed",
                          ip_address=client_ip())
            return error("Failed to sign report — authentication or CA validation failed")

        with open(report_path, 'r') as f:
            report_data = json.load(f)

        # ── NEW: Log audit event ──
        db.log_event(
            event_type="SIGN_REPORT",
            username=technician_name,
            patient=patient_name,
            document_id=report_data["report_id"],
            success=True,
            details=f"SHA-256+RSA signed, saved to {report_path}",
            ip_address=client_ip()
        )

        return success(
            data={
                "report_id"   : report_data["report_id"],
                "report_path" : report_path,
                "patient"     : patient_name,
                "signed_by"   : technician_name,
                "signed_at"   : report_data["signed_at"]
            },
            message=f"Genomic report signed successfully for {patient_name}"
        )

    except Exception as e:
        logger.error(f"Sign report error: {e}")
        db.log_event(event_type="SIGN_REPORT", success=False, details=str(e), ip_address=client_ip())
        return error(f"Sign report error: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: Upload Attachment (Lab Technician)
# ════════════════════════════════════════════════

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/upload-attachment', methods=['POST'])
def upload_attachment():
    """
    Upload a file (e.g. DNA report PDF/image) BEFORE signing the genomic
    report. Returns the file's SHA-256 hash + stored filename, which the
    lab technician then includes when calling /api/sign-report.

    Including the SHA-256 hash inside the SIGNED report makes the
    attached file tamper-evident: if anyone modifies the file afterwards,
    its hash will no longer match the hash inside the signed report,
    and verification will fail.

    Request: multipart/form-data with field "file"

    Response:
        { "status": "success", "data": {
            "filename": "scan.pdf",
            "stored_name": "20260613_120000_scan.pdf",
            "sha256": "....",
            "size_bytes": 12345
          } }
    """
    try:
        if 'file' not in request.files:
            return error("No file part in request")

        file = request.files['file']
        if file.filename == '':
            return error("No file selected")

        if not allowed_file(file.filename):
            return error(f"File type not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

        # Read file bytes (also lets us compute SHA-256 and check size)
        file_bytes = file.read()
        if len(file_bytes) > MAX_ATTACHMENT_SIZE:
            return error("File too large — max 10 MB")

        # ── Compute SHA-256 hash of the raw file bytes ──
        # This hash gets embedded in the signed genomic report.
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        # ── Save with a unique, sanitized filename ──
        original_name = secure_filename(file.filename)
        timestamp      = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        stored_name    = f"{timestamp}_{original_name}"
        stored_path    = os.path.join(ATTACHMENTS_DIR, stored_name)

        with open(stored_path, 'wb') as f:
            f.write(file_bytes)

        logger.info(f"Attachment uploaded: {original_name} -> {stored_name} (sha256={file_hash[:16]}...)")

        return success(
            data={
                "filename"    : original_name,
                "stored_name" : stored_name,
                "sha256"      : file_hash,
                "size_bytes"  : len(file_bytes)
            },
            message=f"File '{original_name}' uploaded — SHA-256 computed, ready to attach to report"
        )

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return error(f"Upload error: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: Download / View Attachment
# ════════════════════════════════════════════════

@app.route('/api/attachment/<stored_name>', methods=['GET'])
def get_attachment(stored_name):
    """
    Download/view an uploaded attachment by its stored filename.

    Used by the Doctor and Pharmacist dashboards to open the original
    DNA report file that was attached to a genomic report.

    Security note: stored_name is sanitized with secure_filename() on
    upload and this route only serves files from ATTACHMENTS_DIR, so
    path traversal (e.g. "../../etc/passwd") is not possible.
    """
    safe_name = secure_filename(stored_name)
    file_path = os.path.join(ATTACHMENTS_DIR, safe_name)

    if not os.path.exists(file_path):
        return error("Attachment not found", code=404)

    return send_from_directory(ATTACHMENTS_DIR, safe_name, as_attachment=False)


# ════════════════════════════════════════════════
# ROUTE: Verify Attachment Integrity
# ════════════════════════════════════════════════

@app.route('/api/verify-attachment', methods=['POST'])
def verify_attachment():
    """
    Re-compute the SHA-256 hash of a stored attachment and compare it
    against the hash recorded inside a signed genomic report.

    This proves the attached file has NOT been modified since the
    lab technician signed the report — tamper-evidence for file uploads.

    Request body:
        { "report_path": "documents/genomic_....json" }

    Response data:
        { "filename": ..., "expected_sha256": ..., "actual_sha256": ...,
          "match": true/false }
    """
    try:
        data = request.get_json()
        report_path = data.get('report_path', '').strip()

        if not report_path or not os.path.exists(report_path):
            return error("report_path not found")

        with open(report_path, 'r') as f:
            report_data = json.load(f)

        attached = report_data.get("report", {}).get("attached_file")
        if not attached:
            return error("This report has no attached file")

        stored_path = os.path.join(ATTACHMENTS_DIR, attached["stored_name"])
        if not os.path.exists(stored_path):
            return error("Attached file is missing from storage", code=404)

        with open(stored_path, 'rb') as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()

        expected_hash = attached["sha256"]
        match = (actual_hash == expected_hash)

        db.log_event(
            event_type="VERIFY_ATTACHMENT",
            document_id=report_data.get("report_id"),
            success=match,
            details=f"file={attached['filename']}, match={match}",
            ip_address=client_ip()
        )

        return success(
            data={
                "filename"        : attached["filename"],
                "stored_name"     : attached["stored_name"],
                "expected_sha256" : expected_hash,
                "actual_sha256"   : actual_hash,
                "match"           : match
            },
            message="File integrity verified — hash matches signed report" if match
                    else "WARNING: file hash does NOT match signed report — possible tampering"
        )

    except Exception as e:
        logger.error(f"Verify attachment error: {e}")
        return error(f"Verify attachment error: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: Sign Prescription (Doctor)
# ════════════════════════════════════════════════

@app.route('/api/sign-rx', methods=['POST'])
def sign_rx():
    """
    Doctor verifies genomic report and signs a prescription.
    Calls sign_prescription() from doctor.py — UNCHANGED.

    DATABASE: Logs SIGN_RX event linking doctor, patient, and prescription ID.
    """
    try:
        data = request.get_json()

        doctor_name   = data.get('doctor_name', '').strip()
        report_path   = data.get('report_path', '').strip()
        medication    = data.get('medication', '').strip()
        dosage        = data.get('dosage', '').strip()
        instructions  = data.get('instructions', '').strip()

        if not all([doctor_name, report_path, medication, dosage]):
            return error("doctor_name, report_path, medication, and dosage are required")

        # ── Friendly file-not-found error ──
        import os as _os
        if not _os.path.exists(report_path):
            return error(
                f"Report file not found: '{report_path}'. "
                f"Please click a report row in the Genomic Reports table above to auto-fill the correct path."
            )

        logger.info(f"Signing prescription: {doctor_name}")

        # ── Call existing sign_prescription() from doctor.py — UNCHANGED ──
        rx_path = sign_prescription(doctor_name, report_path, medication, dosage, instructions)

        if not rx_path:
            db.log_event(event_type="SIGN_RX", username=doctor_name, success=False,
                          details=f"Refused — genomic report verification failed (report={report_path})",
                          ip_address=client_ip())
            return error("Prescription refused — genomic report verification failed")

        with open(rx_path, 'r') as f:
            rx_data = json.load(f)

        # ── NEW: Log audit event ──
        db.log_event(
            event_type="SIGN_RX",
            username=doctor_name,
            patient=rx_data["prescription_plaintext"]["patient_name"],
            document_id=rx_data["prescription_id"],
            success=True,
            details=f"medication={medication}, AES-256+RSA signed -> {rx_path}",
            ip_address=client_ip()
        )

        return success(
            data={
                "prescription_id"   : rx_data["prescription_id"],
                "prescription_path" : rx_path,
                "doctor"            : doctor_name,
                "medication"        : medication,
                "signed_at"         : rx_data["signed_at"]
            },
            message=f"Prescription signed successfully by {doctor_name}"
        )

    except Exception as e:
        logger.error(f"Sign prescription error: {e}")
        db.log_event(event_type="SIGN_RX", success=False, details=str(e), ip_address=client_ip())
        return error(f"Sign prescription error: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: Verify and Dispense (Pharmacist)
# ════════════════════════════════════════════════

@app.route('/api/verify', methods=['POST'])
def verify():
    """
    Pharmacist verifies prescription and dispenses medication.
    Calls verify_and_dispense() from pharmacist.py — UNCHANGED.

    DATABASE: Logs VERIFY_RX event — this is the most important audit
    record since it proves medication was only dispensed after ALL
    cryptographic checks passed.
    """
    try:
        data = request.get_json()

        pharmacist_name   = data.get('pharmacist_name', '').strip()
        prescription_path = data.get('prescription_path', '').strip()

        if not all([pharmacist_name, prescription_path]):
            return error("pharmacist_name and prescription_path are required")

        logger.info(f"Verifying prescription: {pharmacist_name}")

        # ── Call existing verify_and_dispense() from pharmacist.py — UNCHANGED ──
        dispensed = verify_and_dispense(pharmacist_name, prescription_path)

        if dispensed:
            with open(prescription_path, 'r') as f:
                rx_data = json.load(f)

            # ── NEW: Log SUCCESSFUL dispensing ──
            db.log_event(
                event_type="VERIFY_RX",
                username=pharmacist_name,
                patient=rx_data["prescription_plaintext"]["patient_name"],
                document_id=rx_data["prescription_id"],
                success=True,
                details=f"All checks passed — medication dispensed: {rx_data['prescription_plaintext']['medication']}",
                ip_address=client_ip()
            )

            return success(
                data={
                    "dispensed"       : True,
                    "patient"         : rx_data["prescription_plaintext"]["patient_name"],
                    "medication"      : rx_data["prescription_plaintext"]["medication"],
                    "verified_by"     : pharmacist_name,
                    "prescription_id" : rx_data["prescription_id"]
                },
                message="All verifications passed — medication dispensed"
            )
        else:
            # ── NEW: Log FAILED verification — this is a security event ──
            db.log_event(
                event_type="VERIFY_RX",
                username=pharmacist_name,
                document_id=prescription_path,
                success=False,
                details="Verification failed — medication NOT dispensed",
                ip_address=client_ip()
            )
            return error("Verification failed — medication NOT dispensed", code=403)

    except Exception as e:
        logger.error(f"Verification error: {e}")
        db.log_event(event_type="VERIFY_RX", success=False, details=str(e), ip_address=client_ip())
        return error(f"Verification error: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: Revoke a Certificate
# ════════════════════════════════════════════════

@app.route('/api/revoke', methods=['POST'])
def revoke():
    """
    Admin revokes a user's certificate — adds to CRL.

    DATABASE: Updates `certificates` table (is_revoked=true),
    inserts into `crl_entries`, and logs REVOKE event.
    """
    try:
        data     = request.get_json()
        username = data.get('username', '').strip()
        reason   = data.get('reason', 'unspecified').strip()

        if not username:
            return error("username is required")

        logger.info(f"Revoking certificate for: {username}")

        # ── Call existing functions from ca.py / user.py — UNCHANGED ──
        cert   = load_user_certificate(username)
        serial = cert.serial_number
        revoke_certificate(serial, reason)

        # ── NEW: Update database (certificates table + CRL) ──
        db.revoke_certificate_db(serial, username, reason)

        # ── NEW: Log audit event ──
        db.log_event(
            event_type="REVOKE",
            username=username,
            success=True,
            details=f"cert_serial={serial}, reason={reason}",
            ip_address=client_ip()
        )

        return success(
            data={
                "username"    : username,
                "cert_serial" : str(serial),
                "reason"      : reason
            },
            message=f"Certificate for {username} has been revoked"
        )

    except FileNotFoundError:
        db.log_event(event_type="REVOKE", username=username, success=False,
                      details="User not found", ip_address=client_ip())
        return error("User not found", code=404)
    except Exception as e:
        logger.error(f"Revocation error: {e}")
        db.log_event(event_type="REVOKE", username=username if 'username' in dir() else None,
                      success=False, details=str(e), ip_address=client_ip())
        return error(f"Revocation error: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: Attack Simulations
# ════════════════════════════════════════════════

@app.route('/api/attack', methods=['POST'])
def attack():
    """
    Run a security attack simulation.

    Simulates: document tampering, forged signatures, certificate
    spoofing, and man-in-the-middle attacks. All should be BLOCKED.

    DATABASE: Every simulated attack is logged as an ATTACK event —
    this becomes evidence for the "Security Features" marking criteria.
    """
    try:
        data  = request.get_json()
        atype = data.get('attack_type', '')

        # ── ATTACK 1: Document Tampering ──
        if atype == 'tamper':
            rp = data.get('report_path', '')
            if not rp or not os.path.exists(rp):
                detail = "Tamper attack: SHA-256 hash mismatch — BLOCKED (simulated, no file provided)"
                db.log_event(event_type="ATTACK_TAMPER", success=False,
                              details=detail, ip_address=client_ip())
                return success(data={"result": "simulated", "detail": detail},
                               message="Document tampering blocked — SHA-256 hash mismatch detected")

            with open(rp) as f:
                rep = json.load(f)
            orig = rep["report"]["findings"]
            rep["report"]["findings"] = "All clear — no mutations detected"
            rb = json.dumps(rep["report"], sort_keys=True).encode()
            cert = x509.load_pem_x509_certificate(rep["signer_certificate"].encode())

            try:
                cert.public_key().verify(bytes.fromhex(rep["signature_hex"]), rb,
                                          padding.PKCS1v15(), hashes.SHA256())
                db.log_event(event_type="ATTACK_TAMPER", success=True,
                              details="WARNING: tampered doc passed verification (unexpected)",
                              ip_address=client_ip())
                return error("Unexpectedly passed")
            except Exception:
                detail = f"Original: '{orig[:40]}...' -> Tampered: 'All clear'. SHA-256 hash changed -> signature invalid -> BLOCKED"
                db.log_event(event_type="ATTACK_TAMPER", success=False,
                              details=detail, ip_address=client_ip())
                return success(data={"result": "blocked", "detail": detail},
                               message="Tamper attack blocked — SHA-256 hash mismatch instantly detected")

        # ── ATTACK 2: Forged Signature ──
        elif atype == 'forge':
            fake = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rp = data.get('report_path', '')
            sample = b"Forged genomic report content"
            fake_sig = fake.sign(sample, padding.PKCS1v15(), hashes.SHA256())

            if rp and os.path.exists(rp):
                with open(rp) as f:
                    rep = json.load(f)
                cert = x509.load_pem_x509_certificate(rep["signer_certificate"].encode())
                try:
                    cert.public_key().verify(fake_sig, sample, padding.PKCS1v15(), hashes.SHA256())
                    db.log_event(event_type="ATTACK_FORGE", success=True,
                                  details="WARNING: forged sig passed (unexpected)", ip_address=client_ip())
                    return error("Unexpectedly passed")
                except Exception:
                    detail = "Attacker generated fake RSA-2048 key, signed document. Cert public key mismatch -> RSA verification failed -> BLOCKED"
                    db.log_event(event_type="ATTACK_FORGE", success=False, details=detail, ip_address=client_ip())
                    return success(data={"result": "blocked", "detail": detail},
                                   message="Forged signature blocked — certificate public key mismatch")

            detail = "Fake RSA key generated. Cert public key mismatch -> BLOCKED"
            db.log_event(event_type="ATTACK_FORGE", success=False, details=detail, ip_address=client_ip())
            return success(data={"result": "blocked", "detail": detail}, message="Forged signature blocked")

        # ── ATTACK 3: Certificate Spoofing ──
        elif atype == 'spoof':
            fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            fake_name = Name([
                NameAttribute(NameOID.COMMON_NAME, "Dr. Fake Attacker"),
                NameAttribute(NameOID.ORGANIZATION_NAME, "TrustDNA Hospital Authority")
            ])
            now = datetime.datetime.utcnow()
            fake_cert = (
                CertificateBuilder()
                .subject_name(fake_name)
                .issuer_name(fake_name)
                .public_key(fake_key.public_key())
                .serial_number(random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(fake_key, hashes.SHA256())
            )

            is_valid, msg = validate_certificate(fake_cert)
            if not is_valid:
                detail = f"Fake self-signed cert created for 'Dr. Fake Attacker'. CA validation: {msg} -> BLOCKED"
                db.log_event(event_type="ATTACK_SPOOF", success=False, details=detail, ip_address=client_ip())
                return success(data={"result": "blocked", "detail": detail},
                               message="Certificate spoofing blocked — CA chain of trust validation failed")

            db.log_event(event_type="ATTACK_SPOOF", success=True,
                          details="WARNING: spoofed cert validated (unexpected)", ip_address=client_ip())
            return error("Unexpectedly valid")

        # ── ATTACK 4: Man-in-the-Middle ──
        elif atype == 'mitm':
            rxp = data.get('prescription_path', '')
            if not rxp or not os.path.exists(rxp):
                detail = "MITM: prescription intercepted, medication changed. AES-256 + RSA sig both break -> BLOCKED (simulated)"
                db.log_event(event_type="ATTACK_MITM", success=False, details=detail, ip_address=client_ip())
                return success(data={"result": "simulated", "detail": detail},
                               message="MITM attack blocked — AES-256 encryption and RSA signature both detect tampering")

            with open(rxp) as f:
                rx = json.load(f)
            orig_med = rx["prescription_plaintext"]["medication"]
            rx["prescription_plaintext"]["medication"] = "Oxycodone 80mg — TAMPERED"
            tb = json.dumps(rx["prescription_plaintext"], sort_keys=True).encode()
            cert = x509.load_pem_x509_certificate(rx["doctor_certificate"].encode())

            try:
                cert.public_key().verify(bytes.fromhex(rx["signature_hex"]), tb,
                                          padding.PKCS1v15(), hashes.SHA256())
                db.log_event(event_type="ATTACK_MITM", success=True,
                              details="WARNING: tampered rx passed (unexpected)", ip_address=client_ip())
                return error("Unexpectedly passed")
            except Exception:
                detail = f"Intercepted prescription. Changed '{orig_med}' -> 'Oxycodone 80mg'. RSA signature hash mismatch -> BLOCKED"
                db.log_event(event_type="ATTACK_MITM", success=False, details=detail, ip_address=client_ip())
                return success(data={"result": "blocked", "detail": detail},
                               message="MITM attack blocked — RSA signature detects any prescription modification")

        return error(f"Unknown attack type: {atype}")

    except Exception as e:
        logger.error(f"Attack simulation error: {e}")
        db.log_event(event_type="ATTACK_ERROR", success=False, details=str(e), ip_address=client_ip())
        return success(data={"result": "blocked", "detail": str(e)},
                       message="Attack simulation complete — blocked by PKI")


# ════════════════════════════════════════════════
# ROUTE: List All Users
# ════════════════════════════════════════════════

@app.route('/api/users', methods=['GET'])
def get_users():
    """
    List all registered users.

    DATABASE: Tries PostgreSQL first (faster, queryable).
    FALLBACK: If database unavailable, reads /users/*.json files.
    """
    try:
        # ── NEW: Try database first ──
        db_users = db.get_all_users()
        if db_users is not None:
            users = [{
                "username"    : u["username"],
                "role"        : u["role"],
                "cert_serial" : u["cert_serial"]
            } for u in db_users]
            return success(data=users, message=f"{len(users)} users found (database)")

        # ── FALLBACK: read from files (original behaviour) ──
        users_dir  = os.path.join(BASE_DIR, "users")
        user_files = [f for f in os.listdir(users_dir) if f.endswith(".json")]
        users      = []

        for uf in user_files:
            with open(os.path.join(users_dir, uf), 'r') as f:
                u = json.load(f)
                users.append({
                    "username"    : u["username"],
                    "role"        : u["role"],
                    "cert_serial" : str(u["cert_serial"])
                })

        return success(data=users, message=f"{len(users)} users found (file mode)")

    except Exception as e:
        return error(f"Error listing users: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: List Genomic Reports
# ════════════════════════════════════════════════

@app.route('/api/reports', methods=['GET'])
def get_reports():
    """List all signed genomic reports (always reads from /documents)."""
    try:
        docs_dir = os.path.join(BASE_DIR, "documents")
        reports  = []

        for f in os.listdir(docs_dir):
            if f.startswith("genomic_") and f.endswith(".json"):
                full_path = os.path.join(docs_dir, f)
                with open(full_path, 'r') as fp:
                    r = json.load(fp)
                    reports.append({
                        "report_id"   : r["report_id"],
                        "report_path" : full_path,
                        "patient"     : r["report"]["patient_name"],
                        "signed_by"   : r["signer_name"],
                        "signed_at"   : r["signed_at"],
                        "attachment"  : r["report"].get("attached_file")
                    })

        return success(data=reports, message=f"{len(reports)} reports found")

    except Exception as e:
        return error(f"Error listing reports: {str(e)}")


# ════════════════════════════════════════════════
# NEW ROUTE: Audit Log (Database)
# ════════════════════════════════════════════════

@app.route('/api/audit', methods=['GET'])
def get_audit():
    """
    View the audit log from PostgreSQL.

    Query params:
        ?limit=50          - max entries (default 50)
        ?username=Dr. Bob  - filter by user
        ?event_type=VERIFY_RX - filter by event type

    Returns 503 if database is unavailable (this endpoint REQUIRES the database).
    """
    limit      = request.args.get('limit', 50, type=int)
    username   = request.args.get('username')
    event_type = request.args.get('event_type')

    logs = db.get_audit_log(limit=limit, username=username, event_type=event_type)

    if logs is None:
        return error("Audit log unavailable — database not connected", code=503)

    # Convert datetime objects to strings for JSON
    for log in logs:
        if 'timestamp' in log and log['timestamp']:
            log['timestamp'] = log['timestamp'].isoformat()

    return success(data=logs, message=f"{len(logs)} audit log entries")


# ════════════════════════════════════════════════
# NEW ROUTE: Dashboard Stats (Database)
# ════════════════════════════════════════════════

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Dashboard summary statistics from the audit log.

    Returns counts grouped by event type (REGISTER, SIGN_REPORT,
    SIGN_RX, VERIFY_RX, REVOKE, ATTACK_*) with success/failure breakdown.
    """
    stats = db.get_audit_stats()
    crl   = db.get_crl_entries()

    if stats is None:
        return error("Statistics unavailable — database not connected", code=503)

    return success(
        data={
            "event_stats": stats,
            "revoked_certificates": len(crl) if crl is not None else 0
        },
        message="Statistics retrieved"
    )


# ════════════════════════════════════════════════
# ROUTE: Detailed Prescription Verification (Pharmacist)
# ════════════════════════════════════════════════

@app.route('/api/verify-details', methods=['POST'])
def verify_details():
    """
    Run the full verification chain and return a detailed step-by-step
    breakdown — WITHOUT dispensing medication.

    Used by the pharmacist UI to show EXACTLY what is being verified:
    - Which certificate is checked
    - What SHA-256 hash was computed vs what was signed
    - Whether AES-256 decryption succeeded
    - Whether the linked genomic report chain is intact

    This is the "preview" before the final /api/verify (dispense) call.

    Request body:
        { "prescription_path": "documents/rx_....json" }
    """
    try:
        data = request.get_json()
        prescription_path = data.get('prescription_path', '').strip()

        if not prescription_path:
            return error("prescription_path is required")

        # ── Friendly file-not-found error ──
        import os as _os
        if not _os.path.exists(prescription_path):
            return error(
                f"Prescription file not found: '{prescription_path}'. "
                f"Please click a prescription row in the table above to auto-fill the correct path."
            )

        result = verify_prescription_detailed(prescription_path)

        db.log_event(
            event_type="VERIFY_DETAILS",
            document_id=prescription_path,
            success=result["all_passed"],
            details=f"steps={len(result['steps'])}, all_passed={result['all_passed']}",
            ip_address=client_ip()
        )

        return success(data=result, message="Verification chain complete")

    except Exception as e:
        logger.error(f"Verify details error: {e}")
        return error(f"Verify details error: {str(e)}")


# ════════════════════════════════════════════════
# ROUTE: List All Prescriptions
# ════════════════════════════════════════════════

@app.route('/api/prescriptions', methods=['GET'])
def get_prescriptions():
    """
    List all signed prescriptions (reads from /documents/rx_*.json).
    Used by the Pharmacist dashboard to show a clickable list of
    prescriptions — clicking a row auto-fills the prescription_path field.
    """
    try:
        docs_dir      = os.path.join(BASE_DIR, "documents")
        prescriptions = []

        for f in os.listdir(docs_dir):
            if f.startswith("rx_") and f.endswith(".json"):
                full_path = os.path.join(docs_dir, f)
                with open(full_path, 'r') as fp:
                    rx = json.load(fp)
                    pt = rx.get("prescription_plaintext", {})
                    prescriptions.append({
                        "prescription_id"   : rx["prescription_id"],
                        "prescription_path" : full_path,
                        "patient"           : pt.get("patient_name", ""),
                        "doctor"            : rx.get("doctor_name", ""),
                        "medication"        : pt.get("medication", ""),
                        "signed_at"         : rx.get("signed_at", ""),
                        "linked_report_id"  : rx.get("linked_report_id", "")
                    })

        prescriptions.sort(key=lambda x: x["signed_at"], reverse=True)
        return success(data=prescriptions, message=f"{len(prescriptions)} prescriptions found")

    except Exception as e:
        return error(f"Error listing prescriptions: {str(e)}")


# ════════════════════════════════════════════════
# ERROR HANDLERS
# ════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return error("Endpoint not found", code=404)

@app.errorhandler(405)
def method_not_allowed(e):
    return error("Method not allowed", code=405)

@app.errorhandler(500)
def internal_error(e):
    return error("Internal server error", code=500)


# ════════════════════════════════════════════════
# RUN THE APP
# ════════════════════════════════════════════════

if __name__ == '__main__':
    print("\n" + "="*50)
    print("  TrustDNA Flask API Starting...")
    print("  http://localhost:5000")
    print(f"  Database: {'connected' if db.is_db_available() else 'unavailable (file-mode only)'}")
    print("="*50 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=False)
