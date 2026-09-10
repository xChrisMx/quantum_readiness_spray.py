#!/usr/bin/env python3
# =============================================================================
# quantum_readiness_spray.py
#
# AUTHORIZED INTERNAL SECURITY ASSESSMENT TOOL
# Scope: SSH (TCP/22), RDP (TCP/3389), and HTTPS/TLS (TCP/443) discovery and
#        quantum-readiness assessment on internal company networks.
#
# -----------------------------------------------------------------------------
# WHAT THIS SCRIPT DOES
# -----------------------------------------------------------------------------
# Phase 1 (Discovery): Uses masscan to rapidly identify hosts on the
#   configured internal subnets with TCP/22 (SSH), TCP/3389 (RDP), or
#   TCP/443 (HTTPS) open. Results are reverse-DNS resolved and mapped back
#   to the configured subnet that contains them, exactly as in
#   snmp_tftp_audit.py.
#
# Phase 2 (Assessment): For every host discovered in Phase 1:
#   - SSH: Uses `ssh-audit` (if present on PATH) to collect the server's
#     offered KEX/host-key/cipher/MAC algorithm lists; falls back to a
#     hand-rolled raw-socket probe (connect, exchange identification
#     strings, send our own SSH_MSG_KEXINIT, capture the server's
#     SSH_MSG_KEXINIT) if ssh-audit is unavailable or its output can't be
#     parsed. Either way, no authentication is ever attempted -- the
#     connection is closed immediately after the algorithm exchange, well
#     before any USERAUTH message would be sent.
#   - RDP: Performs the X.224 Connection Request/Confirm negotiation to
#     confirm whether the server upgrades to TLS (Enhanced RDP Security /
#     CredSSP), then sends a hand-built TLS 1.3 ClientHello to observe
#     what the server does at the record layer. No CredSSP/NLA
#     authentication is ever attempted and no credentials are ever sent.
#   - HTTPS: Sends the same hand-built TLS 1.3 ClientHello directly (no
#     X.224-style prefix needed for plain TLS), including the already
#     resolved hostname as SNI when one is available. No HTTP request is
#     ever sent and no certificate is validated -- the probe stops at the
#     ServerHello/HelloRetryRequest/Alert, before any application data.
#
# All three protocols are assessed by comparing what the server actually
# offers/negotiates against known post-quantum and hybrid post-quantum
# cryptographic identifiers, and are placed into one of five assessment
# categories (see CATEGORY DEFINITIONS below). These are OUR assessment
# buckets for this engagement, not official NIST labels.
#
# -----------------------------------------------------------------------------
# NON-DESTRUCTIVE / SAFETY GUARANTEES
# -----------------------------------------------------------------------------
# This script never authenticates and never completes a session:
#   - SSH: stops after reading the server's SSH_MSG_KEXINIT. No key
#     exchange is completed and no SSH_MSG_USERAUTH_* message is ever sent.
#   - RDP: stops after reading the server's first TLS response (ServerHello,
#     HelloRetryRequest, or Alert). No certificate is validated, no key
#     exchange is completed, and no CredSSP/NLA credential is ever sent.
#   - HTTPS: same stopping point as RDP's TLS step -- no certificate
#     validation, no completed key exchange, no HTTP request ever sent.
#   - No brute-forcing, no credential guessing, no data modification.
#
# THIS TOOL MUST ONLY BE RUN AGAINST NETWORKS YOU ARE EXPLICITLY AUTHORIZED
# TO ASSESS. Confirm written authorization / an active engagement scope
# before running this script.
#
# -----------------------------------------------------------------------------
# CATEGORY DEFINITIONS (assessment buckets, not official NIST terminology)
# -----------------------------------------------------------------------------
# READY             - Actual evidence of a post-quantum / hybrid algorithm
#                      being negotiated (SSH: our realistic modern-client
#                      preference order actually resolves to a PQC/hybrid
#                      KEX or host-key algorithm; RDP/HTTPS: the server's
#                      TLS 1.3 response selects, or issues a
#                      HelloRetryRequest requesting, a hybrid PQC group).
# CAPABLE           - The server's full advertised capability list contains
#                      a PQC/hybrid identifier, but it was NOT what actually
#                      got negotiated under a realistic client preference.
#                      SSH only: a TLS 1.3 server does not broadcast a full
#                      "supported but unused" group list the way SSH's
#                      KEXINIT does, so this category is expected to be rare
#                      to never trigger for RDP/HTTPS with current scanning
#                      techniques -- that is a limitation of what is
#                      observable on the wire, not evidence of absence.
# PLANNING REQUIRED - Modern classical cryptography only (curve25519/ECDHE,
#                      AES-GCM/ChaCha20, SHA-2, TLS 1.2/1.3). Good current
#                      security, not quantum-resistant.
# LEGACY            - Deprecated/weak cryptography detected (SSHv1-era KEX,
#                      CBC ciphers, RC4, 3DES, MD5/SHA-1 MACs, TLS 1.0/1.1,
#                      SSLv3, RDP "Standard RDP Security"). Takes priority
#                      over Planning Required -- remediate regardless of
#                      quantum posture.
# UNKNOWN           - Insufficient evidence (no response, connection
#                      refused, malformed/unparseable response).
#
# -----------------------------------------------------------------------------
# LIMITATIONS AND ASSUMPTIONS
# -----------------------------------------------------------------------------
#   - SSH "Ready"/"Planning Required"/"Legacy" are determined by applying
#     RFC 4253 negotiation rules (first client-preferred algorithm present
#     in the server's list wins) using a preference order representative of
#     a current, up-to-date OpenSSH client, with legacy algorithms placed
#     at the very bottom purely so a legacy-only server still yields a
#     determinate classification rather than "no data" -- a real hardened
#     client would omit those entirely and simply refuse to connect.
#   - RDP/HTTPS quantum-readiness detection is necessarily best-effort:
#     unlike SSH's KEXINIT, TLS does not broadcast an unused capability
#     list, so "Capable" cannot be reliably proven for RDP/HTTPS the way
#     it can for SSH. A "Planning Required" host may still run PQC-capable
#     software that simply wasn't selected under this probe's parameters.
#   - This tool requires `masscan` on PATH. `ssh-audit` is used as the
#     primary SSH collection method if present on PATH (recommended --
#     it's more robust than the raw-socket fallback), but the script is
#     fully functional without it. The `cryptography` Python package is
#     used only to generate one ephemeral X25519 keypair for the RDP/HTTPS
#     TLS ClientHello's key_share extension -- no ML-KEM/Kyber
#     implementation is needed client-side; PQC hybrid group support is
#     detected via HelloRetryRequest, not by completing a real PQC
#     handshake.
#   - No off-the-shelf TLS scanner (sslscan/sslyze/openssl s_client/etc.)
#     can drive the RDP probe directly: RDP requires its own X.224
#     Connection Request/Confirm negotiation on the TCP stream *before*
#     the server will speak TLS at all, and none of those tools know how
#     to send that RDP-specific prefix. The X.224 step and the TLS
#     ClientHello that follows it are therefore both hand-rolled here, on
#     the same socket, in sequence. HTTPS reuses the same hand-built TLS
#     ClientHello/response parsing directly (no X.224-style prefix needed),
#     so it could be pointed at a real TLS tool later if desired -- it
#     currently isn't, purely to keep one code path for all TLS-based
#     protocols in this script.
#   - Reverse DNS depends on corporate DNS infrastructure; failures resolve
#     to "UNKNOWN" and do not stop the scan.
#   - This tool does not assess any protocol besides SSH, RDP, and HTTPS.
# =============================================================================

import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))

# Same subnets in scope as snmp_tftp_audit.py. Edit this list to change scope.
SUBNETS: List[str] = [
    "156.141.0.0/16",
    "156.140.0.0/16",
    "146.208.0.0/16",
    "141.184.0.0/16",
    "141.183.0.0/16",
    # "141.121.0.0/16",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
]

DEFAULT_WORKERS = 30
DEFAULT_RATE = 25000
DEFAULT_TIMEOUT = 4.0        # seconds, per-probe timeout
DEFAULT_RETRIES = 1
MASSCAN_PORT_SPEC = "T:22,3389,443"
SSH_PORT = 22
RDP_PORT = 3389
HTTPS_PORT = 443

RATING_READY = "Ready"
RATING_CAPABLE = "Capable"
RATING_PLANNING = "Planning Required"
RATING_LEGACY = "Legacy"
RATING_UNKNOWN = "Unknown"
RATING_ORDER = [RATING_READY, RATING_CAPABLE, RATING_PLANNING, RATING_LEGACY, RATING_UNKNOWN]

RATING_EMOJI = {
    RATING_READY: "\U0001F7E2",       # green circle
    RATING_CAPABLE: "\U0001F7E1",     # yellow circle
    RATING_PLANNING: "\U0001F7E0",    # orange circle
    RATING_LEGACY: "\U0001F534",      # red circle
    RATING_UNKNOWN: "⚪",         # white circle
}

RATING_FILL_HEX = {
    RATING_READY: "C6EFCE",
    RATING_CAPABLE: "FFEB9C",
    RATING_PLANNING: "FCE4D6",
    RATING_LEGACY: "FFC7CE",
    RATING_UNKNOWN: "E7E6E6",
}

RATING_DESCRIPTION = {
    RATING_READY: (
        "The system is actively using post-quantum or hybrid cryptography. "
        "The scan found actual evidence of a PQC algorithm being negotiated "
        "in network communications (e.g. TLS 1.3 using hybrid X25519+ML-KEM, "
        "or SSH using an ML-KEM/NTRU-Prime hybrid key exchange)."
    ),
    RATING_CAPABLE: (
        "The system appears capable of supporting PQC, but the scan cannot "
        "prove it is actually being used. The server advertised a PQC/"
        "hybrid algorithm as available, but a realistic modern client "
        "negotiation still resolved to classical cryptography. Available "
        "does not equal enabled."
    ),
    RATING_PLANNING: (
        "The system is secure using today's cryptography (modern TLS/SSH, "
        "ECDHE/curve25519, AES-GCM/ChaCha20) but is not yet quantum-"
        "resistant. This is expected to be the most common category in an "
        "enterprise environment today."
    ),
    RATING_LEGACY: (
        "The system is using outdated or deprecated protocols/ciphers "
        "(e.g. SSHv1-era KEX, RC4, 3DES, CBC-mode ciphers, MD5/SHA-1 MACs, "
        "TLS 1.0/1.1, SSLv3, or RDP Standard Security) that should be "
        "remediated regardless of quantum posture. Legacy findings take "
        "priority over a plain Planning Required rating."
    ),
    RATING_UNKNOWN: (
        "Not enough evidence to make a reliable assessment (no response, "
        "connection refused, or an unparseable response). Unknown does "
        "NOT mean quantum-safe -- it means we don't have evidence either way."
    ),
}

# -----------------------------------------------------------------------------
# SSH: known algorithm identifiers
# -----------------------------------------------------------------------------

KNOWN_PQC_SSH_KEX: Dict[str, str] = {
    "sntrup761x25519-sha512@openssh.com": "Streamlined NTRU Prime 761 + X25519 hybrid KEX",
    "sntrup761x25519-sha512": "Streamlined NTRU Prime 761 + X25519 hybrid KEX",
    "mlkem768x25519-sha256": "ML-KEM-768 + X25519 hybrid KEX (NIST FIPS 203)",
    "mlkem1024nistp384-sha384": "ML-KEM-1024 + NIST P-384 hybrid KEX (NIST FIPS 203)",
    "mlkem768nistp256-sha256": "ML-KEM-768 + NIST P-256 hybrid KEX (NIST FIPS 203)",
}

# No PQC signature/host-key algorithm is standardized/deployed in OpenSSH as
# of this tool's authoring. Kept as a dict (rather than removed) so the same
# evaluation logic below picks up any future ML-DSA/SLH-DSA host key types
# without code changes -- just add entries here.
KNOWN_PQC_SSH_HOSTKEY: Dict[str, str] = {}

LEGACY_SSH_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}
LEGACY_SSH_HOSTKEY = {"ssh-rsa", "ssh-dss"}
LEGACY_SSH_CIPHER = {
    "3des-cbc", "des-cbc", "blowfish-cbc", "cast128-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se",
}
LEGACY_SSH_MAC = {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "none"}

# Preference order representing a current, up-to-date OpenSSH client.
# Legacy entries are appended at the bottom ONLY so a legacy-only server
# still yields a determinate negotiated result for classification -- a real
# hardened client would omit them and simply fail to connect.
CLIENT_KEX_PREFERENCE = [
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
]
CLIENT_HOSTKEY_PREFERENCE = [
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "ssh-dss",
]
CLIENT_CIPHER_PREFERENCE = [
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
    "aes256-cbc",
    "aes192-cbc",
    "aes128-cbc",
    "3des-cbc",
    "arcfour256",
    "arcfour128",
    "arcfour",
]
CLIENT_MAC_PREFERENCE = [
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-md5",
    "hmac-md5-96",
]

# -----------------------------------------------------------------------------
# RDP/TLS: known group/cipher/version identifiers
# -----------------------------------------------------------------------------

# TLS SupportedGroups codepoints. Hybrid PQC values verified against a local
# OpenSSL 3.5 build's actual wire bytes (X25519MLKEM768 = 0x11EC observed in
# both ClientHello.supported_groups and a completed ServerHello.key_share).
GROUP_X25519MLKEM768 = 0x11EC
GROUP_SECP256R1MLKEM768 = 0x11EB
GROUP_SECP384R1MLKEM1024 = 0x11ED
GROUP_X25519 = 0x001D
GROUP_SECP256R1 = 0x0017
GROUP_SECP384R1 = 0x0018

PQC_TLS_GROUPS = {GROUP_X25519MLKEM768, GROUP_SECP256R1MLKEM768, GROUP_SECP384R1MLKEM1024}

TLS_GROUP_NAMES = {
    GROUP_X25519MLKEM768: "X25519MLKEM768 (hybrid PQC: X25519 + ML-KEM-768)",
    GROUP_SECP256R1MLKEM768: "SecP256r1MLKEM768 (hybrid PQC: P-256 + ML-KEM-768)",
    GROUP_SECP384R1MLKEM1024: "SecP384r1MLKEM1024 (hybrid PQC: P-384 + ML-KEM-1024)",
    GROUP_X25519: "x25519",
    GROUP_SECP256R1: "secp256r1",
    GROUP_SECP384R1: "secp384r1",
}

# Bare algorithm name + plain-English description for the PQC groups only,
# used to populate the report's dedicated "Algorithm" / "Algorithm
# Description" columns (kept separate from TLS_GROUP_NAMES above, which is
# the combined "name (description)" string used inline in Evidence/Details).
PQC_TLS_GROUP_INFO: Dict[int, Tuple[str, str]] = {
    GROUP_X25519MLKEM768: ("X25519MLKEM768",
                           "Hybrid PQC key exchange: X25519 + ML-KEM-768 (TLS 1.3 supported_groups/key_share)"),
    GROUP_SECP256R1MLKEM768: ("SecP256r1MLKEM768",
                              "Hybrid PQC key exchange: NIST P-256 + ML-KEM-768 (TLS 1.3 supported_groups/key_share)"),
    GROUP_SECP384R1MLKEM1024: ("SecP384r1MLKEM1024",
                               "Hybrid PQC key exchange: NIST P-384 + ML-KEM-1024 (TLS 1.3 supported_groups/key_share)"),
}

TLS_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0x003C: "AES128-SHA256 (RSA key exchange)",
    0x002F: "AES128-SHA (RSA key exchange)",
    0x0035: "AES256-SHA (RSA key exchange)",
    0x000A: "3DES-EDE-CBC-SHA (legacy)",
    0x0005: "RC4-SHA (legacy)",
    0x0004: "RC4-MD5 (legacy)",
}
LEGACY_TLS_CIPHERS = {0x000A, 0x0005, 0x0004}

TLS_VERSION_NAMES = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0", 0x0300: "SSL 3.0"}
LEGACY_TLS_VERSIONS = {0x0301, 0x0302, 0x0300}

PHASE_A_CIPHERS = [0x1302, 0x1301, 0x1303]
PHASE_A_GROUPS = [GROUP_X25519MLKEM768, GROUP_SECP256R1MLKEM768, GROUP_SECP384R1MLKEM1024,
                   GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]
PHASE_B_CIPHERS = [0x1302, 0x1301, 0x1303,
                    0xC030, 0xC02C, 0xC02F, 0xC02B, 0xCCA8, 0xCCA9,
                    0x003C, 0x002F, 0x0035, 0x000A, 0x0005, 0x0004]
PHASE_B_GROUPS = [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]
SIGNATURE_ALGORITHMS = [0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
                         0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601]

# RFC 8446 section 4.1.3: SHA-256("HelloRetryRequest"), the fixed Random
# value that marks a ServerHello as actually being a HelloRetryRequest.
HRR_RANDOM_MAGIC = bytes([
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
])

RDP_PROTOCOL_SSL = 0x00000001
RDP_PROTOCOL_HYBRID = 0x00000002
RDP_PROTOCOL_HYBRID_EX = 0x00000008

# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class DiscoveredService:
    ip: str
    port: int
    service: str  # "SSH", "RDP", or "HTTPS"
    hostname: str = "UNKNOWN"
    subnet: str = "UNKNOWN"


@dataclass
class QCRecord:
    timestamp: str
    ip: str
    hostname: str
    subnet: str
    port: int
    protocol: str
    service: str
    rating: str
    evidence: str
    details: str
    algorithm: str = ""
    algorithm_description: str = ""
    scan_status: str = "Completed"


CSV_FIELDS = ["Timestamp", "IP Address", "Hostname", "Subnet Range", "Port",
              "Protocol", "Service", "QC Rating", "Evidence", "Details",
              "Algorithm", "Algorithm Description", "Scan Status"]


def record_to_row(r: QCRecord) -> Dict[str, str]:
    return {
        "Timestamp": r.timestamp, "IP Address": r.ip, "Hostname": r.hostname,
        "Subnet Range": r.subnet, "Port": r.port, "Protocol": r.protocol,
        "Service": r.service, "QC Rating": r.rating, "Evidence": r.evidence,
        "Details": r.details, "Algorithm": r.algorithm,
        "Algorithm Description": r.algorithm_description, "Scan Status": r.scan_status,
    }


# =============================================================================
# LOGGING / PROGRESS DISPLAY (mirrors snmp_tftp_audit.py)
# =============================================================================

_progress_lock = threading.Lock()
_last_progress_len = 0


class ProgressAwareHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        global _last_progress_len
        with _progress_lock:
            if _last_progress_len:
                sys.stdout.write("\r" + " " * _last_progress_len + "\r")
                sys.stdout.flush()
            super().emit(record)
            _last_progress_len = 0


def setup_logging(log_path: str) -> logging.Logger:
    logger = logging.getLogger("quantum_readiness_spray")
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    console_handler = ProgressAwareHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def draw_progress_line(line: str) -> None:
    global _last_progress_len
    with _progress_lock:
        pad = max(0, _last_progress_len - len(line))
        sys.stdout.write("\r" + line + (" " * pad))
        sys.stdout.flush()
        _last_progress_len = len(line)


def finish_progress_line() -> None:
    global _last_progress_len
    with _progress_lock:
        if _last_progress_len:
            sys.stdout.write("\n")
            sys.stdout.flush()
        _last_progress_len = 0


def fmt_elapsed(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def render_bar(pct: Optional[float], width: int = 30) -> str:
    if pct is None:
        return "[" + "-" * width + "]  n/a"
    pct = max(0.0, min(100.0, pct))
    filled = int(width * pct / 100.0)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {pct:5.1f}%"


# =============================================================================
# DEPENDENCY / VALIDATION HELPERS
# =============================================================================

def check_external_tool(name: str) -> Optional[str]:
    return shutil.which(name)


def validate_subnets(raw_subnets: List[str], logger: logging.Logger) -> List[ipaddress.IPv4Network]:
    networks = []
    for entry in raw_subnets:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            logger.error(f"Skipping invalid CIDR '{entry}': {exc}")
    return networks


def subnet_for_ip(ip: str, networks: List[ipaddress.IPv4Network]) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "UNKNOWN"
    for net in networks:
        if addr in net:
            return str(net)
    return "UNKNOWN"


def resolve_hostname(ip: str, timeout: float) -> str:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return "UNKNOWN"
    finally:
        socket.setdefaulttimeout(old_timeout)


# =============================================================================
# PHASE 1: MASSCAN DISCOVERY (same approach as snmp_tftp_audit.py)
# =============================================================================

class MasscanStatus:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.percent: Optional[float] = None
        self.eta: str = ""

    def update_from_line(self, line: str) -> None:
        m = re.search(r"(\d+(?:\.\d+)?)%\s+done", line)
        eta_m = re.search(r"done,\s*([\d:]+)\s*remaining", line)
        with self.lock:
            if m:
                try:
                    self.percent = float(m.group(1))
                except ValueError:
                    pass
            if eta_m:
                self.eta = eta_m.group(1)


def _masscan_stderr_reader(proc: subprocess.Popen, status: MasscanStatus) -> None:
    buf = b""
    stream = proc.stderr
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(256)
            if not chunk:
                break
            buf += chunk
            while True:
                idx_r = buf.find(b"\r")
                idx_n = buf.find(b"\n")
                candidates = [i for i in (idx_r, idx_n) if i != -1]
                if not candidates:
                    break
                idx = min(candidates)
                line = buf[:idx].decode(errors="ignore").strip()
                buf = buf[idx + 1:]
                if line:
                    status.update_from_line(line)
    except (ValueError, OSError):
        pass


def build_masscan_command(masscan_path: str, subnets: List[str], rate: int,
                           output_file: str, interface: Optional[str]) -> List[str]:
    cmd = [masscan_path, "-p", MASSCAN_PORT_SPEC, "--rate", str(rate), "-oL", output_file]
    if interface:
        cmd += ["-e", interface]
    cmd += subnets
    return cmd


def parse_masscan_list_output(path: str, start_offset: int = 0) -> Tuple[List[Tuple[str, int, str]], int]:
    records: List[Tuple[str, int, str]] = []
    if not os.path.exists(path):
        return records, start_offset
    with open(path, "rb") as f:
        f.seek(start_offset)
        chunk = f.read()
    if not chunk:
        return records, start_offset
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return records, start_offset
    usable, new_offset = chunk[:last_newline + 1], start_offset + last_newline + 1
    for raw_line in usable.split(b"\n"):
        line = raw_line.decode(errors="ignore").strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        status, proto, port_s, ip, _ts = parts[:5]
        if status != "open":
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        records.append((ip, port, proto))
    return records, new_offset


def run_masscan_phase1(masscan_path: str, subnets: List[str], rate: int,
                        output_file: str, interface: Optional[str],
                        logger: logging.Logger, stop_event: threading.Event
                        ) -> List[Tuple[str, int, str]]:
    cmd = build_masscan_command(masscan_path, subnets, rate, output_file, interface)
    logger.info("Phase 1 - DISCOVERY starting")
    logger.debug(f"Masscan command: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.error(f"masscan executable not found at '{masscan_path}'.")
        return []
    except PermissionError as exc:
        logger.error(f"Permission error launching masscan: {exc}. "
                      f"Masscan typically requires root/administrator privileges.")
        return []
    except OSError as exc:
        logger.error(f"Failed to launch masscan: {exc}")
        return []

    status = MasscanStatus()
    reader_thread = threading.Thread(target=_masscan_stderr_reader, args=(proc, status), daemon=True)
    reader_thread.start()

    start_time = time.time()
    ssh_count = 0
    rdp_count = 0
    https_count = 0
    offset = 0
    seen: set = set()

    try:
        while True:
            if stop_event.is_set():
                logger.warning("Interrupt received, terminating masscan...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break

            retcode = proc.poll()
            new_records, offset = parse_masscan_list_output(output_file, offset)
            for ip, port, proto in new_records:
                key = (ip, port)
                if key in seen:
                    continue
                seen.add(key)
                if port == SSH_PORT:
                    ssh_count += 1
                elif port == RDP_PORT:
                    rdp_count += 1
                elif port == HTTPS_PORT:
                    https_count += 1

            elapsed = time.time() - start_time
            with status.lock:
                pct = status.percent
                eta = status.eta

            total = ssh_count + rdp_count + https_count
            bar = render_bar(pct)
            eta_str = eta if eta else "n/a"
            line = (f"Phase 1 - DISCOVERY {bar} | SSH: {ssh_count} RDP: {rdp_count} "
                     f"HTTPS: {https_count} Total: {total} | Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta_str}")
            draw_progress_line(line)

            if retcode is not None:
                time.sleep(0.3)
                new_records, offset = parse_masscan_list_output(output_file, offset)
                for ip, port, proto in new_records:
                    key = (ip, port)
                    if key in seen:
                        continue
                    seen.add(key)
                    if port == SSH_PORT:
                        ssh_count += 1
                    elif port == RDP_PORT:
                        rdp_count += 1
                    elif port == HTTPS_PORT:
                        https_count += 1
                break
            time.sleep(0.5)
    finally:
        finish_progress_line()

    if proc.returncode not in (0, None) and not stop_event.is_set():
        logger.warning(f"masscan exited with return code {proc.returncode}. "
                        f"Results collected so far will still be used.")

    final_records, _ = parse_masscan_list_output(output_file, 0)
    logger.info(f"Phase 1 - DISCOVERY complete. SSH hits: {ssh_count}, "
                f"RDP hits: {rdp_count}, HTTPS hits: {https_count}, "
                f"elapsed: {fmt_elapsed(time.time() - start_time)}")
    return final_records


# =============================================================================
# PHASE 2: SSH QUANTUM-READINESS PROBE
# =============================================================================

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_name_list(buf: bytes, offset: int) -> Tuple[List[str], int]:
    length = struct.unpack("!I", buf[offset:offset + 4])[0]
    offset += 4
    raw = buf[offset:offset + length].decode("ascii", errors="ignore")
    offset += length
    return ([s for s in raw.split(",") if s], offset)


def _build_ssh_kexinit_packet() -> bytes:
    def name_list(items: List[str]) -> bytes:
        joined = ",".join(items).encode("ascii")
        return struct.pack("!I", len(joined)) + joined

    payload = bytes([20]) + os.urandom(16)
    payload += name_list(CLIENT_KEX_PREFERENCE)
    payload += name_list(CLIENT_HOSTKEY_PREFERENCE)
    payload += name_list(CLIENT_CIPHER_PREFERENCE)
    payload += name_list(CLIENT_CIPHER_PREFERENCE)
    payload += name_list(CLIENT_MAC_PREFERENCE)
    payload += name_list(CLIENT_MAC_PREFERENCE)
    payload += name_list(["none"])
    payload += name_list(["none"])
    payload += name_list([])
    payload += name_list([])
    payload += b"\x00"          # first_kex_packet_follows = false
    payload += struct.pack("!I", 0)  # reserved

    base = 1 + len(payload)  # padding_length byte + payload
    pad_len = 8 - ((4 + base) % 8)
    if pad_len < 4:
        pad_len += 8
    packet_length = base + pad_len
    return struct.pack("!I", packet_length) + struct.pack("!B", pad_len) + payload + os.urandom(pad_len)


def _read_ssh_binary_packet(sock: socket.socket) -> bytes:
    length = struct.unpack("!I", _recv_exact(sock, 4))[0]
    if length <= 0 or length > 262144:
        raise ValueError(f"Implausible SSH packet length {length}")
    rest = _recv_exact(sock, length)
    pad_len = rest[0]
    payload = rest[1:length - pad_len]
    return payload


def _negotiate(client_pref: List[str], server_list: List[str]) -> Optional[str]:
    server_set = set(server_list)
    for algo in client_pref:
        if algo in server_set:
            return algo
    return None


def _classify_ssh_algorithms(server_kex: List[str], server_hostkey: List[str],
                              server_cipher: List[str], server_mac: List[str],
                              source_tag: str) -> Tuple[str, str, str, str, str, str]:
    """Shared classification logic for both collection methods (ssh-audit
    and the raw-socket fallback). Applies RFC 4253 negotiation rules using
    CLIENT_*_PREFERENCE against whatever algorithm lists were collected.
    Returns (rating, evidence, details, algorithm, algorithm_description,
    scan_status)."""
    negotiated_kex = _negotiate(CLIENT_KEX_PREFERENCE, server_kex)
    negotiated_hostkey = _negotiate(CLIENT_HOSTKEY_PREFERENCE, server_hostkey)
    negotiated_cipher = _negotiate(CLIENT_CIPHER_PREFERENCE, server_cipher)
    negotiated_mac = _negotiate(CLIENT_MAC_PREFERENCE, server_mac)

    ready_evidence = []
    ready_algo, ready_desc = "", ""
    if negotiated_kex in KNOWN_PQC_SSH_KEX:
        ready_evidence.append(f"Negotiated KEX: {negotiated_kex} ({KNOWN_PQC_SSH_KEX[negotiated_kex]})")
        ready_algo, ready_desc = negotiated_kex, KNOWN_PQC_SSH_KEX[negotiated_kex]
    if negotiated_hostkey in KNOWN_PQC_SSH_HOSTKEY:
        ready_evidence.append(f"Negotiated host key: {negotiated_hostkey} "
                               f"({KNOWN_PQC_SSH_HOSTKEY[negotiated_hostkey]})")
        if not ready_algo:
            ready_algo, ready_desc = negotiated_hostkey, KNOWN_PQC_SSH_HOSTKEY[negotiated_hostkey]

    details = (f"[{source_tag}] Negotiated KEX={negotiated_kex or 'none'}, "
               f"HostKey={negotiated_hostkey or 'none'}, "
               f"Cipher={negotiated_cipher or 'none'}, MAC={negotiated_mac or 'none'}.")

    if ready_evidence:
        return RATING_READY, "; ".join(ready_evidence), details, ready_algo, ready_desc, "Completed"

    capable_evidence = []
    capable_algo, capable_desc = "", ""
    for name in server_kex:
        if name in KNOWN_PQC_SSH_KEX:
            capable_evidence.append(f"Offered KEX: {name} ({KNOWN_PQC_SSH_KEX[name]})")
            if not capable_algo:
                capable_algo, capable_desc = name, KNOWN_PQC_SSH_KEX[name]
    for name in server_hostkey:
        if name in KNOWN_PQC_SSH_HOSTKEY:
            capable_evidence.append(f"Offered host key: {name} ({KNOWN_PQC_SSH_HOSTKEY[name]})")
            if not capable_algo:
                capable_algo, capable_desc = name, KNOWN_PQC_SSH_HOSTKEY[name]
    if capable_evidence:
        return RATING_CAPABLE, "; ".join(capable_evidence), details, capable_algo, capable_desc, "Completed"

    legacy_hits = []
    if negotiated_kex in LEGACY_SSH_KEX:
        legacy_hits.append(f"legacy KEX {negotiated_kex}")
    if negotiated_hostkey in LEGACY_SSH_HOSTKEY:
        legacy_hits.append(f"legacy host key {negotiated_hostkey}")
    if negotiated_cipher in LEGACY_SSH_CIPHER:
        legacy_hits.append(f"legacy cipher {negotiated_cipher}")
    if negotiated_mac in LEGACY_SSH_MAC:
        legacy_hits.append(f"legacy MAC {negotiated_mac}")
    if legacy_hits:
        return (RATING_LEGACY, "", "Legacy algorithm(s) negotiated: " + ", ".join(legacy_hits) + ". " + details,
                "", "", "Completed")

    if negotiated_kex or negotiated_hostkey or negotiated_cipher or negotiated_mac:
        return RATING_PLANNING, "", details, "", "", "Completed"

    return RATING_UNKNOWN, "", "No mutually supported algorithms found. " + details, "", "", "No Response"


def _run_ssh_audit_json(ssh_audit_path: str, ip: str, port: int, timeout: float) -> Optional[dict]:
    try:
        result = subprocess.run(
            [ssh_audit_path, "-j", "-p", str(port), ip],
            capture_output=True, text=True, timeout=timeout + 20)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if not result.stdout or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def probe_ssh_via_ssh_audit(ip: str, port: int, timeout: float,
                             ssh_audit_path: str) -> Optional[Tuple[str, str, str, str, str, str]]:
    """Uses the `ssh-audit` tool to collect the server's offered algorithm
    lists (schema: top-level "kex"/"key"/"enc"/"mac" arrays of {"algorithm":
    ...}), then applies our own classification on top. Returns None if the
    tool is missing, times out, or its output doesn't match the expected
    schema -- callers should fall back to the raw-socket probe in that case.
    """
    data = _run_ssh_audit_json(ssh_audit_path, ip, port, timeout)
    if not data:
        return None
    try:
        server_kex = [e["algorithm"] for e in data.get("kex", []) if e.get("algorithm")]
        server_hostkey = [e["algorithm"] for e in data.get("key", []) if e.get("algorithm")]
        server_cipher = [e["algorithm"] for e in data.get("enc", []) if e.get("algorithm")]
        server_mac = [e["algorithm"] for e in data.get("mac", []) if e.get("algorithm")]
    except (AttributeError, TypeError, KeyError):
        return None
    if not server_kex or not server_hostkey:
        return None
    return _classify_ssh_algorithms(server_kex, server_hostkey, server_cipher, server_mac, "ssh-audit")


def probe_ssh_raw(ip: str, port: int, timeout: float) -> Tuple[str, str, str, str, str, str]:
    """Hand-rolled raw-socket fallback: connects, exchanges identification
    strings, sends our own SSH_MSG_KEXINIT, and captures the server's
    SSH_MSG_KEXINIT directly. Used when ssh-audit is unavailable or its
    output could not be parsed. Returns (rating, evidence, details, algorithm,
    algorithm_description, scan_status)."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Version exchange -- read lines until we see the SSH identification
        # string (servers may send preceding banner lines per RFC 4253).
        buf = b""
        banner = None
        for _ in range(20):
            chunk = sock.recv(256)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buf = rest
                if line.strip().startswith(b"SSH-"):
                    banner = line.strip().decode(errors="ignore")
                    break
        if banner is None:
            return RATING_UNKNOWN, "", "No SSH identification string received.", "", "", "No Response"

        sock.sendall(b"SSH-2.0-QuantumReadinessAudit_1.0\r\n")
        sock.sendall(_build_ssh_kexinit_packet())

        kexinit_payload = None
        for _ in range(5):
            payload = _read_ssh_binary_packet(sock)
            if payload and payload[0] == 20:
                kexinit_payload = payload
                break
        if kexinit_payload is None:
            return RATING_UNKNOWN, "", "Server did not send SSH_MSG_KEXINIT.", "", "", "No Response"

        off = 1 + 16  # msg type + cookie
        server_kex, off = _read_name_list(kexinit_payload, off)
        server_hostkey, off = _read_name_list(kexinit_payload, off)
        server_cipher_c2s, off = _read_name_list(kexinit_payload, off)
        _server_cipher_s2c, off = _read_name_list(kexinit_payload, off)
        server_mac_c2s, off = _read_name_list(kexinit_payload, off)

        return _classify_ssh_algorithms(server_kex, server_hostkey, server_cipher_c2s,
                                         server_mac_c2s, "raw-probe")

    except socket.timeout:
        return RATING_UNKNOWN, "", "Connection/read timed out.", "", "", "No Response"
    except ConnectionRefusedError:
        return RATING_UNKNOWN, "", "Connection refused.", "", "", "No Response"
    except (OSError, ConnectionError, struct.error, ValueError, UnicodeDecodeError) as exc:
        return RATING_UNKNOWN, "", f"Error during SSH probe: {exc}", "", "", "Error"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_ssh(ip: str, port: int, timeout: float, ssh_audit_path: str) -> Tuple[str, str, str, str, str, str]:
    """Returns (rating, evidence, details, algorithm, algorithm_description,
    scan_status). Prefers ssh-audit (more robust, battle-tested KEXINIT
    collection); falls back to the hand-rolled raw-socket probe if ssh-audit
    is unavailable or unparseable."""
    if ssh_audit_path:
        result = probe_ssh_via_ssh_audit(ip, port, timeout, ssh_audit_path)
        if result is not None:
            return result
    return probe_ssh_raw(ip, port, timeout)


# =============================================================================
# PHASE 2: RDP QUANTUM-READINESS PROBE
# =============================================================================

def _x224_connection_request() -> bytes:
    neg_req = struct.pack("<BBHI", 0x01, 0x00, 0x08,
                           RDP_PROTOCOL_SSL | RDP_PROTOCOL_HYBRID | RDP_PROTOCOL_HYBRID_EX)
    x224 = bytes([0xE0]) + b"\x00\x00" + b"\x00\x00" + b"\x00" + neg_req
    tpdu = bytes([len(x224)]) + x224
    tpkt_len = 4 + len(tpdu)
    return struct.pack("!BBH", 0x03, 0x00, tpkt_len) + tpdu


def _read_tpkt_pdu(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    if header[0] != 0x03:
        raise ValueError(f"Unexpected TPKT version byte {header[0]:#x}")
    total_len = struct.unpack("!H", header[2:4])[0]
    if total_len < 4:
        raise ValueError(f"Implausible TPKT length {total_len}")
    return _recv_exact(sock, total_len - 4)


def x224_negotiate(sock: socket.socket) -> Tuple[Optional[int], Optional[int]]:
    """Returns (selected_protocol, failure_code). Both None means the server
    responded with a bare CC and no RDP negotiation structure at all (very
    old server -- implies Standard RDP Security)."""
    sock.sendall(_x224_connection_request())
    tpdu = _read_tpkt_pdu(sock)
    # Fixed X.224 CC header: li(1) + cdt(1) + dst_ref(2) + src_ref(2) +
    # class_option(1) = 7 bytes, before any RDP_NEG_RSP/FAILURE data.
    if len(tpdu) < 7 or tpdu[1] != 0xD0:
        raise ValueError("Did not receive a valid X.224 Connection Confirm")
    remainder = tpdu[7:]
    if len(remainder) < 8:
        return None, None
    neg_type = remainder[0]
    value = struct.unpack("<I", remainder[4:8])[0]
    if neg_type == 0x02:
        return value, None
    if neg_type == 0x03:
        return None, value
    return None, None


def _tls_ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def _sni_ext(server_name: str) -> bytes:
    """RFC 6066 server_name extension for a single DNS hostname entry."""
    name_bytes = server_name.encode("ascii", errors="ignore")
    entry = b"\x00" + struct.pack("!H", len(name_bytes)) + name_bytes  # name_type=0 (host_name)
    list_body = struct.pack("!H", len(entry)) + entry
    return _tls_ext(0x0000, list_body)


def _build_client_hello(versions: List[int], groups: List[int], ciphers: List[int],
                         x25519_pub: bytes, server_name: Optional[str] = None) -> bytes:
    session_id = os.urandom(32)
    random32 = os.urandom(32)
    body = b"\x03\x03" + random32 + bytes([len(session_id)]) + session_id
    cs = b"".join(struct.pack("!H", c) for c in ciphers)
    body += struct.pack("!H", len(cs)) + cs
    body += b"\x01\x00"  # compression methods: length 1, null

    ver_body = bytes([len(versions) * 2]) + b"".join(struct.pack("!H", v) for v in versions)
    grp_inner = b"".join(struct.pack("!H", g) for g in groups)
    grp_body = struct.pack("!H", len(grp_inner)) + grp_inner
    sig_inner = b"".join(struct.pack("!H", s) for s in SIGNATURE_ALGORITHMS)
    sig_body = struct.pack("!H", len(sig_inner)) + sig_inner
    ks_entry = struct.pack("!H", GROUP_X25519) + struct.pack("!H", len(x25519_pub)) + x25519_pub
    ks_body = struct.pack("!H", len(ks_entry)) + ks_entry

    exts = (_tls_ext(0x002B, ver_body) + _tls_ext(0x000A, grp_body) +
            _tls_ext(0x000D, sig_body) + _tls_ext(0x0033, ks_body))
    if server_name:
        exts += _sni_ext(server_name)
    body += struct.pack("!H", len(exts)) + exts

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _read_tls_record(sock: socket.socket) -> Tuple[int, bytes]:
    header = _recv_exact(sock, 5)
    rtype = header[0]
    length = struct.unpack("!H", header[3:5])[0]
    payload = _recv_exact(sock, length)
    return rtype, payload


def _parse_server_hello(hbody: bytes) -> Dict:
    result: Dict = {"is_hrr": False, "version": None, "cipher": None, "group": None}
    result["version"] = struct.unpack("!H", hbody[0:2])[0]
    random32 = hbody[2:34]
    result["is_hrr"] = (random32 == HRR_RANDOM_MAGIC)
    idx = 34
    sid_len = hbody[idx]
    idx += 1 + sid_len
    result["cipher"] = struct.unpack("!H", hbody[idx:idx + 2])[0]
    idx += 2
    idx += 1  # compression method
    if idx + 2 > len(hbody):
        return result
    ext_total_len = struct.unpack("!H", hbody[idx:idx + 2])[0]
    idx += 2
    ext_data = hbody[idx:idx + ext_total_len]
    pos = 0
    while pos + 4 <= len(ext_data):
        etype, elen = struct.unpack("!HH", ext_data[pos:pos + 4])
        ebody = ext_data[pos + 4:pos + 4 + elen]
        pos += 4 + elen
        if etype == 0x002B and len(ebody) >= 2:
            result["version"] = struct.unpack("!H", ebody[0:2])[0]
        elif etype == 0x0033:
            if result["is_hrr"]:
                if len(ebody) >= 2:
                    result["group"] = struct.unpack("!H", ebody[0:2])[0]
            else:
                if len(ebody) >= 2:
                    result["group"] = struct.unpack("!H", ebody[0:2])[0]
    return result


def _generate_x25519_pub() -> bytes:
    priv = x25519.X25519PrivateKey.generate()
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _tls_probe(sock: socket.socket, versions: List[int], groups: List[int],
                ciphers: List[int], x25519_pub: bytes,
                server_name: Optional[str] = None) -> Dict:
    """Sends one ClientHello on an already-connected socket (post-X.224 for
    RDP, or immediately after connect for plain TLS/HTTPS) and classifies
    the response. Returns a dict with keys: outcome
    ('ready'|'planning'|'legacy'|'failed'), evidence, details, algorithm,
    algorithm_description (the latter two only populated for 'ready')."""
    sock.sendall(_build_client_hello(versions, groups, ciphers, x25519_pub, server_name))
    rtype, payload = _read_tls_record(sock)

    if rtype == 0x15:  # Alert
        level = payload[0] if len(payload) > 0 else -1
        desc = payload[1] if len(payload) > 1 else -1
        return {"outcome": "failed", "evidence": "", "details": f"TLS alert (level={level}, description={desc})."}

    if rtype != 0x16:
        return {"outcome": "failed", "evidence": "", "details": f"Unexpected TLS record type {rtype:#x}."}

    htype = payload[0]
    if htype != 0x02:  # not ServerHello/HRR
        return {"outcome": "failed", "evidence": "", "details": f"Unexpected handshake type {htype:#x}."}

    hlen = int.from_bytes(payload[1:4], "big")
    hbody = payload[4:4 + hlen]
    info = _parse_server_hello(hbody)
    version_name = TLS_VERSION_NAMES.get(info["version"], f"0x{info['version']:04x}" if info["version"] else "unknown")
    cipher_name = TLS_CIPHER_NAMES.get(info["cipher"], f"0x{info['cipher']:04x}" if info["cipher"] else "unknown")

    if info["is_hrr"]:
        group = info["group"]
        group_name = TLS_GROUP_NAMES.get(group, f"0x{group:04x}" if group else "unknown")
        if group in PQC_TLS_GROUPS:
            algo, desc = PQC_TLS_GROUP_INFO.get(group, (group_name, ""))
            return {"outcome": "ready",
                     "evidence": f"TLS 1.3 HelloRetryRequest requested hybrid PQC group {group_name}.",
                     "details": f"Server prefers {group_name} over the classical group offered in our ClientHello.",
                     "algorithm": algo, "algorithm_description": desc}
        return {"outcome": "planning", "evidence": "",
                 "details": f"TLS 1.3 HelloRetryRequest requested classical group {group_name}.",
                 "algorithm": "", "algorithm_description": ""}

    group = info["group"]
    group_name = TLS_GROUP_NAMES.get(group, f"0x{group:04x}" if group else "none")
    if group in PQC_TLS_GROUPS:
        algo, desc = PQC_TLS_GROUP_INFO.get(group, (group_name, ""))
        return {"outcome": "ready",
                 "evidence": f"TLS handshake completed key_share using hybrid PQC group {group_name} "
                             f"({version_name}, {cipher_name}).",
                 "details": f"{version_name}, cipher {cipher_name}, group {group_name}.",
                 "algorithm": algo, "algorithm_description": desc}

    if info["version"] in LEGACY_TLS_VERSIONS or info["cipher"] in LEGACY_TLS_CIPHERS:
        bits = []
        if info["version"] in LEGACY_TLS_VERSIONS:
            bits.append(f"legacy TLS version {version_name}")
        if info["cipher"] in LEGACY_TLS_CIPHERS:
            bits.append(f"legacy cipher {cipher_name}")
        return {"outcome": "legacy", "evidence": "", "details": "; ".join(bits) + ".",
                 "algorithm": "", "algorithm_description": ""}

    return {"outcome": "planning", "evidence": "",
             "details": f"{version_name} negotiated, cipher {cipher_name}, group {group_name}.",
             "algorithm": "", "algorithm_description": ""}


def probe_rdp(ip: str, port: int, timeout: float) -> Tuple[str, str, str, str, str, str]:
    """Returns (rating, evidence, details, algorithm, algorithm_description,
    scan_status)."""
    if not _HAVE_CRYPTOGRAPHY:
        return (RATING_UNKNOWN, "", "The 'cryptography' package is not installed; RDP TLS probing skipped.",
                "", "", "Tool Missing")

    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        selected_protocol, failure_code = x224_negotiate(sock)

        if selected_protocol is None:
            if failure_code is not None:
                return RATING_LEGACY, "", f"RDP_NEG_FAILURE returned (code {failure_code}).", "", "", "Completed"
            return (RATING_LEGACY, "", "Server did not negotiate Enhanced RDP Security; implies legacy "
                    "Standard RDP Security.", "", "", "Completed")

        if selected_protocol == 0:
            return (RATING_LEGACY, "", "Server selected Standard RDP Security (legacy, non-TLS RC4-based "
                    "encryption).", "", "", "Completed")

        x25519_pub = _generate_x25519_pub()
        result = _tls_probe(sock, [0x0304], PHASE_A_GROUPS, PHASE_A_CIPHERS, x25519_pub)

        if result["outcome"] == "ready":
            return (RATING_READY, result["evidence"], result["details"],
                    result["algorithm"], result["algorithm_description"], "Completed")
        if result["outcome"] == "planning":
            return RATING_PLANNING, "", result["details"], "", "", "Completed"
        if result["outcome"] == "legacy":
            return RATING_LEGACY, "", result["details"], "", "", "Completed"

        # Phase A failed (alert/parse issue) -- fall back on a fresh
        # connection with a broader, more permissive ClientHello to
        # establish a classical baseline (Planning Required vs Legacy).
        phase_a_details = result["details"]
        try:
            sock.close()
        except OSError:
            pass
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        selected_protocol2, _failure_code2 = x224_negotiate(sock)
        if selected_protocol2 is None or selected_protocol2 == 0:
            return (RATING_LEGACY, "", "Standard RDP Security negotiated on fallback attempt.",
                    "", "", "Completed")

        x25519_pub2 = _generate_x25519_pub()
        result2 = _tls_probe(sock, [0x0304, 0x0303, 0x0302, 0x0301], PHASE_B_GROUPS,
                              PHASE_B_CIPHERS, x25519_pub2)
        if result2["outcome"] == "ready":
            return (RATING_READY, result2["evidence"], result2["details"],
                    result2["algorithm"], result2["algorithm_description"], "Completed")
        if result2["outcome"] == "planning":
            return RATING_PLANNING, "", result2["details"], "", "", "Completed"
        if result2["outcome"] == "legacy":
            return RATING_LEGACY, "", result2["details"], "", "", "Completed"

        return (RATING_UNKNOWN, "", (f"TLS negotiation inconclusive. Phase A: {phase_a_details} "
                                     f"Phase B: {result2['details']}"), "", "", "No Response")

    except socket.timeout:
        return RATING_UNKNOWN, "", "Connection/read timed out.", "", "", "No Response"
    except ConnectionRefusedError:
        return RATING_UNKNOWN, "", "Connection refused.", "", "", "No Response"
    except (OSError, ConnectionError, struct.error, ValueError, IndexError) as exc:
        return RATING_UNKNOWN, "", f"Error during RDP probe: {exc}", "", "", "Error"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# =============================================================================
# PHASE 2: HTTPS/TLS QUANTUM-READINESS PROBE
# =============================================================================

def probe_https(ip: str, port: int, timeout: float, hostname: str) -> Tuple[str, str, str, str, str, str]:
    """Same TLS 1.3 ClientHello/HelloRetryRequest technique as probe_rdp,
    minus the X.224 prefix -- HTTPS speaks TLS immediately on connect.
    Sends the already-resolved hostname as SNI when one is available, since
    a realistic client always would and some SNI-routed load balancers/CDNs
    behave differently without it. Returns (rating, evidence, details,
    algorithm, algorithm_description, scan_status)."""
    if not _HAVE_CRYPTOGRAPHY:
        return (RATING_UNKNOWN, "", "The 'cryptography' package is not installed; HTTPS TLS probing skipped.",
                "", "", "Tool Missing")

    sni = hostname if hostname and hostname != "UNKNOWN" else None
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        x25519_pub = _generate_x25519_pub()
        result = _tls_probe(sock, [0x0304], PHASE_A_GROUPS, PHASE_A_CIPHERS, x25519_pub, server_name=sni)

        if result["outcome"] == "ready":
            return (RATING_READY, result["evidence"], result["details"],
                    result["algorithm"], result["algorithm_description"], "Completed")
        if result["outcome"] == "planning":
            return RATING_PLANNING, "", result["details"], "", "", "Completed"
        if result["outcome"] == "legacy":
            return RATING_LEGACY, "", result["details"], "", "", "Completed"

        # Phase A failed (alert/parse issue) -- fall back on a fresh
        # connection with a broader, more permissive ClientHello to
        # establish a classical baseline (Planning Required vs Legacy).
        phase_a_details = result["details"]
        try:
            sock.close()
        except OSError:
            pass
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        x25519_pub2 = _generate_x25519_pub()
        result2 = _tls_probe(sock, [0x0304, 0x0303, 0x0302, 0x0301], PHASE_B_GROUPS,
                              PHASE_B_CIPHERS, x25519_pub2, server_name=sni)
        if result2["outcome"] == "ready":
            return (RATING_READY, result2["evidence"], result2["details"],
                    result2["algorithm"], result2["algorithm_description"], "Completed")
        if result2["outcome"] == "planning":
            return RATING_PLANNING, "", result2["details"], "", "", "Completed"
        if result2["outcome"] == "legacy":
            return RATING_LEGACY, "", result2["details"], "", "", "Completed"

        return (RATING_UNKNOWN, "", (f"TLS negotiation inconclusive. Phase A: {phase_a_details} "
                                     f"Phase B: {result2['details']}"), "", "", "No Response")

    except socket.timeout:
        return RATING_UNKNOWN, "", "Connection/read timed out.", "", "", "No Response"
    except ConnectionRefusedError:
        return RATING_UNKNOWN, "", "Connection refused.", "", "", "No Response"
    except (OSError, ConnectionError, struct.error, ValueError, IndexError) as exc:
        return RATING_UNKNOWN, "", f"Error during HTTPS probe: {exc}", "", "", "Error"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# =============================================================================
# PHASE 2 ORCHESTRATION
# =============================================================================

@dataclass
class Phase2Stats:
    lock: threading.Lock = field(default_factory=threading.Lock)
    total: int = 0
    completed: int = 0
    ssh_total: int = 0
    ssh_completed: int = 0
    rdp_total: int = 0
    rdp_completed: int = 0
    https_total: int = 0
    https_completed: int = 0
    active_workers: int = 0
    rating_counts: Dict[str, int] = field(default_factory=lambda: {r: 0 for r in RATING_ORDER})


def audit_one_service(svc: DiscoveredService, args: argparse.Namespace) -> QCRecord:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rating, evidence, details, algorithm, algorithm_description, status = RATING_UNKNOWN, "", "", "", "", "No Response"
    # Only "No Response" (timeout/refused/no banner) is worth retrying -- it's
    # the one outcome that plausibly reflects transient packet loss during a
    # large sweep rather than a deterministic property of the host. Retrying
    # "Error"/"Tool Missing" would just waste time for the same result.
    for _attempt in range(max(1, args.retries + 1)):
        try:
            if svc.service == "SSH":
                rating, evidence, details, algorithm, algorithm_description, status = probe_ssh(
                    svc.ip, svc.port, args.timeout, args.ssh_audit_path)
            elif svc.service == "RDP":
                rating, evidence, details, algorithm, algorithm_description, status = probe_rdp(
                    svc.ip, svc.port, args.timeout)
            else:
                rating, evidence, details, algorithm, algorithm_description, status = probe_https(
                    svc.ip, svc.port, args.timeout, svc.hostname)
        except Exception as exc:  # noqa: BLE001 - one bad host must not kill the scan
            rating, evidence, details, algorithm, algorithm_description, status = (
                RATING_UNKNOWN, "", f"Unhandled error: {exc}", "", "", "Error")
        if status != "No Response":
            break
    return QCRecord(timestamp=ts, ip=svc.ip, hostname=svc.hostname, subnet=svc.subnet,
                     port=svc.port, protocol="TCP", service=svc.service, rating=rating,
                     evidence=evidence, details=details, algorithm=algorithm,
                     algorithm_description=algorithm_description, scan_status=status)


def render_phase2_line(stats: Phase2Stats, start_time: float) -> str:
    with stats.lock:
        completed = stats.completed
        total = stats.total
        pct = (completed / total * 100.0) if total else 0.0
        rc = dict(stats.rating_counts)
        active = stats.active_workers
        ssh_c, ssh_t = stats.ssh_completed, stats.ssh_total
        rdp_c, rdp_t = stats.rdp_completed, stats.rdp_total
        https_c, https_t = stats.https_completed, stats.https_total

    elapsed = time.time() - start_time
    if 0 < completed < total:
        eta = fmt_elapsed((elapsed / completed) * (total - completed))
    elif completed >= total and total > 0:
        eta = "00:00:00"
    else:
        eta = "n/a"

    bar = render_bar(pct)
    return (f"Phase 2 - QUANTUM AUDIT {bar} | Completed: {completed}/{total} | "
            f"Workers: {active} | SSH: {ssh_c}/{ssh_t} | RDP: {rdp_c}/{rdp_t} | "
            f"HTTPS: {https_c}/{https_t} | "
            f"Ready:{rc[RATING_READY]} Capable:{rc[RATING_CAPABLE]} "
            f"Planning:{rc[RATING_PLANNING]} Legacy:{rc[RATING_LEGACY]} "
            f"Unknown:{rc[RATING_UNKNOWN]} | Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta}")


def run_phase2(services: List[DiscoveredService], args: argparse.Namespace,
               logger: logging.Logger, stop_event: threading.Event) -> List[QCRecord]:
    stats = Phase2Stats()
    stats.total = len(services)
    stats.ssh_total = sum(1 for s in services if s.service == "SSH")
    stats.rdp_total = sum(1 for s in services if s.service == "RDP")
    stats.https_total = sum(1 for s in services if s.service == "HTTPS")

    records: List[QCRecord] = []
    start_time = time.time()
    logger.info(f"Phase 2 - QUANTUM AUDIT starting ({stats.total} services, {args.workers} workers)")

    def wrapped(svc: DiscoveredService) -> Tuple[DiscoveredService, QCRecord]:
        with stats.lock:
            stats.active_workers += 1
        try:
            result = audit_one_service(svc, args)
        finally:
            with stats.lock:
                stats.active_workers -= 1
        return svc, result

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = [executor.submit(wrapped, svc) for svc in services]
        try:
            for future in as_completed(futures):
                svc, record = future.result()
                records.append(record)
                with stats.lock:
                    stats.completed += 1
                    if svc.service == "SSH":
                        stats.ssh_completed += 1
                    elif svc.service == "RDP":
                        stats.rdp_completed += 1
                    else:
                        stats.https_completed += 1
                    stats.rating_counts[record.rating] += 1
                draw_progress_line(render_phase2_line(stats, start_time))
                if stop_event.is_set():
                    logger.warning("Interrupt received, cancelling remaining audits...")
                    for f in futures:
                        f.cancel()
                    break
        finally:
            finish_progress_line()

    logger.info(f"Phase 2 - QUANTUM AUDIT complete. {stats.completed}/{stats.total} "
                f"audits finished in {fmt_elapsed(time.time() - start_time)}.")
    return records


# =============================================================================
# REPORT GENERATION
# =============================================================================

def write_csv_report(records: List[QCRecord], path: str, logger: logging.Logger) -> None:
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for record in records:
                writer.writerow(record_to_row(record))
        logger.info(f"CSV report written to {path}")
    except OSError as exc:
        logger.error(f"Failed to write CSV report to {path}: {exc}")


def compute_rating_stats(records: List[QCRecord]) -> Dict[str, int]:
    counts = {r: 0 for r in RATING_ORDER}
    for rec in records:
        counts[rec.rating] += 1
    return counts


def write_xlsx_report(ssh_records: List[QCRecord], rdp_records: List[QCRecord],
                       https_records: List[QCRecord],
                       networks: List[ipaddress.IPv4Network], path: str,
                       logger: logging.Logger) -> None:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.utils import get_column_letter
    except ImportError:
        logger.error("openpyxl is not installed; skipping XLSX report. "
                      "Install with: python3 -m pip install openpyxl")
        return

    def style_service_sheet(ws, records: List[QCRecord]) -> None:
        ws.append(CSV_FIELDS)
        for cell in ws[1]:
            cell.font = Font(bold=True)
        ws.freeze_panes = "A2"
        rating_col = CSV_FIELDS.index("QC Rating") + 1
        wrap_cols = [CSV_FIELDS.index(c) + 1 for c in ("Evidence", "Details", "Algorithm Description")]
        for record in records:
            row = record_to_row(record)
            ws.append([row[col] for col in CSV_FIELDS])
            cell = ws.cell(row=ws.max_row, column=rating_col)
            cell.value = f"{RATING_EMOJI[record.rating]} {record.rating}"
            cell.fill = PatternFill("solid", fgColor=RATING_FILL_HEX[record.rating])
            for col in wrap_cols:
                ws.cell(row=ws.max_row, column=col).alignment = Alignment(wrap_text=True, vertical="top")
            ws.row_dimensions[ws.max_row].height = 45
        if records:
            ws.auto_filter.ref = f"A1:{get_column_letter(len(CSV_FIELDS))}{len(records) + 1}"
        widths = {"Timestamp": 20, "IP Address": 16, "Hostname": 30, "Subnet Range": 18,
                  "Port": 8, "Protocol": 10, "Service": 10, "QC Rating": 20,
                  "Evidence": 60, "Details": 60, "Algorithm": 30,
                  "Algorithm Description": 50, "Scan Status": 14}
        for i, col in enumerate(CSV_FIELDS, start=1):
            ws.column_dimensions[get_column_letter(i)].width = widths.get(col, 16)

    try:
        wb = Workbook()

        # --- Overview sheet ---
        ov = wb.active
        ov.title = "Overview"
        ov.column_dimensions["A"].width = 30
        ov.column_dimensions["B"].width = 70
        ov.column_dimensions["C"].width = 14
        ov.column_dimensions["D"].width = 14

        ov.append(["Quantum Readiness Assessment -- SSH, RDP & HTTPS"])
        ov["A1"].font = Font(bold=True, size=14)
        ov.append([f"Scan date: {datetime.now().strftime('%Y-%m-%d')}"])
        ov.append([f"Configured subnets in scope: {len(networks)}"])
        ov.append([])
        ov.append(["How to read this report"])
        ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
        ov.append(["These are our assessment categories for this engagement, not official NIST labels. "
                    "They describe how prepared a system is for the eventual threat of cryptographically "
                    "relevant quantum computers."])
        ov.append([])
        ov.append(["Rating", "What it means"])
        for cell in ov[ov.max_row]:
            cell.font = Font(bold=True)
        for rating in RATING_ORDER:
            ov.append([f"{RATING_EMOJI[rating]} {rating}", RATING_DESCRIPTION[rating]])
            row = ov.max_row
            ov.cell(row=row, column=1).fill = PatternFill("solid", fgColor=RATING_FILL_HEX[rating])
            ov.cell(row=row, column=2).alignment = Alignment(wrap_text=True, vertical="top")
            ov.row_dimensions[row].height = 60
        ov.append([])
        ov.append(["Methodology notes"])
        ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
        for note in [
            "SSH: rating is based on applying real SSH negotiation rules (RFC 4253) using a preference "
            "order representative of a current, up-to-date OpenSSH client against the algorithms the "
            "server actually offered in its SSH_MSG_KEXINIT. No authentication is attempted.",
            "RDP/HTTPS: rating is based on the server's response to a hand-built TLS 1.3 ClientHello. "
            "RDP sends it after Enhanced RDP Security negotiation; HTTPS sends it immediately on "
            "connect. 'Ready' requires either a completed handshake selecting a hybrid PQC group, or "
            "a HelloRetryRequest naming one. No CredSSP/NLA credential or HTTP request is ever sent.",
            "'Capable' is expected to be far more reliable for SSH than for RDP/HTTPS: SSH's KEXINIT "
            "always discloses the server's full algorithm list regardless of what gets negotiated, "
            "while TLS servers only reveal what they select. A 'Planning Required' RDP/HTTPS host may "
            "still run PQC-capable software this scan could not prove.",
            "The headline 'quantum ready' percentage below counts Ready only -- proven, actually-"
            "negotiated PQC/hybrid cryptography. Capable and Planning Required are broken out "
            "separately and are not included in that percentage.",
        ]:
            ov.append([note])
            ov.cell(row=ov.max_row, column=1).alignment = Alignment(wrap_text=True, vertical="top")
            ov.merge_cells(start_row=ov.max_row, start_column=1, end_row=ov.max_row, end_column=2)
            ov.row_dimensions[ov.max_row].height = 45
        ov.append([])

        def add_summary_section(title: str, records: List[QCRecord]) -> None:
            ov.append([title])
            ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
            total = len(records)
            counts = compute_rating_stats(records)
            ov.append([f"Total {title.split()[0]} servers found:", total])
            ov.append(["Rating", "Count", "% of Total"])
            for cell in ov[ov.max_row]:
                cell.font = Font(bold=True)
            for rating in RATING_ORDER:
                pct = (counts[rating] / total * 100.0) if total else 0.0
                ov.append([f"{RATING_EMOJI[rating]} {rating}", counts[rating], round(pct, 1)])
                ov.cell(row=ov.max_row, column=1).fill = PatternFill("solid", fgColor=RATING_FILL_HEX[rating])
                ov.cell(row=ov.max_row, column=3).number_format = "0.0"
            ready_pct = (counts[RATING_READY] / total * 100.0) if total else 0.0
            ov.append([f"That means: {ready_pct:.1f}% of {title.split()[0]} servers found are quantum "
                       f"ready (proven PQC/hybrid negotiated)."])
            ov.cell(row=ov.max_row, column=1).font = Font(bold=True, italic=True)
            ov.merge_cells(start_row=ov.max_row, start_column=1, end_row=ov.max_row, end_column=3)
            ov.append([])

        add_summary_section("SSH Servers", ssh_records)
        add_summary_section("RDP Servers", rdp_records)
        add_summary_section("HTTPS Servers", https_records)

        # --- SSH / RDP / HTTPS sheets ---
        ssh_ws = wb.create_sheet("SSH")
        style_service_sheet(ssh_ws, ssh_records)
        rdp_ws = wb.create_sheet("RDP")
        style_service_sheet(rdp_ws, rdp_records)
        https_ws = wb.create_sheet("HTTPS")
        style_service_sheet(https_ws, https_records)

        wb.save(path)
        logger.info(f"XLSX report written to {path}")
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to write XLSX report to {path}: {exc}")


# =============================================================================
# MAIN
# =============================================================================

def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authorized internal SSH/RDP/HTTPS quantum-readiness assessment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--output-dir", type=str, default=SCRIPT_DIR)
    parser.add_argument("--masscan-path", type=str, default="masscan")
    parser.add_argument("--ssh-audit-path", type=str, default="ssh-audit",
                         help="Path to the ssh-audit executable, used as the primary SSH "
                              "algorithm collection method. Falls back to a hand-rolled raw-"
                              "socket probe per-host if this is not found or fails to parse.")
    parser.add_argument("--interface", type=str, default=None)
    parser.add_argument("--skip-masscan", action="store_true")
    parser.add_argument("--masscan-output-file", type=str, default=None)
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    scan_date = datetime.now().strftime("%Y-%m-%d")
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: Could not create output directory '{args.output_dir}': {exc}", file=sys.stderr)
        return 1

    log_path = os.path.join(args.output_dir, f"quantum_readiness_spray_{scan_date}.log")
    csv_path = os.path.join(args.output_dir, f"quantum_readiness_spray_{scan_date}.csv")
    xlsx_path = os.path.join(args.output_dir, f"quantum_readiness_spray_{scan_date}.xlsx")

    try:
        logger = setup_logging(log_path)
    except OSError as exc:
        print(f"ERROR: Could not open log file '{log_path}': {exc}", file=sys.stderr)
        return 1

    if not _HAVE_CRYPTOGRAPHY:
        logger.warning("The 'cryptography' package is not installed. RDP and HTTPS hosts will be "
                        "reported as Unknown. Install with: python3 -m pip install cryptography")

    stop_event = threading.Event()

    def handle_sigint(signum, frame):  # noqa: ANN001
        if stop_event.is_set():
            logger.warning("Second interrupt received, forcing exit.")
            sys.exit(130)
        logger.warning("Ctrl+C received - finishing current work and writing "
                        "partial reports. Press Ctrl+C again to force exit.")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    logger.info("=" * 70)
    logger.info("AUTHORIZED SSH/RDP/HTTPS QUANTUM-READINESS ASSESSMENT")
    logger.info("=" * 70)
    logger.info("Configured subnets in scope:")
    for s in SUBNETS:
        logger.info(f"  - {s}")
    logger.info(f"Workers: {args.workers} | Masscan rate: {args.rate} | "
                f"Timeout: {args.timeout}s | Retries: {args.retries}")

    networks = validate_subnets(SUBNETS, logger)
    if not networks:
        logger.error("No valid subnets configured. Exiting.")
        return 1

    masscan_path = check_external_tool(args.masscan_path) or args.masscan_path
    if not args.skip_masscan and check_external_tool(args.masscan_path) is None:
        logger.error(f"Required tool '{args.masscan_path}' was not found on PATH.")
        return 1

    resolved_ssh_audit = check_external_tool(args.ssh_audit_path)
    if resolved_ssh_audit is None:
        logger.warning(f"'{args.ssh_audit_path}' was not found on PATH. Falling back to the "
                        f"hand-rolled raw-socket SSH probe for all SSH hosts (fully functional, "
                        f"just less battle-tested than ssh-audit).")
        args.ssh_audit_path = ""
    else:
        logger.info(f"Using ssh-audit at '{resolved_ssh_audit}' as the primary SSH algorithm "
                    f"collection method.")
        args.ssh_audit_path = resolved_ssh_audit

    raw_records: List[Tuple[str, int, str]] = []
    if args.skip_masscan:
        if not args.masscan_output_file or not os.path.exists(args.masscan_output_file):
            logger.error("--skip-masscan requires a valid --masscan-output-file.")
            return 1
        raw_records, _ = parse_masscan_list_output(args.masscan_output_file, 0)
    else:
        masscan_out = args.masscan_output_file or os.path.join(
            args.output_dir, f".masscan_output_{scan_date}.txt")
        try:
            raw_records = run_masscan_phase1(masscan_path, SUBNETS, args.rate, masscan_out,
                                              args.interface, logger, stop_event)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Phase 1 discovery failed unexpectedly: {exc}")
            raw_records = []

    dedup: Dict[Tuple[str, int], Tuple[str, int, str]] = {}
    for ip, port, proto in raw_records:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Skipping malformed IP address from scan output: {ip}")
            continue
        dedup[(ip, port)] = (ip, port, proto)

    logger.info(f"Discovered {len(dedup)} unique host/port combinations after deduplication.")

    services: List[DiscoveredService] = []
    for ip, port, proto in dedup.values():
        if stop_event.is_set():
            break
        service_name = ("SSH" if port == SSH_PORT else "RDP" if port == RDP_PORT
                         else "HTTPS" if port == HTTPS_PORT else "UNKNOWN")
        if service_name == "UNKNOWN":
            continue
        hostname = resolve_hostname(ip, timeout=min(2.0, args.timeout))
        subnet = subnet_for_ip(ip, networks)
        services.append(DiscoveredService(ip=ip, port=port, service=service_name,
                                           hostname=hostname, subnet=subnet))

    records: List[QCRecord] = []
    if services and not stop_event.is_set():
        records = run_phase2(services, args, logger, stop_event)
    elif not services:
        logger.info("No SSH/RDP/HTTPS services discovered; skipping Phase 2 audit.")

    ssh_records = [r for r in records if r.service == "SSH"]
    rdp_records = [r for r in records if r.service == "RDP"]
    https_records = [r for r in records if r.service == "HTTPS"]

    write_csv_report(records, csv_path, logger)
    write_xlsx_report(ssh_records, rdp_records, https_records, networks, xlsx_path, logger)

    ssh_counts = compute_rating_stats(ssh_records)
    rdp_counts = compute_rating_stats(rdp_records)
    https_counts = compute_rating_stats(https_records)
    logger.info("=" * 70)
    logger.info("SCAN SUMMARY")
    logger.info(f"  SSH servers found: {len(ssh_records)} | " +
                " | ".join(f"{k}: {v}" for k, v in ssh_counts.items()))
    logger.info(f"  RDP servers found: {len(rdp_records)} | " +
                " | ".join(f"{k}: {v}" for k, v in rdp_counts.items()))
    logger.info(f"  HTTPS servers found: {len(https_records)} | " +
                " | ".join(f"{k}: {v}" for k, v in https_counts.items()))
    logger.info("=" * 70)
    logger.info(f"Reports written to: {os.path.abspath(args.output_dir)}")

    if stop_event.is_set():
        logger.warning("Scan was interrupted by user; reports reflect partial results.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
