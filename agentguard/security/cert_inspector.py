"""
IRIS: X.509 certificate inspection.

Parses real, DER-encoded X.509 certificates (ASN.1 structure) and flags
properties associated with adversary-controlled infrastructure: self-signed
certs and certs issued very recently before use, both real, well-documented
indicators (MITRE ATT&CK T1587.003, Develop Capabilities: Digital
Certificates) since legitimate CA-issued certs are rarely self-signed and
are typically issued well before the domain is actively used.

This does real ASN.1 decoding via the cryptography library's x509 module,
not string matching, it reads the actual certificate structure: issuer and
subject distinguished names, validity window, SAN entries, and public key
algorithm.
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

FRESHLY_ISSUED_THRESHOLD_HOURS = 72
MITRE_ATTACK_ENTERPRISE_TTP = {
    "id": "T1587.003",
    "name": "Develop Capabilities: Digital Certificates",
    "tactic": "Resource Development",
}


@dataclass
class CertInspectionResult:
    subject_cn: str
    issuer_cn: str
    self_signed: bool
    not_valid_before: str
    not_valid_after: str
    hours_since_issued: float
    freshly_issued: bool
    san_dns_names: list
    public_key_algorithm: str
    public_key_bits: int
    suspicious: bool
    suspicious_reasons: list


def _common_name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def _public_key_info(cert: x509.Certificate) -> tuple:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.key_size
    return pub.__class__.__name__, 0


def inspect_certificate(der_bytes: bytes) -> CertInspectionResult:
    """Decode a DER-encoded X.509 certificate and flag suspicious properties."""
    cert = x509.load_der_x509_certificate(der_bytes)

    self_signed = cert.issuer == cert.subject

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    hours_since_issued = (now - not_before).total_seconds() / 3600
    freshly_issued = 0 <= hours_since_issued < FRESHLY_ISSUED_THRESHOLD_HOURS

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_dns = []

    algo, bits = _public_key_info(cert)

    reasons = []
    if self_signed:
        reasons.append("self-signed (issuer matches subject)")
    if freshly_issued:
        reasons.append(f"issued {round(hours_since_issued, 1)}h ago, inside the {FRESHLY_ISSUED_THRESHOLD_HOURS}h freshness window")

    return CertInspectionResult(
        subject_cn=_common_name(cert.subject),
        issuer_cn=_common_name(cert.issuer),
        self_signed=self_signed,
        not_valid_before=not_before.isoformat(),
        not_valid_after=cert.not_valid_after_utc.isoformat(),
        hours_since_issued=round(hours_since_issued, 2),
        freshly_issued=freshly_issued,
        san_dns_names=san_dns,
        public_key_algorithm=algo,
        public_key_bits=bits,
        suspicious=bool(reasons),
        suspicious_reasons=reasons,
    )


def inspect_certificate_dict(der_bytes: bytes) -> dict:
    return asdict(inspect_certificate(der_bytes))
