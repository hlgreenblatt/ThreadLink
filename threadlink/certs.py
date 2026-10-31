"""
Self-signed certificates for sprint agents.

QUIC requires TLS 1.3 — there is no unencrypted mode to fall back to — so every
agent needs a key pair before it can accept a connection. For a LAN swarm we
generate a self-signed cert per agent and cache it.

This gives CONFIDENTIALITY without AUTHENTICATION: traffic is encrypted, but a
self-signed cert alone does not prove the peer is the agent you meant to reach.
The `spki_pin` below is the upgrade path — pin the public key hash once and an
impostor with a different key is rejected. See docs/SECURITY.md.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from cryptography.x509.oid import NameOID

VALID_DAYS = 365


# Captain's order 2026-10-31: agent identities are CRYSTALS-Dilithium (ML-DSA, FIPS 204).
# ML-DSA-65 = NIST category 3, the same strength class as the ML-KEM-768 key agreement.
# "p-256" stays available for a peer that cannot verify ML-DSA yet.
CERT_ALGORITHMS = {
    "ml-dsa-44": mldsa.MLDSA44PrivateKey,
    "ml-dsa-65": mldsa.MLDSA65PrivateKey,
    "ml-dsa-87": mldsa.MLDSA87PrivateKey,
    "p-256": None,
}
DEFAULT_CERT_ALGORITHM = "ml-dsa-65"


def ensure_cert(directory: str | Path, agent_id: str,
                hosts: list[str] | None = None,
                algorithm: str = DEFAULT_CERT_ALGORITHM) -> tuple[str, str]:
    """Return (certfile, keyfile) for `agent_id`, generating them if absent.

    ML-DSA-65 (Dilithium) by default: a post-quantum signature in the certificate
    and in every CertificateVerify. The price is size - a 5.4 KB certificate and a
    3.3 KB signature against ~0.5 KB for P-256 - sent once per handshake.
    An existing pair on disk is returned as is, whatever its algorithm.
    """
    if algorithm not in CERT_ALGORITHMS:
        raise ValueError(f"algorithm must be one of {sorted(CERT_ALGORITHMS)}")
    d = Path(directory).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    certfile, keyfile = d / f"{agent_id}.crt", d / f"{agent_id}.key"
    if certfile.exists() and keyfile.exists():
        return str(certfile), str(keyfile)

    key_cls = CERT_ALGORITHMS[algorithm]
    key = key_cls.generate() if key_cls else ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])

    alt: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.DNSName(agent_id)]
    for h in hosts or []:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            alt.append(x509.DNSName(h))
    alt.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))     # tolerate clock skew
        .not_valid_after(now + dt.timedelta(days=VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256() if key_cls is None else None)   # ML-DSA hashes internally
    )

    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    keyfile.chmod(0o600)
    return str(certfile), str(keyfile)


def spki_pin_of_cert(cert: "x509.Certificate") -> str:
    """SHA-256 of a loaded certificate's SubjectPublicKeyInfo, base64.

    This is the "Peer Key ID" in the ThreadLink spec: it identifies the key, not
    a semantic identity, and survives certificate renewal as long as the key is
    reused. Used at handshake time when we already hold the peer's x509 object.
    """
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


def spki_pin(certfile: str | Path) -> str:
    """SHA-256 of the SubjectPublicKeyInfo, base64 — the peer's stable identity.

    Survives certificate renewal as long as the key is reused, which is exactly
    what you want to pin. Agents advertise this in HELLO so a swarm can move
    from trust-on-first-use to pinned identity without a CA.
    """
    cert = x509.load_pem_x509_certificate(Path(certfile).read_bytes())
    return spki_pin_of_cert(cert)
