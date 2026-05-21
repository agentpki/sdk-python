"""Ed25519 key utilities.

AgentPKI uses Ed25519 (RFC 8032) for all signing. Private keys are 32-byte
seeds; public keys are 32 bytes (the compressed Edwards y-coordinate).
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from agentpki.util import base64_encode


@dataclass(frozen=True)
class KeyPair:
    private_key: bytes  # 32-byte Ed25519 seed
    public_key: bytes   # 32-byte compressed public key


def generate_key_pair() -> KeyPair:
    """Generate a new Ed25519 keypair using OS cryptographic randomness."""
    priv = Ed25519PrivateKey.generate()
    private_bytes = priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return KeyPair(private_key=private_bytes, public_key=public_bytes)


def get_public_key(private_key: bytes) -> bytes:
    """Derive the public key from a private key (seed)."""
    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    return priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )


# Ed25519 SubjectPublicKeyInfo prefix per RFC 8410:
#   SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING (00 || raw key) }
_SPKI_PREFIX = bytes([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
])


def public_key_to_spki(public_key: bytes) -> bytes:
    """Wrap a raw 32-byte Ed25519 public key in a DER SubjectPublicKeyInfo per RFC 8410."""
    if len(public_key) != 32:
        raise ValueError(
            f"public_key_to_spki: expected 32-byte Ed25519 key, got {len(public_key)} bytes"
        )
    return _SPKI_PREFIX + public_key


def public_key_to_spki_base64(public_key: bytes) -> str:
    """Convenience: SPKI-wrapped key, base64-encoded (drop into IssuerKey.pubkey)."""
    return base64_encode(public_key_to_spki(public_key))
