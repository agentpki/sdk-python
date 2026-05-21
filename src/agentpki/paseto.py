"""PASETO v4.public primitives.

Reference: https://github.com/paseto-standard/paseto-spec/blob/master/docs/Specification-v4.md

v4.public uses Ed25519 (no key wrapping, no encryption). Token layout:
    v4.public.<base64url(payload || signature)>[.<base64url(footer)>]

Sign:   m2 = PAE(["v4.public.", payload, footer, implicit])
        sig = Ed25519::Sign(sk, m2)
        body = base64url(payload || sig)

Verify: parse, recompute m2, Ed25519::Verify(pk, sig, m2)
"""

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agentpki.util import base64url_decode, base64url_encode, pae


V4_PUBLIC_HEADER = "v4.public."
_HEADER_BYTES = V4_PUBLIC_HEADER.encode("utf-8")


@dataclass(frozen=True)
class ParseResult:
    payload_bytes: bytes   # raw payload bytes (typically JSON, but opaque here)
    signature: bytes       # 64-byte Ed25519 signature
    footer_bytes: bytes    # often empty


def sign(
    payload_bytes: bytes,
    private_key: bytes,
    footer_bytes: bytes = b"",
    implicit: bytes = b"",
) -> str:
    """Produce a PASETO v4.public token."""
    m2 = pae(_HEADER_BYTES, payload_bytes, footer_bytes, implicit)
    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    signature = priv.sign(m2)
    body = payload_bytes + signature
    token = V4_PUBLIC_HEADER + base64url_encode(body)
    if footer_bytes:
        token += "." + base64url_encode(footer_bytes)
    return token


def parse(token: str) -> ParseResult:
    """Parse a PASETO v4.public token without verifying.

    SECURITY: Do not trust the returned bytes until verify() succeeds.
    """
    if not token.startswith(V4_PUBLIC_HEADER):
        raise ValueError("paseto.parse: token does not start with v4.public.")
    rest = token[len(V4_PUBLIC_HEADER):]
    parts = rest.split(".")
    if len(parts) < 1 or len(parts) > 2:
        raise ValueError(
            f"paseto.parse: expected 1 or 2 dot-segments, got {len(parts)}"
        )
    if not parts[0]:
        raise ValueError("paseto.parse: empty body segment")
    body = base64url_decode(parts[0])
    if len(body) < 64:
        raise ValueError(
            f"paseto.parse: body too short ({len(body)} bytes) for 64-byte signature"
        )
    payload_bytes = body[:-64]
    signature = body[-64:]
    footer_bytes = base64url_decode(parts[1]) if len(parts) > 1 else b""
    return ParseResult(
        payload_bytes=payload_bytes,
        signature=signature,
        footer_bytes=footer_bytes,
    )


def verify(
    token: str,
    public_key: bytes,
    implicit: bytes = b"",
) -> ParseResult | None:
    """Verify a PASETO v4.public token against the given Ed25519 public key.

    Returns the parsed components on success, or None on signature failure.
    Raises ValueError on malformed tokens.
    """
    parsed = parse(token)
    m2 = pae(_HEADER_BYTES, parsed.payload_bytes, parsed.footer_bytes, implicit)
    pub = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        pub.verify(parsed.signature, m2)
        return parsed
    except InvalidSignature:
        return None
