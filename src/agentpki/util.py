"""Encoding and PASETO Pre-Authentication Encoding helpers.

Pure stdlib — no third-party deps in this module.
"""

import base64
import os
import struct


def base64url_encode(data: bytes) -> str:
    """Base64url encode (RFC 4648 §5) — no padding, '-' and '_' instead of '+' and '/'."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """Base64url decode (handles missing padding)."""
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def base64_encode(data: bytes) -> str:
    """Standard base64 (RFC 4648 §4) with padding — used by RFC 9421 byte-sequence values."""
    return base64.b64encode(data).decode("ascii")


def base64_decode(s: str) -> bytes:
    """Standard base64 decode (handles missing padding)."""
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(padded.encode("ascii"))


def le64(n: int) -> bytes:
    """Little-endian uint64 with high bit cleared, per PASETO PAE convention."""
    masked = n & ((1 << 63) - 1)
    return struct.pack("<Q", masked)


def pae(*pieces: bytes) -> bytes:
    """Pre-Authentication Encoding per PASETO spec §2.

    PAE([]) = 0x0000000000000000
    PAE(x) = LE64(|x|) || LE64(|x[0]|) || x[0] || ...
    """
    out = bytearray()
    out.extend(le64(len(pieces)))
    for piece in pieces:
        out.extend(le64(len(piece)))
        out.extend(piece)
    return bytes(out)


def random_hex(byte_length: int) -> str:
    """Cryptographically secure random hex of the given byte length.

    16 bytes = 32 hex chars = 128 bits of entropy (minimum required for jti).
    """
    return os.urandom(byte_length).hex()
