"""Issuer directory resolution per spec §6.

Provides both async (httpx.AsyncClient) and sync (httpx.Client) entry points.
"""

import json
import time
from dataclasses import dataclass
from typing import Literal, Optional, Union

import httpx

from agentpki.types import IssuerDirectory, IssuerKey
from agentpki.util import base64_decode


class IssuerDirectoryError(Exception):
    def __init__(self, message: str, issuer: str):
        super().__init__(message)
        self.issuer = issuer


@dataclass(frozen=True)
class KeySelectionCurrent:
    key: IssuerKey
    status: Literal["current"] = "current"


@dataclass(frozen=True)
class KeySelectionRevoked:
    kid: str
    revoked_at: int
    reason: str
    status: Literal["revoked"] = "revoked"


@dataclass(frozen=True)
class KeySelectionNotFound:
    reason: str
    status: Literal["not_found"] = "not_found"


KeySelection = Union[KeySelectionCurrent, KeySelectionRevoked, KeySelectionNotFound]


def _validate_doc(doc: dict, issuer: str) -> IssuerDirectory:
    if doc.get("v") != 1:
        raise IssuerDirectoryError(
            f"unsupported directory version: {doc.get('v')}", issuer
        )
    if doc.get("issuer") != issuer:
        raise IssuerDirectoryError(
            f"issuer mismatch: expected '{issuer}', document declares '{doc.get('issuer')}'",
            issuer,
        )
    current_keys = doc.get("current_keys")
    if not isinstance(current_keys, list) or len(current_keys) == 0:
        raise IssuerDirectoryError("directory has no current_keys", issuer)
    return doc  # type: ignore[return-value]


async def resolve_issuer_directory(
    issuer: str,
    *,
    url_override: Optional[str] = None,
    timeout_seconds: float = 5.0,
    client: Optional[httpx.AsyncClient] = None,
) -> IssuerDirectory:
    """Async: fetch and validate an issuer's directory document."""
    url = url_override or f"https://{issuer}/.well-known/agentpki-issuer.json"
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=timeout_seconds)
    try:
        res = await client.get(url, headers={"Accept": "application/json"})
    except httpx.RequestError as e:
        raise IssuerDirectoryError(f"fetch failed for {url}: {e}", issuer) from e
    finally:
        if own_client and client is not None:
            await client.aclose()

    if res.status_code >= 400:
        raise IssuerDirectoryError(f"HTTP {res.status_code} fetching {url}", issuer)

    try:
        doc = res.json()
    except json.JSONDecodeError as e:
        raise IssuerDirectoryError(f"invalid JSON at {url}: {e}", issuer) from e

    return _validate_doc(doc, issuer)


def resolve_issuer_directory_sync(
    issuer: str,
    *,
    url_override: Optional[str] = None,
    timeout_seconds: float = 5.0,
) -> IssuerDirectory:
    """Sync: fetch and validate an issuer's directory document."""
    url = url_override or f"https://{issuer}/.well-known/agentpki-issuer.json"
    with httpx.Client(timeout=timeout_seconds) as client:
        try:
            res = client.get(url, headers={"Accept": "application/json"})
        except httpx.RequestError as e:
            raise IssuerDirectoryError(f"fetch failed for {url}: {e}", issuer) from e

    if res.status_code >= 400:
        raise IssuerDirectoryError(f"HTTP {res.status_code} fetching {url}", issuer)

    try:
        doc = res.json()
    except json.JSONDecodeError as e:
        raise IssuerDirectoryError(f"invalid JSON at {url}: {e}", issuer) from e

    return _validate_doc(doc, issuer)


def select_key(
    doc: IssuerDirectory,
    kid: Optional[str],
    now: Optional[int] = None,
) -> KeySelection:
    """Select the appropriate signing key from an issuer directory."""
    current = now if now is not None else int(time.time())
    revoked_keys = doc.get("revoked_keys", []) or []

    if kid and revoked_keys:
        for rk in revoked_keys:
            if rk["kid"] == kid:
                return KeySelectionRevoked(
                    kid=kid,
                    revoked_at=rk["revoked_at"],
                    reason=rk["reason"],
                )

    if kid:
        for k in doc["current_keys"]:
            if k["kid"] == kid:
                if k["valid_from"] > current:
                    return KeySelectionNotFound(
                        reason=f"kid '{kid}' not yet valid (valid_from > now)"
                    )
                if k["valid_to"] < current:
                    return KeySelectionNotFound(
                        reason=f"kid '{kid}' expired (valid_to < now)"
                    )
                return KeySelectionCurrent(key=k)
        return KeySelectionNotFound(reason=f"kid '{kid}' not in current_keys")

    candidates = sorted(
        (
            k for k in doc["current_keys"]
            if k["valid_from"] <= current and k["valid_to"] >= current
        ),
        key=lambda k: -k["valid_from"],
    )
    if not candidates:
        return KeySelectionNotFound(
            reason="no current_keys are currently within validity window"
        )
    return KeySelectionCurrent(key=candidates[0])


# Ed25519 SubjectPublicKeyInfo prefix per RFC 8410.
_ED25519_SPKI_PREFIX = bytes([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
])


def decode_public_key(pubkey_b64: str) -> bytes:
    """Decode an IssuerKey.pubkey field to raw 32-byte Ed25519 public key.

    Accepts either 44-byte SPKI-wrapped or 32-byte raw.
    """
    decoded = base64_decode(pubkey_b64)
    if len(decoded) == 32:
        return decoded
    if len(decoded) == 44 and decoded[: len(_ED25519_SPKI_PREFIX)] == _ED25519_SPKI_PREFIX:
        return decoded[len(_ED25519_SPKI_PREFIX):]
    raise ValueError(
        "decode_public_key: expected 32-byte raw or 44-byte SPKI Ed25519 key, "
        f"got {len(decoded)} bytes"
    )
