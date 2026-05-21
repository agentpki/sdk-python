"""AgentPKI Passport — high-level sign / parse / verify.

Composes PASETO v4.public primitives with the AgentPKI passport schema and
the temporal-claim checks required by spec §4 and §8.2.

Does NOT do issuer-directory resolution, CRL checking, or site-policy
enforcement. Those are the verifier's job, not the holder's.
"""

import json
import time
from dataclasses import dataclass
from typing import Optional

from agentpki import paseto
from agentpki.types import FailureReason, PassportFooter, PassportPayload


MAX_LIFETIME_SECONDS = 86400  # Spec §4.2.1


@dataclass
class VerifyResult:
    valid: bool
    payload: Optional[PassportPayload] = None
    footer: Optional[PassportFooter] = None
    failure_reason: Optional[FailureReason] = None
    failure_detail: Optional[str] = None


def sign_passport(
    payload: PassportPayload,
    *,
    private_key: bytes,
    kid: Optional[str] = None,
) -> str:
    """Sign an AgentPKI passport. Returns a v4.public PASETO token.

    Raises ValueError if the payload violates a spec invariant the holder
    can check locally — version mismatch, missing fields, lifetime > 24h, etc.
    """
    _validate_payload_for_signing(payload)
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    footer_bytes = (
        json.dumps({"kid": kid}, separators=(",", ":")).encode("utf-8")
        if kid is not None
        else b""
    )
    return paseto.sign(payload_bytes, private_key, footer_bytes)


def parse_passport(
    token: str,
) -> tuple[PassportPayload, Optional[PassportFooter]]:
    """Parse a passport without verifying its signature.

    SECURITY: The returned payload and footer are NOT authenticated until
    verify_passport() succeeds.
    """
    parsed = paseto.parse(token)
    payload: PassportPayload = json.loads(parsed.payload_bytes.decode("utf-8"))
    footer: Optional[PassportFooter] = (
        json.loads(parsed.footer_bytes.decode("utf-8"))
        if parsed.footer_bytes
        else None
    )
    return payload, footer


def verify_passport(
    token: str,
    public_key: bytes,
    *,
    now: Optional[int] = None,
    expected_issuer: Optional[str] = None,
) -> VerifyResult:
    """Verify a passport against a specific Ed25519 public key.

    Performs:
      1. PASETO v4.public signature verification
      2. Version check (v == 1)
      3. iss match (if expected_issuer is provided)
      4. exp > now
      5. nbf <= now (if present)

    Does NOT check: revocation list, audience, capability scopes, abuse
    score, or HTTP Message Signature binding.
    """
    try:
        parsed = paseto.parse(token)
    except ValueError as e:
        return VerifyResult(valid=False, failure_reason="malformed", failure_detail=str(e))

    verified = paseto.verify(token, public_key)
    if verified is None:
        return VerifyResult(valid=False, failure_reason="bad_signature")

    try:
        payload: PassportPayload = json.loads(parsed.payload_bytes.decode("utf-8"))
        footer: Optional[PassportFooter] = (
            json.loads(parsed.footer_bytes.decode("utf-8"))
            if parsed.footer_bytes
            else None
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return VerifyResult(
            valid=False,
            failure_reason="malformed",
            failure_detail=f"payload or footer not valid JSON: {e}",
        )

    if payload.get("v") != 1:
        return VerifyResult(
            valid=False,
            failure_reason="malformed",
            failure_detail=f"unsupported version v={payload.get('v')}",
        )

    if expected_issuer and payload.get("iss") != expected_issuer:
        return VerifyResult(
            valid=False,
            failure_reason="malformed",
            failure_detail=(
                f"iss mismatch: expected '{expected_issuer}', "
                f"got '{payload.get('iss')}'"
            ),
        )

    current = now if now is not None else int(time.time())

    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < current:
        return VerifyResult(
            valid=False,
            failure_reason="expired",
            failure_detail=f"exp={exp} < now={current}",
        )

    nbf = payload.get("nbf")
    if isinstance(nbf, int) and nbf > current:
        return VerifyResult(
            valid=False,
            failure_reason="not_yet_valid",
            failure_detail=f"nbf={nbf} > now={current}",
        )

    return VerifyResult(valid=True, payload=payload, footer=footer)


def _validate_payload_for_signing(p: PassportPayload) -> None:
    if p.get("v") != 1:
        raise ValueError(f"sign_passport: v must be 1, got {p.get('v')}")
    if not p.get("iss"):
        raise ValueError("sign_passport: iss required")
    if not p.get("sub"):
        raise ValueError("sign_passport: sub required")
    iat = p.get("iat")
    exp = p.get("exp")
    if not isinstance(iat, int):
        raise ValueError("sign_passport: iat must be int (UNIX seconds)")
    if not isinstance(exp, int):
        raise ValueError("sign_passport: exp must be int (UNIX seconds)")
    if exp <= iat:
        raise ValueError(f"sign_passport: exp ({exp}) must be > iat ({iat})")
    if exp - iat > MAX_LIFETIME_SECONDS:
        raise ValueError(
            f"sign_passport: spec §4.2.1 requires exp − iat ≤ 86400; got {exp - iat}"
        )
    jti = p.get("jti")
    if not jti or len(jti) < 32:
        raise ValueError(
            "sign_passport: jti must be at least 32 hex chars (128 bits of entropy)"
        )
    tier = p.get("tier")
    if tier not in (1, 2, 3):
        raise ValueError(f"sign_passport: tier must be 1, 2, or 3 (got {tier})")
