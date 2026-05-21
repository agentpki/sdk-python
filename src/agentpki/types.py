"""Type definitions for AgentPKI Protocol v0.1.

Field names and constraints follow the spec exactly. Do not rename or alias
these — they appear on the wire.
"""

from typing import Literal, NotRequired, TypedDict


TrustTier = Literal[1, 2, 3]


FailureReason = Literal[
    "malformed",
    "bad_signature",
    "expired",
    "not_yet_valid",
    "unknown_issuer",
    "revoked",
    "revoked_key",
    "tier_too_low",
    "missing_scope",
    "audience_mismatch",
    "signature_mode_required",
    "signature_invalid",
    "abuse_threshold_exceeded",
    "replay_detected",
]


class RateHint(TypedDict, total=False):
    rpm: int
    daily: int


class JsonWebKey(TypedDict, total=False):
    kty: str
    crv: str
    x: str


class ConfirmationKey(TypedDict, total=False):
    jwk: JsonWebKey


class PassportPayload(TypedDict):
    v: Literal[1]
    iss: str
    sub: str
    iat: int
    exp: int
    jti: str
    tier: TrustTier
    aud: NotRequired[str | list[str]]
    nbf: NotRequired[int]
    scope: NotRequired[list[str]]
    rate: NotRequired[RateHint]
    cnf: NotRequired[ConfirmationKey]
    ext: NotRequired[dict[str, object]]


class PassportFooter(TypedDict):
    kid: str


class IssuerKey(TypedDict):
    kid: str
    alg: Literal["Ed25519"]
    pubkey: str
    valid_from: int
    valid_to: int


class RevokedKey(TypedDict):
    kid: str
    revoked_at: int
    reason: str


class KybMetadata(TypedDict):
    verified_by: str
    verified_at: int
    legal_name: str
    jurisdiction: str


class Contact(TypedDict):
    abuse: str
    security: str


class IssuerDirectory(TypedDict):
    v: Literal[1]
    issuer: str
    name: str
    tier: TrustTier
    current_keys: list[IssuerKey]
    revoked_keys: NotRequired[list[RevokedKey]]
    kyb: NotRequired[KybMetadata]
    crl_url: str
    abuse_report_url: str
    contact: Contact
    signed_by_root: NotRequired[str]


class SignOptions(TypedDict):
    private_key: bytes
    kid: NotRequired[str]
