"""AgentPKI — cryptographic identity for AI agents.

Python SDK mirroring @agentpki/sdk (TypeScript).

  Spec:    https://agentpki.dev/spec/v0.1
  Repo:    https://github.com/agentpki/sdk-python

Quickstart:

    from agentpki import generate_key_pair, sign_passport, verify_passport
    import time

    kp = generate_key_pair()
    now = int(time.time())

    token = sign_passport(
        {
            "v": 1, "iss": "example.com", "sub": "agent:example.com/bot-1",
            "iat": now, "exp": now + 3600, "jti": "0" * 32, "tier": 1,
            "scope": ["read:articles"],
        },
        private_key=kp.private_key,
        kid="example-2026-q2",
    )

    result = verify_passport(token, kp.public_key)
    assert result.valid
"""

from agentpki.client import AgentPKI, PassportProvider, PassportProviderResult
from agentpki.directory import (
    IssuerDirectoryError,
    KeySelection,
    KeySelectionCurrent,
    KeySelectionNotFound,
    KeySelectionRevoked,
    decode_public_key,
    resolve_issuer_directory,
    resolve_issuer_directory_sync,
    select_key,
)
from agentpki.keys import (
    KeyPair,
    generate_key_pair,
    get_public_key,
    public_key_to_spki,
    public_key_to_spki_base64,
)
from agentpki.passport import (
    VerifyResult,
    parse_passport,
    sign_passport,
    verify_passport,
)
from agentpki.signatures import (
    SignatureComponents,
    SignatureMetadata,
    build_signature_base,
    sign_request,
    verify_request_signature,
)
from agentpki.types import (
    ConfirmationKey,
    Contact,
    FailureReason,
    IssuerDirectory,
    IssuerKey,
    JsonWebKey,
    KybMetadata,
    PassportFooter,
    PassportPayload,
    RateHint,
    RevokedKey,
    SignOptions,
    TrustTier,
)

__version__ = "0.1.0a1"

__all__ = [
    "__version__",
    # passport
    "sign_passport", "parse_passport", "verify_passport", "VerifyResult",
    # directory
    "resolve_issuer_directory", "resolve_issuer_directory_sync",
    "select_key", "decode_public_key", "IssuerDirectoryError",
    "KeySelection", "KeySelectionCurrent", "KeySelectionRevoked", "KeySelectionNotFound",
    # signatures
    "build_signature_base", "sign_request", "verify_request_signature",
    "SignatureComponents", "SignatureMetadata",
    # client
    "AgentPKI", "PassportProvider", "PassportProviderResult",
    # keys
    "generate_key_pair", "get_public_key", "public_key_to_spki",
    "public_key_to_spki_base64", "KeyPair",
    # types
    "PassportPayload", "PassportFooter", "IssuerKey", "IssuerDirectory",
    "RevokedKey", "KybMetadata", "Contact", "RateHint",
    "JsonWebKey", "ConfirmationKey", "SignOptions",
    "TrustTier", "FailureReason",
]
