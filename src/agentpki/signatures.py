"""RFC 9421 HTTP Message Signatures — AgentPKI Mode B subset.

Spec §7.2 requires signing at minimum:
  @method, @target-uri, content-digest (if body present), @signature-params
with created, expires, keyid (the passport token), and alg="ed25519".
"""

import base64
import re
from dataclasses import dataclass
from typing import Literal, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agentpki.util import base64_encode


@dataclass
class SignatureComponents:
    method: str
    url: str  # full target URI (scheme + host + path + query)
    body_sha256: Optional[str] = None  # standard base64 (not base64url)


@dataclass
class SignatureMetadata:
    created: int
    expires: int
    keyid: str  # AgentPKI passport token
    alg: Literal["ed25519"] = "ed25519"


def build_signature_base(
    components: SignatureComponents,
    meta: SignatureMetadata,
) -> tuple[str, str]:
    """Build the RFC 9421 signature base for AgentPKI Mode B.

    Returns (signature_base, signature_input_header_value).
    """
    covered = ['"@method"', '"@target-uri"']
    lines = [
        f'"@method": {components.method.upper()}',
        f'"@target-uri": {components.url}',
    ]

    if components.body_sha256:
        covered.append('"content-digest"')
        lines.append(f'"content-digest": sha-256=:{components.body_sha256}:')

    sig_params = (
        f'({" ".join(covered)})'
        f";created={meta.created}"
        f";expires={meta.expires}"
        f';keyid="{meta.keyid}"'
        f';alg="{meta.alg}"'
    )
    lines.append(f'"@signature-params": {sig_params}')

    return "\n".join(lines), f"sig1={sig_params}"


def sign_request(
    components: SignatureComponents,
    meta: SignatureMetadata,
    private_key: bytes,
) -> tuple[str, str]:
    """Sign a request per AgentPKI Mode B.

    Returns the values for the Signature-Input and Signature headers.
    """
    base, signature_input = build_signature_base(components, meta)
    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    sig = priv.sign(base.encode("utf-8"))
    return signature_input, f"sig1=:{base64_encode(sig)}:"


def verify_request_signature(
    components: SignatureComponents,
    meta: SignatureMetadata,
    public_key: bytes,
    signature_b64: str,
) -> bool:
    """Verify a Mode B signature."""
    base, _ = build_signature_base(components, meta)
    sig = _base64_sfv_decode(signature_b64)
    pub = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        pub.verify(sig, base.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


_SFV_PATTERN = re.compile(r"^(?:sig1=)?:?([A-Za-z0-9+/=]+):?$")


def _base64_sfv_decode(value: str) -> bytes:
    """Extract bytes from an RFC 8941 byte-sequence value: 'sig1=:<base64>:'."""
    m = _SFV_PATTERN.match(value)
    if not m:
        raise ValueError(f"signatures.verify: malformed signature SFV value: {value}")
    b64 = m.group(1)
    padded = b64 + "=" * ((4 - len(b64) % 4) % 4)
    return base64.b64decode(padded)
