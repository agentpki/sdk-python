"""Round-trip sanity check for the AgentPKI Python SDK.

Mirrors sdk-typescript/examples/round-trip.ts step-for-step. Run with:

    cd agentpki/sdk-python
    pip install -e .          # or: pip install agentpki  (after PyPI publish)
    python examples/round_trip.py
"""

import hashlib
import sys
import time

# Force UTF-8 stdout so the ✓ / ✗ glyphs render on Windows PowerShell
# (defaults to cp1252 when stdout is captured/piped).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # pragma: no cover
    pass

from agentpki import (
    generate_key_pair,
    parse_passport,
    public_key_to_spki_base64,
    sign_passport,
    sign_request,
    verify_passport,
    verify_request_signature,
)
from agentpki.signatures import SignatureComponents, SignatureMetadata
from agentpki.util import base64_encode, random_hex


GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[2m"
RESET = "\033[0m"

_passed = 0
_failed = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  {GREEN}✓{RESET} {name}")
    else:
        _failed += 1
        suffix = f" {DIM}({detail}){RESET}" if detail else ""
        print(f"  {RED}✗{RESET} {name}{suffix}")


print("\nAgentPKI Python SDK — round-trip sanity check\n")

# ───────────────────────────────────────────────────────────
print("1. Key generation")
kp = generate_key_pair()
check("private_key is 32 bytes", len(kp.private_key) == 32, f"got {len(kp.private_key)}")
check("public_key is 32 bytes", len(kp.public_key) == 32, f"got {len(kp.public_key)}")
print(f"  {DIM}SPKI base64: {public_key_to_spki_base64(kp.public_key)}{RESET}")

# ───────────────────────────────────────────────────────────
print("\n2. Passport signing")
now = int(time.time())
token = sign_passport(
    {
        "v": 1,
        "iss": "example.com",
        "sub": "agent:example.com/research-bot-v1",
        "iat": now,
        "exp": now + 3600,
        "jti": random_hex(16),
        "tier": 1,
        "scope": ["read:articles", "read:public-data"],
        "rate": {"rpm": 60, "daily": 10000},
    },
    private_key=kp.private_key,
    kid="example-2026-q2",
)
check("token starts with v4.public.", token.startswith("v4.public."))
check("token has footer segment", token.count(".") == 3)
print(f"  {DIM}Token (first 60 chars): {token[:60]}...{RESET}")
print(f"  {DIM}Token length: {len(token)} bytes{RESET}")

# ───────────────────────────────────────────────────────────
print("\n3. Passport parsing")
payload, footer = parse_passport(token)
check("parsed payload['iss'] == 'example.com'", payload["iss"] == "example.com")
check("parsed payload['tier'] == 1", payload["tier"] == 1)
check(
    "parsed footer['kid'] == 'example-2026-q2'",
    footer is not None and footer["kid"] == "example-2026-q2",
)
check(
    "parsed payload['scope'] contains read:articles",
    "read:articles" in payload.get("scope", []),
)

# ───────────────────────────────────────────────────────────
print("\n4. Passport verification (happy path)")
result = verify_passport(token, kp.public_key)
check("valid is True", result.valid)
check(
    "payload.sub matches",
    result.payload is not None
    and result.payload["sub"] == "agent:example.com/research-bot-v1",
)
check(
    "footer.kid matches",
    result.footer is not None and result.footer["kid"] == "example-2026-q2",
)

# ───────────────────────────────────────────────────────────
print("\n5. Tamper detection")
parts = token.split(".")
body = parts[2]
mid = len(body) // 2
parts[2] = body[:mid] + ("B" if body[mid] == "A" else "A") + body[mid + 1 :]
tampered = ".".join(parts)
tamper_result = verify_passport(tampered, kp.public_key)
check("tampered signature rejected", not tamper_result.valid)
check(
    "failure_reason in {bad_signature, malformed}",
    tamper_result.failure_reason in ("bad_signature", "malformed"),
    f"got {tamper_result.failure_reason}",
)

wrong_kp = generate_key_pair()
wrong_result = verify_passport(token, wrong_kp.public_key)
check("wrong key rejected", not wrong_result.valid)

# ───────────────────────────────────────────────────────────
print("\n6. Expiry enforcement")
expired_token = sign_passport(
    {
        "v": 1,
        "iss": "example.com",
        "sub": "agent:example.com/research-bot-v1",
        "iat": now - 7200,
        "exp": now - 3600,
        "jti": random_hex(16),
        "tier": 1,
    },
    private_key=kp.private_key,
)
expired_result = verify_passport(expired_token, kp.public_key)
check("expired token rejected", not expired_result.valid)
check(
    "failure_reason == 'expired'",
    expired_result.failure_reason == "expired",
    f"got {expired_result.failure_reason}",
)

# ───────────────────────────────────────────────────────────
print("\n7. Lifetime cap (24h)")
threw = False
try:
    sign_passport(
        {
            "v": 1,
            "iss": "example.com",
            "sub": "agent:example.com/over-24h",
            "iat": now,
            "exp": now + 86401,
            "jti": random_hex(16),
            "tier": 1,
        },
        private_key=kp.private_key,
    )
except ValueError:
    threw = True
check("25h passport rejected at signing", threw)

# ───────────────────────────────────────────────────────────
print("\n8. RFC 9421 signature round-trip")
body_bytes = b'{"hello":"world"}'
body_digest = base64_encode(hashlib.sha256(body_bytes).digest())
sig_created = int(time.time())
components = SignatureComponents(
    method="POST",
    url="https://example.com/api/foo",
    body_sha256=body_digest,
)
meta = SignatureMetadata(
    created=sig_created,
    expires=sig_created + 300,
    keyid=token,
    alg="ed25519",
)
sig_input, signature = sign_request(components, meta, kp.private_key)
check('signature_input contains "content-digest"', '"content-digest"' in sig_input)
check(
    "signature starts with sig1=: and ends with :",
    signature.startswith("sig1=:") and signature.endswith(":"),
)

sig_ok = verify_request_signature(components, meta, kp.public_key, signature)
check("signed request verifies", sig_ok)

tampered_body_digest = base64_encode(hashlib.sha256(b'{"hello":"WORLD"}').digest())
tampered_components = SignatureComponents(
    method="POST",
    url="https://example.com/api/foo",
    body_sha256=tampered_body_digest,
)
sig_tampered = verify_request_signature(
    tampered_components, meta, kp.public_key, signature
)
check("tampered body rejected", not sig_tampered)

# ───────────────────────────────────────────────────────────
total = _passed + _failed
fail_msg = f", {RED}{_failed} failed{RESET}" if _failed else ""
print(f"\n{total} checks — {GREEN}{_passed} passed{RESET}{fail_msg}\n")
if _failed:
    sys.exit(1)
