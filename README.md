# @agentpki/sdk — Python

Python SDK for AgentPKI — cryptographic identity for AI agents.

- **Spec:** https://agentpki.dev/spec/v0.1
- **Companion TS SDK:** https://npmjs.com/package/@agentpki/sdk

```bash
pip install agentpki
```

```python
from agentpki import generate_key_pair, sign_passport, verify_passport
import time

kp = generate_key_pair()
now = int(time.time())

token = sign_passport(
    {
        "v": 1,
        "iss": "example.com",
        "sub": "agent:example.com/research-bot-v1",
        "iat": now,
        "exp": now + 3600,
        "jti": "0e4f8a2c91b34e7b9c5d8a1e2f3b4c5d",
        "tier": 1,
        "scope": ["read:articles"],
    },
    private_key=kp.private_key,
    kid="example-2026-q2",
)

result = verify_passport(token, kp.public_key)
assert result.valid
assert result.payload["iss"] == "example.com"
```

See `examples/round_trip.py` for a complete sanity check covering signing, parsing, verification, tamper detection, expiry enforcement, lifetime cap, and RFC 9421 HTTP Message Signatures.

## License

MIT
