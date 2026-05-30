# Changelog — agentpki (Python SDK)

All notable changes to the Python SDK.

## [0.2.0a1] — 2026-05-27

### Added

Support for AgentPKI Protocol v0.2 (see https://agentpki.dev/spec/v0.2).

- **Extended verifier response fields.** The `VerifyResponse` dataclass now exposes:
  - `crl_fresh: Optional[bool]` — true if the verifier consulted a current CRL during verification
  - `replay_checked: Optional[bool]` — true if the verifier consulted a replay cache (Mode B only)
  - `cached_until: Optional[int]` — unix-timestamp hint indicating how long the verdict may be safely cached
- **CRL helper.** New `resolve_crl(issuer)` function that fetches and parses the issuer's CRL per spec §5.
- **Replay-cache types.** New `ReplayCheckResult` dataclass for downstream consumers integrating directly with the verifier's replay-cache endpoint.
- **Abuse report submission.** New `submit_abuse_report(verifier_base, report)` helper for sites that observe misuse and want to feed back into the issuer's abuse score (spec §7).

### Changed

- `VerifyResponse` fields are all `Optional`, so v0.1-only verifier responses continue to work without code changes.
- `parse_passport` is unchanged — the token wire format is byte-identical between v0.1 and v0.2.

### Compatibility

- v0.2 SDK ← v0.1 verifier: full compatibility. v0.2-specific response fields will be `None`.
- v0.1 SDK ← v0.2 verifier: full compatibility. v0.2 fields are gracefully ignored.

### Migration

No code changes required to upgrade from `0.1.0a1`. Consumers that wish to surface the new freshness/replay signals to their application logic can add optional reads:

```python
result = verify(token)
if result.crl_fresh is False:
    print("CRL stale — trust assessment may be lagging")
```

## [0.1.0a1] — 2026-05-21

Initial alpha release. Supports AgentPKI Protocol v0.1.
