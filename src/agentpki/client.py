"""AgentPKI client — wraps HTTP requests and attaches a passport.

In Mode B (default), also produces an RFC 9421 HTTP Message Signature bound
to the request method, URL, and body hash.
"""

import hashlib
import time
from dataclasses import dataclass
from typing import Callable, Optional

import httpx

from agentpki.signatures import (
    SignatureComponents,
    SignatureMetadata,
    sign_request,
)
from agentpki.util import base64_encode


PASSPORT_HEADER = "AgentPKI-Token"


@dataclass
class PassportProviderResult:
    token: str
    cnf_private_key: Optional[bytes] = None  # required for Mode B


PassportProvider = Callable[[], PassportProviderResult]


class AgentPKI:
    """Sync HTTP client that attaches an AgentPKI passport (and Mode B signature) to every request.

    Use as a context manager or call .close() when done.
    """

    def __init__(
        self,
        passport_provider: PassportProvider,
        *,
        mode: str = "B",
        signature_lifetime_seconds: int = 120,
        client: Optional[httpx.Client] = None,
    ):
        self._provider = passport_provider
        self._mode = mode
        self._sig_lifetime = signature_lifetime_seconds
        self._client = client or httpx.Client()
        self._own_client = client is None

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        result = self._provider()
        if not isinstance(result, PassportProviderResult):
            raise TypeError("passport_provider must return PassportProviderResult")

        headers = dict(kwargs.pop("headers", None) or {})
        headers[PASSPORT_HEADER] = result.token

        if self._mode == "B":
            if not result.cnf_private_key:
                raise ValueError("AgentPKI Mode B requires cnf_private_key from passport_provider")

            body = kwargs.get("content") or kwargs.get("data") or b""
            if isinstance(body, str):
                body = body.encode("utf-8")
            elif not isinstance(body, (bytes, bytearray)):
                # For json= or other body forms, signing requires pre-serialized bytes.
                body = b""

            body_sha256: Optional[str] = None
            if body:
                digest = hashlib.sha256(bytes(body)).digest()
                body_sha256 = base64_encode(digest)
                headers["Content-Digest"] = f"sha-256=:{body_sha256}:"

            now = int(time.time())
            components = SignatureComponents(
                method=method,
                url=url,
                body_sha256=body_sha256,
            )
            meta = SignatureMetadata(
                created=now,
                expires=now + self._sig_lifetime,
                keyid=result.token,
                alg="ed25519",
            )
            sig_input, sig = sign_request(components, meta, result.cnf_private_key)
            headers["Signature-Input"] = sig_input
            headers["Signature"] = sig

        return self._client.request(method, url, headers=headers, **kwargs)

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        if self._own_client:
            self._client.close()

    def __enter__(self) -> "AgentPKI":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
