"""Cryplus Python SDK: a thin client for cryplus-core. No third-party dependencies.

All cryptography happens inside cryplus-core; this module only speaks its
local HTTP API.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import ssl
from dataclasses import dataclass, asdict
from typing import BinaryIO, Iterable, Optional
from urllib.parse import urlparse

__all__ = ["Cryplus", "Context", "CryplusError"]
__version__ = "0.1.0"

_CHUNK = 64 * 1024


class CryplusError(Exception):
    def __init__(self, code: str, status: Optional[int] = None):
        super().__init__(f"cryplus: {code}")
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Context:
    """Scopes a ciphertext. The same context must be used to decrypt."""

    tenant: str
    collection: str = ""
    field: str = ""
    record_id: str = ""

    def _json(self) -> dict:
        d = asdict(self)
        return {
            "tenant": d["tenant"],
            "collection": d["collection"],
            "field": d["field"],
            "recordId": d["record_id"],
        }


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


class Cryplus:
    """Client for cryplus-core.

    url may be one URL, a comma-separated string or a list (JSON calls fail over to the next instance
    when one is unreachable; streams do not). For https:// pass ca= (and cert=/key= for mutual TLS),
    or set CRYPLUS_CA / CRYPLUS_CLIENT_CERT / CRYPLUS_CLIENT_KEY. Certificates are always verified.
    """

    def __init__(
        self,
        url: "Optional[str | list[str]]" = None,
        token: Optional[str] = None,
        timeout: float = 15.0,
        ca: Optional[str] = None,
        cert: Optional[str] = None,
        key: Optional[str] = None,
    ):
        raw = url or os.environ.get("CRYPLUS_URL") or "http://127.0.0.1:7788"
        urls = raw if isinstance(raw, list) else raw.split(",")
        self.urls = [u.strip().rstrip("/") for u in urls if u.strip()]
        if not self.urls:
            raise ValueError("cryplus: no URL configured")
        self.url = self.urls[0]
        self._token = token or os.environ.get("CRYPLUS_TOKEN")
        if not self._token:
            raise ValueError("cryplus: token required (token= or CRYPLUS_TOKEN)")
        self.timeout = timeout
        self._parsed = [urlparse(u) for u in self.urls]
        schemes = {p.scheme for p in self._parsed}
        if len(schemes) != 1:
            raise ValueError("cryplus: all URLs must use the same scheme")
        self._https = schemes == {"https"}
        ca = ca or os.environ.get("CRYPLUS_CA")
        cert = cert or os.environ.get("CRYPLUS_CLIENT_CERT")
        key = key or os.environ.get("CRYPLUS_CLIENT_KEY")
        if not self._https and (ca or cert):
            raise ValueError("cryplus: TLS options were given but the URL is not https://")
        self._ssl: Optional[ssl.SSLContext] = None
        if self._https:
            ctx = ssl.create_default_context(cafile=ca)  # verifies certificate and hostname
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            if cert:
                ctx.load_cert_chain(cert, key)
            self._ssl = ctx
        self._preferred = 0

    # -- connection ---------------------------------------------------------
    def _conn(self, idx: int) -> http.client.HTTPConnection:
        p = self._parsed[idx]
        host = p.hostname or "127.0.0.1"
        if self._https:
            return http.client.HTTPSConnection(host, p.port or 443, timeout=self.timeout, context=self._ssl)
        return http.client.HTTPConnection(host, p.port or 80, timeout=self.timeout)

    def _json_once(self, idx: int, method: str, path: str, body: Optional[dict]):
        c = self._conn(idx)
        try:
            headers = {"Authorization": f"Bearer {self._token}"}
            data = None
            if body is not None:
                data = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            c.request(method, path, body=data, headers=headers)
            r = c.getresponse()
            raw = r.read()
            parsed = json.loads(raw) if raw else {}
            if r.status // 100 != 2:
                raise CryplusError(parsed.get("error", f"http_{r.status}"), r.status)
            return parsed
        except (OSError, http.client.HTTPException) as e:
            raise CryplusError(f"unreachable: {e}") from e
        finally:
            c.close()

    def _json_call(self, method: str, path: str, body: Optional[dict] = None):
        last: Optional[Exception] = None
        for i in range(len(self.urls)):
            idx = (self._preferred + i) % len(self.urls)
            try:
                out = self._json_once(idx, method, path, body)
                self._preferred = idx
                return out
            except CryplusError as e:
                last = e
                if not e.code.startswith("unreachable"):
                    raise
        assert last is not None
        raise last

    # -- single values --------------------------------------------------------
    def batch(self, ops: Iterable[dict]) -> list:
        """Run many operations in one request. Each op: {op, context, data}."""
        res = self._json_call("POST", "/v1/batch", {"ops": list(ops)})["results"]
        return res

    def encrypt(self, ctx: Context, plaintext: "str | bytes") -> str:
        b = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        return self._json_call("POST", "/v1/encrypt", {"context": ctx._json(), "data": _b64(b)})["data"]

    def decrypt_bytes(self, ctx: Context, ciphertext: str) -> bytes:
        r = self._json_call("POST", "/v1/decrypt", {"context": ctx._json(), "data": ciphertext})
        return base64.b64decode(r.get("data", ""))

    def decrypt(self, ctx: Context, ciphertext: str) -> str:
        return self.decrypt_bytes(ctx, ciphertext).decode("utf-8")

    def blind_index(self, ctx: Context, value: str) -> str:
        return self._json_call("POST", "/v1/blind-index", {"context": ctx._json(), "data": _b64(value.encode())})["data"]

    def rewrap(self, ctx: Context, ciphertext: str) -> "tuple[str, bool]":
        r = self._json_call("POST", "/v1/rewrap", {"context": ctx._json(), "data": ciphertext})
        return r["data"], bool(r.get("changed"))

    # -- admin ----------------------------------------------------------------
    def keys(self) -> dict:
        return self._json_call("GET", "/v1/keys")

    def rotate_keys(self) -> int:
        """Rotate the KEK. Only the leader can; followers answer read_only_instance, so try each instance."""
        last: Optional[Exception] = None
        for i in range(len(self.urls)):
            idx = (self._preferred + i) % len(self.urls)
            try:
                return int(self._json_once(idx, "POST", "/v1/keys/rotate", {})["version"])
            except CryplusError as e:
                last = e
                if e.code != "read_only_instance" and not e.code.startswith("unreachable"):
                    raise
        assert last is not None
        raise last

    # -- streaming ------------------------------------------------------------
    def _stream(self, path: str, ctx: Context, src: BinaryIO, dst: BinaryIO) -> None:
        def body():
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    return
                yield chunk

        c = self._conn(self._preferred)
        try:
            c.request(
                "POST",
                path,
                body=body(),
                encode_chunked=True,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/octet-stream",
                    "Transfer-Encoding": "chunked",
                    "X-Cryplus-Tenant": ctx.tenant,
                    "X-Cryplus-Collection": ctx.collection,
                    "X-Cryplus-Field": ctx.field,
                    "X-Cryplus-Record": ctx.record_id,
                },
            )
            r = c.getresponse()
            if r.status != 200:
                try:
                    code = json.loads(r.read()).get("error", f"http_{r.status}")
                except ValueError:
                    code = f"http_{r.status}"
                raise CryplusError(code, r.status)
            # A truncated/aborted body raises IncompleteRead instead of ending cleanly.
            while True:
                chunk = r.read(_CHUNK)
                if not chunk:
                    break
                dst.write(chunk)
        except http.client.IncompleteRead as e:
            raise CryplusError("stream_aborted") from e
        except (OSError, http.client.HTTPException) as e:
            raise CryplusError(f"stream_failed: {e}") from e
        finally:
            c.close()

    def encrypt_stream(self, ctx: Context, src: BinaryIO, dst: BinaryIO) -> None:
        self._stream("/v1/stream/encrypt", ctx, src, dst)

    def decrypt_stream(self, ctx: Context, src: BinaryIO, dst: BinaryIO) -> None:
        """Plaintext written to dst before an error is raised is NOT trustworthy; discard dst on error."""
        self._stream("/v1/stream/decrypt", ctx, src, dst)
