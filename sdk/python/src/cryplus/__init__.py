"""Cryplus Python SDK: a thin client for cryplus-core. No third-party dependencies.

All cryptography happens inside cryplus-core; this module only speaks its
local HTTP API.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
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
    def __init__(self, url: Optional[str] = None, token: Optional[str] = None, timeout: float = 15.0):
        self.url = (url or os.environ.get("CRYPLUS_URL") or "http://127.0.0.1:7788").rstrip("/")
        self._token = token or os.environ.get("CRYPLUS_TOKEN")
        if not self._token:
            raise ValueError("cryplus: token required (token= or CRYPLUS_TOKEN)")
        self.timeout = timeout
        u = urlparse(self.url)
        self._https = u.scheme == "https"
        self._host = u.hostname or "127.0.0.1"
        self._port = u.port or (443 if self._https else 80)

    # -- connection ---------------------------------------------------------
    def _conn(self) -> http.client.HTTPConnection:
        cls = http.client.HTTPSConnection if self._https else http.client.HTTPConnection
        return cls(self._host, self._port, timeout=self.timeout)

    def _json_call(self, method: str, path: str, body: Optional[dict] = None):
        c = self._conn()
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
        return int(self._json_call("POST", "/v1/keys/rotate", {})["version"])

    # -- streaming ------------------------------------------------------------
    def _stream(self, path: str, ctx: Context, src: BinaryIO, dst: BinaryIO) -> None:
        def body():
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    return
                yield chunk

        c = self._conn()
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
