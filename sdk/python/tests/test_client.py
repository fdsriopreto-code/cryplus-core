import io
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from cryplus import Context, Cryplus, CryplusError  # noqa: E402

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "bin", "cryplus-core.exe"))
TOKEN = "py-test-token-0123456789"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class CoreCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cryplus-py-")
        port = free_port()
        cls.proc = subprocess.Popen(
            [BIN, "--listen", f"127.0.0.1:{port}", "--keyfile", os.path.join(cls.tmp, "k.json"), "--audit-log", ""],
            env={**os.environ, "CRYPLUS_TOKEN": TOKEN},
            stderr=subprocess.DEVNULL,
        )
        cls.url = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.url + "/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.05)
        cls.c = Cryplus(cls.url, TOKEN)
        cls.ctx = Context("acme", "User", "cpf")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait()

    def test_roundtrip(self):
        for s in ["", "123.456.789-00", "ação ✓ 日本語", "x" * 100_000]:
            ct = self.c.encrypt(self.ctx, s)
            self.assertTrue(ct.startswith("cp1."))
            self.assertEqual(self.c.decrypt(self.ctx, ct), s)

    def test_wrong_tenant_is_generic_error(self):
        ct = self.c.encrypt(self.ctx, "secret")
        with self.assertRaises(CryplusError) as e:
            self.c.decrypt(Context("evil", "User", "cpf"), ct)
        self.assertEqual(e.exception.code, "decryption_failed")

    def test_bad_token(self):
        with self.assertRaises(CryplusError) as e:
            Cryplus(self.url, "wrong-token-0123456789").encrypt(self.ctx, "x")
        self.assertEqual(e.exception.code, "unauthorized")

    def test_blind_index_and_rotation(self):
        a = self.c.blind_index(self.ctx, "111")
        self.assertEqual(a, self.c.blind_index(self.ctx, "111"))
        self.assertNotEqual(a, self.c.blind_index(Context("other", "User", "cpf"), "111"))
        old = self.c.encrypt(self.ctx, "keep")
        self.c.rotate_keys()
        new, changed = self.c.rewrap(self.ctx, old)
        self.assertTrue(changed)
        self.assertEqual(self.c.decrypt(self.ctx, new), "keep")
        self.assertEqual(a, self.c.blind_index(self.ctx, "111"))

    def test_batch(self):
        res = self.c.batch(
            [
                {"op": "encrypt", "context": self.ctx._json(), "data": "YQ=="},
                {"op": "decrypt", "context": self.ctx._json(), "data": "cp1.garbage"},
            ]
        )
        self.assertTrue(res[0]["data"].startswith("cp1."))
        self.assertEqual(res[1]["error"], "malformed_ciphertext")

    def test_stream_roundtrip_and_tamper(self):
        data = bytes((i * 31) & 0xFF for i in range(500_000))
        enc = io.BytesIO()
        self.c.encrypt_stream(self.ctx, io.BytesIO(data), enc)
        self.assertNotIn(data[1000:1064], enc.getvalue())
        dec = io.BytesIO()
        self.c.decrypt_stream(self.ctx, io.BytesIO(enc.getvalue()), dec)
        self.assertEqual(dec.getvalue(), data)

        bad = bytearray(enc.getvalue())
        bad[-10] ^= 1
        with self.assertRaises(CryplusError):
            self.c.decrypt_stream(self.ctx, io.BytesIO(bytes(bad)), io.BytesIO())
        with self.assertRaises(CryplusError):
            self.c.decrypt_stream(self.ctx, io.BytesIO(enc.getvalue()[:70_000]), io.BytesIO())
        with self.assertRaises(CryplusError) as e:
            self.c.decrypt_stream(Context("evil", "User", "cpf"), io.BytesIO(enc.getvalue()), io.BytesIO())
        self.assertEqual(e.exception.code, "decryption_failed")



class TlsCase(unittest.TestCase):
    """mTLS + per-service token + failover, against the real binary."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cryplus-py-tls-")
        subprocess.run([BIN, "tls", "dev-certs", "--out", cls.tmp], check=True, capture_output=True)
        tokens = os.path.join(cls.tmp, "tokens.json")
        r = subprocess.run(
            [BIN, "token", "new", "--name", "py", "--roles", "crypt,admin", "--tenants", "*", "--file", tokens],
            check=True, capture_output=True, text=True,
        )
        cls.token = r.stdout.strip()
        port = free_port()
        cls.proc = subprocess.Popen(
            [BIN, "--listen", f"127.0.0.1:{port}", "--keyfile", os.path.join(cls.tmp, "k.json"), "--audit-log", "",
             "--tls-cert", os.path.join(cls.tmp, "server.pem"), "--tls-key", os.path.join(cls.tmp, "server-key.pem"),
             "--client-ca", os.path.join(cls.tmp, "ca.pem"), "--tokens-file", tokens],
            env={**os.environ, "CRYPLUS_TOKEN": ""},
            stderr=subprocess.DEVNULL,
        )
        cls.url = f"https://127.0.0.1:{port}"
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        cls.paths = dict(ca=os.path.join(cls.tmp, "ca.pem"), cert=os.path.join(cls.tmp, "client.pem"), key=os.path.join(cls.tmp, "client-key.pem"))

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait()

    def test_mtls_roundtrip(self):
        c = Cryplus(self.url, self.token, **self.paths)
        ctx = Context("acme", "User", "cpf")
        self.assertEqual(c.decrypt(ctx, c.encrypt(ctx, "seguro")), "seguro")
        self.assertIsInstance(c.rotate_keys(), int)  # admin role

    def test_no_client_cert_is_refused(self):
        c = Cryplus(self.url, self.token, ca=self.paths["ca"])
        with self.assertRaises(CryplusError) as e:
            c.encrypt(Context("acme"), "x")
        self.assertTrue(e.exception.code.startswith("unreachable"))

    def test_untrusted_server_is_refused(self):
        other = tempfile.mkdtemp(prefix="cryplus-py-other-")
        subprocess.run([BIN, "tls", "dev-certs", "--out", other], check=True, capture_output=True)
        c = Cryplus(self.url, self.token, ca=os.path.join(other, "ca.pem"), cert=self.paths["cert"], key=self.paths["key"])
        with self.assertRaises(CryplusError) as e:
            c.encrypt(Context("acme"), "x")
        self.assertTrue(e.exception.code.startswith("unreachable"))

    def test_tls_options_on_http_url_are_rejected(self):
        with self.assertRaises(ValueError):
            Cryplus("http://127.0.0.1:1", "x" * 20, ca=self.paths["ca"])

    def test_failover_skips_dead_instance(self):
        c = Cryplus(["https://127.0.0.1:1", self.url], self.token, **self.paths)
        ctx = Context("acme")
        self.assertEqual(c.decrypt(ctx, c.encrypt(ctx, "ha")), "ha")


if __name__ == "__main__":
    unittest.main()
