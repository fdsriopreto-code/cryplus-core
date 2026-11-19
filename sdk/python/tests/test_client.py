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


if __name__ == "__main__":
    unittest.main()
