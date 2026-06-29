"""End-to-end and unit tests. Run with: python -m unittest discover -s tests

Each test points BLINDVAULT_HOME at a throwaway directory, supplies the master
password via BLINDVAULT_PASSWORD, and lowers the scrypt cost so the suite is fast.
"""

from __future__ import annotations

import importlib
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blindvault.agent import resolver  # noqa: E402
from blindvault.cli import main  # noqa: E402
from blindvault.core import config, session  # noqa: E402
from blindvault.core.crypto import (  # noqa: E402
    AuthError,
    Cipher,
    derive_kek,
    generate_data_key,
    new_salt,
    unwrap_data_key,
    wrap_data_key,
)
from blindvault.core.service import SOURCE_GENERATED, SOURCE_MANUAL, Vault  # noqa: E402

PASSWORD = "correct horse battery staple"


def _start_tcp_upstream(received):
    """A local upstream that records the Authorization header it receives."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            received["auth"] = self.headers.get("Authorization")
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    return up, up.server_address[1]


def _have_pywin32():
    try:
        import win32pipe  # noqa: F401
        return True
    except ImportError:
        return False


def _unix_http_get(sock_path, path):
    """Minimal HTTP/1.1 GET over a Unix-domain socket (no external deps)."""
    import socket as _socket

    sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(sock_path)
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    sock.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n")[0].split()[1])
    return status, body


class TempVaultCase(unittest.TestCase):
    KEYS = (config.ENV_HOME, config.ENV_PASSWORD, "BLINDVAULT_SCRYPT_N", "BLINDVAULT_ALLOW_WEAK_KDF")

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._saved = {k: os.environ.get(k) for k in self.KEYS}
        os.environ[config.ENV_HOME] = self._tmp.name
        os.environ[config.ENV_PASSWORD] = PASSWORD
        os.environ["BLINDVAULT_SCRYPT_N"] = "1024"        # fast KDF for tests only
        os.environ["BLINDVAULT_ALLOW_WEAK_KDF"] = "1"     # ...explicitly opted into

    def tearDown(self) -> None:
        for key in self.KEYS:
            value = self._saved.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    def run_cli(self, argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        prev_stdin = sys.stdin
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = main(argv)
        finally:
            sys.stdin = prev_stdin
        return code, out.getvalue(), err.getvalue()


class CryptoTests(TempVaultCase):
    def test_envelope_roundtrip(self):
        salt = new_salt()
        kek = derive_kek(PASSWORD, salt, n=1024)
        data_key = generate_data_key()
        wrapped = wrap_data_key(data_key, kek)
        self.assertEqual(unwrap_data_key(wrapped, kek), data_key)

    def test_wrong_password_cannot_unwrap(self):
        salt = new_salt()
        wrapped = wrap_data_key(generate_data_key(), derive_kek(PASSWORD, salt, n=1024))
        wrong = derive_kek("not the password", salt, n=1024)
        with self.assertRaises(AuthError):
            unwrap_data_key(wrapped, wrong)

    def test_cipher_roundtrip(self):
        cipher = Cipher(generate_data_key())
        token = cipher.encrypt("hunter2")
        self.assertNotIn("hunter2", token)
        self.assertEqual(cipher.decrypt(token), "hunter2")


class ResolverTests(unittest.TestCase):
    def test_find_and_inject(self):
        args = ["curl", "-H", "Authorization: Bearer {{secret:TOK}}"]
        self.assertEqual(resolver.references_in_args(args), ["TOK"])
        injected = resolver.inject(args, lambda n: "REALVALUE")
        self.assertIn("Authorization: Bearer REALVALUE", injected)

    def test_scrub_masks_value(self):
        scrub = resolver.make_scrubber({"TOK": "s3cr3t-value"})
        self.assertEqual(scrub("leaked s3cr3t-value here"), "leaked [redacted:TOK] here")

    def test_scrub_longer_first(self):
        scrub = resolver.make_scrubber({"SHORT": "abc", "LONG": "abc123"})
        self.assertEqual(scrub("abc123"), "[redacted:LONG]")

    def test_make_reference(self):
        self.assertEqual(resolver.make_reference("STRIPE_KEY"), "{{secret:STRIPE_KEY}}")

    def test_prompt_instruction(self):
        text = resolver.prompt_instruction("STRIPE_KEY")
        self.assertIn("{{secret:STRIPE_KEY}}", text)   # contains the usable reference
        self.assertIn("bv run", text)                  # tells the agent how to use it
        self.assertIn("STRIPE_KEY", text)


class ServiceTests(TempVaultCase):
    def _unlocked(self) -> Vault:
        Vault.initialize(PASSWORD)
        return Vault.open_locked().unlock_with_password(PASSWORD)

    def test_locked_vault_blocks_values(self):
        vault = self._unlocked()
        vault.add("K", "the-value")
        locked = Vault.open_locked()
        self.assertTrue(locked.is_locked)
        self.assertEqual(locked.names(), ["K"])           # names visible while locked
        with self.assertRaises(AuthError):
            locked.reveal("K")                             # values are not
        with self.assertRaises(AuthError):
            locked.add("X", "y")                           # writing is not

    def test_wrong_password_rejected(self):
        Vault.initialize(PASSWORD)
        with self.assertRaises(AuthError):
            Vault.open_locked().unlock_with_password("wrong")

    def test_origin_tracking(self):
        vault = self._unlocked()
        vault.add("MANUAL_KEY", "typed", "note")
        vault.generate("AI_KEY", length=16)
        rows = {r["name"]: r for r in Vault.open_locked().entries()}
        self.assertEqual(rows["MANUAL_KEY"]["source"], SOURCE_MANUAL)
        self.assertEqual(rows["AI_KEY"]["source"], SOURCE_GENERATED)

    def test_change_password(self):
        vault = self._unlocked()
        vault.add("K", "v")
        Vault.open_locked().change_password(PASSWORD, "new-pass")
        self.assertEqual(Vault.open_locked().unlock_with_password("new-pass").reveal("K"), "v")
        with self.assertRaises(AuthError):
            Vault.open_locked().unlock_with_password(PASSWORD)

    def test_migrate_from_v1(self):
        # Build a fake pre-0.2.0 vault: a plaintext key.bin + a version-1 store.
        from cryptography.fernet import Fernet

        from blindvault.core import store

        home = Path(os.environ[config.ENV_HOME])
        home.mkdir(parents=True, exist_ok=True)
        legacy_key = Fernet.generate_key()
        config.legacy_key_path().write_bytes(legacy_key)
        ciphertext = Fernet(legacy_key).encrypt(b"legacy-value").decode("ascii")
        store.save(config.store_path(), {
            "version": 1,
            "secrets": {"OLD": {"ciphertext": ciphertext, "description": "note"}},
        })

        self.assertTrue(Vault.is_legacy_v1())
        self.assertEqual(Vault.legacy_names(), ["OLD"])
        migrated = Vault.migrate_from_v1("brand-new-pass")
        self.assertEqual(migrated, 1)
        # old key file is gone; value is readable under the new password
        self.assertFalse(config.legacy_key_path().exists())
        self.assertFalse(Vault.is_legacy_v1())
        vault = Vault.open_locked().unlock_with_password("brand-new-pass")
        self.assertEqual(vault.reveal("OLD"), "legacy-value")
        self.assertEqual(vault.entries()[0]["description"], "note")

    def test_locked_delete_requires_unlock(self):
        vault = self._unlocked()
        vault.add("K", "v")
        with self.assertRaises(AuthError):
            Vault.open_locked().delete("K")  # no password/session => refused

    def test_set_overwrite_preserves_policy(self):
        vault = self._unlocked()
        vault.add("K", "v1")
        vault.set_policy("K", [], ["api.stripe.com"])
        vault.add("K", "v2")  # overwrite the value...
        kept = Vault.open_locked().unlock_with_password(PASSWORD).get_policy("K")
        self.assertEqual(kept, {"allow_commands": [], "allow_hosts": ["api.stripe.com"]})

    def test_rekey_rotates_data_key(self):
        vault = self._unlocked()
        vault.add("K", "v")
        old_key = Vault.open_locked().unlock_with_password(PASSWORD).data_key
        Vault.open_locked().change_password(PASSWORD, "new", rekey=True)
        rotated = Vault.open_locked().unlock_with_password("new")
        self.assertNotEqual(rotated.data_key, old_key)
        self.assertEqual(rotated.reveal("K"), "v")


class CliTests(TempVaultCase):
    def _init_and_set(self, name="API_KEY", value="s3cr3t-value-xyz"):
        self.assertEqual(self.run_cli(["init"])[0], 0)
        code, out, _ = self.run_cli(["set", name, "--stdin"], stdin=value + "\n")
        self.assertEqual(code, 0)
        self.assertNotIn(value, out)

    def test_ls_hides_values(self):
        self._init_and_set()
        code, out, _ = self.run_cli(["ls"])
        self.assertEqual(code, 0)
        self.assertIn("API_KEY", out)
        self.assertNotIn("s3cr3t-value-xyz", out)

    def test_run_injects_into_argv_and_scrubs(self):
        self._init_and_set(value="argv-secret-123")
        code, out, _ = self.run_cli(
            ["run", "--", sys.executable, "-c", "print('{{secret:API_KEY}}')"]
        )
        self.assertEqual(code, 0)
        self.assertNotIn("argv-secret-123", out)
        self.assertIn("[redacted:API_KEY]", out)

    def test_run_injects_into_env_and_scrubs(self):
        self._init_and_set(value="env-secret-456")
        code, out, _ = self.run_cli(
            ["run", "--env", "TK=API_KEY", "--", sys.executable, "-c",
             "import os; print(os.environ['TK'])"]
        )
        self.assertEqual(code, 0)
        self.assertNotIn("env-secret-456", out)
        self.assertIn("[redacted:API_KEY]", out)

    def test_reveal_requires_force_and_password(self):
        self._init_and_set(value="reveal-me-please")
        # without --force: refused
        code, out, _ = self.run_cli(["reveal", "API_KEY"])
        self.assertEqual(code, 1)
        self.assertNotIn("reveal-me-please", out)
        # with --force and the correct password on stdin: shown
        code, out, _ = self.run_cli(
            ["reveal", "API_KEY", "--force", "--password-stdin"], stdin=PASSWORD + "\n"
        )
        self.assertEqual(code, 0)
        self.assertIn("reveal-me-please", out)

    def test_reveal_ignores_env_password(self):
        # The env password is set (and correct), but reveal must NOT use it: a
        # wrong password on stdin has to fail, proving an agent that only has the
        # environment cannot make BlindVault print a secret.
        self._init_and_set(value="should-stay-hidden")
        code, out, _ = self.run_cli(
            ["reveal", "API_KEY", "--force", "--password-stdin"], stdin="wrong-password\n"
        )
        self.assertEqual(code, 1)
        self.assertNotIn("should-stay-hidden", out)

    def test_unlock_session_lets_run_work_without_password(self):
        self._init_and_set(value="session-secret-789")
        self.assertEqual(self.run_cli(["unlock"])[0], 0)
        # Simulate an agent that has NO password: remove it from the environment.
        saved = os.environ.pop(config.ENV_PASSWORD)
        try:
            code, out, _ = self.run_cli(
                ["run", "--", sys.executable, "-c", "print('{{secret:API_KEY}}')"]
            )
        finally:
            os.environ[config.ENV_PASSWORD] = saved
        self.assertEqual(code, 0)
        self.assertIn("[redacted:API_KEY]", out)
        self.assertNotIn("session-secret-789", out)

    def test_lock_clears_session(self):
        self._init_and_set()
        self.run_cli(["unlock"])
        self.assertIsNotNone(session.load())
        self.run_cli(["lock"])
        self.assertIsNone(session.load())

    def test_gen_never_displays_value(self):
        self.run_cli(["init"])
        code, out, _ = self.run_cli(["gen", "TOKEN", "--length", "24"])
        self.assertEqual(code, 0)
        self.assertIn("never displayed", out)

    def test_weak_kdf_warns_on_open(self):
        self.run_cli(["init"])  # setUp uses n=1024 with the weak-KDF flag set
        saved = os.environ.pop("BLINDVAULT_ALLOW_WEAK_KDF")  # a real user wouldn't have it
        try:
            code, _out, err = self.run_cli(["ls"])
        finally:
            os.environ["BLINDVAULT_ALLOW_WEAK_KDF"] = saved
        self.assertEqual(code, 0)
        self.assertIn("weak", err.lower())  # warns + suggests rekey

    def test_run_refuses_secret_as_program_and_never_leaks(self):
        # Regression for the critical leak: a reference in the program slot must
        # be refused, and the value must never appear in stdout/stderr.
        self._init_and_set(value="leaky-secret-value")
        code, out, err = self.run_cli(["run", "--", "{{secret:API_KEY}}"])
        self.assertEqual(code, 1)
        self.assertNotIn("leaky-secret-value", out)
        self.assertNotIn("leaky-secret-value", err)


class PolicyUnitTests(unittest.TestCase):
    def test_extract_hosts(self):
        from blindvault.agent import policy
        args = ["curl", "-H", "Authorization: Bearer x", "https://api.stripe.com/v1/charges"]
        self.assertEqual(policy.extract_hosts(args), ["api.stripe.com"])

    def test_host_allowed(self):
        from blindvault.agent import policy
        self.assertTrue(policy.host_allowed("api.stripe.com", ["api.stripe.com"]))
        self.assertTrue(policy.host_allowed("api.stripe.com", ["stripe.com"]))  # subdomain ok
        self.assertFalse(policy.host_allowed("evil.com", ["stripe.com"]))

    def test_enforce_commands(self):
        from blindvault.agent import policy
        pol = {"allow_commands": ["curl"], "allow_hosts": []}
        policy.enforce("K", pol, [], "curl")  # allowed, no raise
        with self.assertRaises(policy.PolicyError):
            policy.enforce("K", pol, [], "wget")

    def test_enforce_hosts(self):
        from blindvault.agent import policy
        pol = {"allow_commands": [], "allow_hosts": ["api.stripe.com"]}
        policy.enforce("K", pol, ["https://api.stripe.com/x"], "curl")  # allowed
        with self.assertRaises(policy.PolicyError):
            policy.enforce("K", pol, ["https://evil.example/x"], "curl")
        with self.assertRaises(policy.PolicyError):
            policy.enforce("K", pol, ["no-url-here"], "curl")  # can't verify => blocked

    def test_blob_roundtrip_and_legacy(self):
        from blindvault.core.service import _decode_blob, _encode_blob
        self.assertEqual(_decode_blob("plain-legacy-value"), ("plain-legacy-value", None))
        value, pol = _decode_blob(_encode_blob("K", "v", {"allow_hosts": ["x"]}), expected_name="K")
        self.assertEqual(value, "v")
        self.assertEqual(pol, {"allow_hosts": ["x"]})

    def test_blob_name_binding_detects_swap(self):
        from blindvault.core.crypto import VaultError
        from blindvault.core.service import _decode_blob, _encode_blob
        swapped = _encode_blob("PROD", "prod-value", None)  # belongs to PROD
        with self.assertRaises(VaultError):
            _decode_blob(swapped, expected_name="STAGING")   # but read as STAGING


class PolicyCliTests(TempVaultCase):
    def test_run_blocked_and_allowed_by_host_policy(self):
        self.assertEqual(self.run_cli(["init"])[0], 0)
        self.run_cli(["set", "TOK", "--stdin"], stdin="tok-secret-value\n")
        code, _, _ = self.run_cli(
            ["policy", "TOK", "--allow-host", "api.stripe.com", "--password-stdin"],
            stdin=PASSWORD + "\n",
        )
        self.assertEqual(code, 0)

        ok = ["run", "--", sys.executable, "-c", "print('{{secret:TOK}}')", "https://api.stripe.com/v1"]
        code, out, _ = self.run_cli(ok)
        self.assertEqual(code, 0)
        self.assertIn("[redacted:TOK]", out)
        self.assertNotIn("tok-secret-value", out)

        bad = ["run", "--", sys.executable, "-c", "print('{{secret:TOK}}')", "https://evil.example/x"]
        code, out, err = self.run_cli(bad)
        self.assertEqual(code, 1)
        self.assertIn("usage policy", err)
        self.assertNotIn("tok-secret-value", out)

    def test_policy_change_requires_password(self):
        self.run_cli(["init"])
        self.run_cli(["set", "TOK", "--stdin"], stdin="v\n")
        # env password is correct but policy changes ignore it; a wrong stdin
        # password must be rejected (so an agent can't weaken a policy).
        code, _, err = self.run_cli(
            ["policy", "TOK", "--allow-host", "x.com", "--password-stdin"], stdin="wrong\n"
        )
        self.assertEqual(code, 1)

    def test_env_delivery_blocked_for_host_restricted_secret(self):
        self.run_cli(["init"])
        self.run_cli(["set", "TOK", "--stdin"], stdin="v\n")
        self.run_cli(
            ["policy", "TOK", "--allow-host", "api.stripe.com", "--password-stdin"],
            stdin=PASSWORD + "\n",
        )
        code, _, err = self.run_cli(
            ["run", "--env", "K=TOK", "--", sys.executable, "-c", "print(1)", "https://api.stripe.com/"]
        )
        self.assertEqual(code, 1)
        self.assertIn("--env", err)


class EnvImportTests(TempVaultCase):
    def test_parse(self):
        from blindvault.agent import envfile
        text = (
            "# a comment\n"
            "export API_KEY=abc123\n"
            "DB_URL='postgres://x'\n"
            "QUOTED=\"hello world\"\n"
            "BAD KEY=zzz\n"
            "EMPTY=\n"
        )
        got = dict(envfile.parse(text))
        self.assertEqual(got["API_KEY"], "abc123")
        self.assertEqual(got["DB_URL"], "postgres://x")
        self.assertEqual(got["QUOTED"], "hello world")
        self.assertIn("EMPTY", got)
        self.assertNotIn("BAD KEY", got)  # invalid key skipped

    def test_cli_import(self):
        self.run_cli(["init"])
        env_path = os.path.join(self._tmp.name, "sample.env")
        with open(env_path, "w", encoding="utf-8") as handle:
            handle.write("API_KEY=sk_test_123\nDB_PASSWORD=p@ss\n# note\nEMPTY=\n")
        code, out, _ = self.run_cli(["import", env_path])
        self.assertEqual(code, 0)
        self.assertIn("Imported 2", out)
        self.assertNotIn("sk_test_123", out)
        _, lsout, _ = self.run_cli(["ls"])
        self.assertIn("API_KEY", lsout)
        self.assertIn("DB_PASSWORD", lsout)
        self.assertNotIn("sk_test_123", lsout)


class KdfTests(unittest.TestCase):
    def test_default_n_ignores_weak_override_without_flag(self):
        from blindvault.core import crypto
        keys = ("BLINDVAULT_SCRYPT_N", "BLINDVAULT_ALLOW_WEAK_KDF")
        saved = {k: os.environ.get(k) for k in keys}
        try:
            os.environ["BLINDVAULT_SCRYPT_N"] = "2"
            os.environ.pop("BLINDVAULT_ALLOW_WEAK_KDF", None)
            self.assertEqual(crypto.default_scrypt_n(), crypto.DEFAULT_SCRYPT_N)  # weak ignored
            os.environ["BLINDVAULT_ALLOW_WEAK_KDF"] = "1"
            self.assertEqual(crypto.default_scrypt_n(), 2)                         # opted in
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def test_validate_rejects_abusive_params(self):
        from blindvault.core import crypto
        with self.assertRaises(crypto.VaultError):
            crypto.validate_scrypt_params(3, 8, 1)        # not a power of two
        with self.assertRaises(crypto.VaultError):
            crypto.validate_scrypt_params(2 ** 30, 8, 1)  # would exceed the memory cap
        crypto.validate_scrypt_params(2 ** 14, 8, 1)      # fine


class BrokerTests(TempVaultCase):
    def _unlocked(self):
        Vault.initialize(PASSWORD)
        return Vault.open_locked().unlock_with_password(PASSWORD)

    def test_proxy_injects_secret_without_exposing_it(self):
        import threading
        import urllib.request
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        from blindvault.broker import server as broker_mod

        received = {}

        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                received["auth"] = self.headers.get("Authorization")
                received["path"] = self.path
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        up_port = up.server_address[1]
        threading.Thread(target=up.serve_forever, daemon=True).start()

        vault = self._unlocked()
        vault.add("STRIPE_KEY", "sk_live_REALSECRET")
        vault.set_policy("STRIPE_KEY", [], [f"127.0.0.1:{up_port}"])  # restrict to the upstream

        server = broker_mod.Broker(
            Vault.open_locked().unlock_with_password(PASSWORD)
        ).make_server("127.0.0.1", 0)
        proxy_port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            # The agent calls the proxy WITHOUT any secret of its own.
            with urllib.request.urlopen(
                f"http://127.0.0.1:{proxy_port}/STRIPE_KEY/v1/charges"
            ) as resp:
                client_body = resp.read().decode()
        finally:
            server.shutdown()
            up.shutdown()

        # The broker injected the REAL secret on its side:
        self.assertEqual(received["auth"], "Bearer sk_live_REALSECRET")
        self.assertEqual(received["path"], "/v1/charges")
        # ...and the agent's response never contains the secret:
        self.assertIn("ok", client_body)
        self.assertNotIn("sk_live_REALSECRET", client_body)

    def test_proxy_refuses_secret_without_host_policy(self):
        import threading
        import urllib.error
        import urllib.request

        from blindvault.broker import server as broker_mod

        vault = self._unlocked()
        vault.add("LOOSE", "value")  # no allow_hosts => cannot be proxied safely

        server = broker_mod.Broker(
            Vault.open_locked().unlock_with_password(PASSWORD)
        ).make_server("127.0.0.1", 0)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/LOOSE/x")
            self.assertEqual(ctx.exception.code, 403)
        finally:
            server.shutdown()


class HardeningTests(unittest.TestCase):
    def test_hardening_helpers_are_safe_everywhere(self):
        from blindvault.broker import hardening
        self.assertIsInstance(hardening.harden_process(), dict)
        hardening.drop_privileges("no-such-user-zzz")  # no-op unless root; must not raise
        warning = hardening.ptrace_scope_warning()
        self.assertTrue(warning is None or isinstance(warning, str))


@unittest.skipUnless(
    sys.platform.startswith("linux") and hasattr(__import__("socket"), "SO_PEERCRED"),
    "Unix-socket peer authentication is Linux-only",
)
class Phase2BrokerTests(TempVaultCase):
    def _unlocked(self):
        Vault.initialize(PASSWORD)
        return Vault.open_locked().unlock_with_password(PASSWORD)

    def _start_upstream(self, received):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                received["auth"] = self.headers.get("Authorization")
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        return up, up.server_address[1]

    def test_unix_socket_injects_and_authenticates_uid(self):
        import os
        import threading

        from blindvault.broker import server as broker_mod

        received = {}
        up, up_port = self._start_upstream(received)

        vault = self._unlocked()
        vault.add("STRIPE_KEY", "sk_live_UNIXSECRET")
        vault.set_policy("STRIPE_KEY", [], [f"127.0.0.1:{up_port}"])

        sock_path = os.path.join(self._tmp.name, "proxy.sock")
        broker = broker_mod.Broker(
            Vault.open_locked().unlock_with_password(PASSWORD),
            allowed_uids={os.getuid()},  # our own uid is allowed
        )
        server = broker.make_unix_server(sock_path)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            status, body = _unix_http_get(sock_path, "/STRIPE_KEY/v1/charges")
        finally:
            server.server_close()
            up.shutdown()

        self.assertEqual(status, 200)
        self.assertEqual(received["auth"], "Bearer sk_live_UNIXSECRET")  # injected by broker
        self.assertNotIn(b"sk_live_UNIXSECRET", body)                    # not leaked to client

    def test_unix_socket_rejects_unauthorized_uid(self):
        import os
        import threading

        from blindvault.broker import server as broker_mod

        self._unlocked()
        sock_path = os.path.join(self._tmp.name, "proxy.sock")
        broker = broker_mod.Broker(
            Vault.open_locked().unlock_with_password(PASSWORD),
            allowed_uids={os.getuid() + 1},  # NOT our uid
        )
        server = broker.make_unix_server(sock_path)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            status, _ = _unix_http_get(sock_path, "/STRIPE_KEY/x")
        finally:
            server.server_close()
        self.assertEqual(status, 403)  # peer UID not authorized


@unittest.skipUnless(sys.platform == "win32" and _have_pywin32(),
                     "Windows named-pipe peer auth requires Windows + pywin32")
class Phase2WindowsTests(TempVaultCase):
    _counter = 0

    def _pipe_name(self):
        Phase2WindowsTests._counter += 1
        return rf"\\.\pipe\BlindVault-test-{os.getpid()}-{Phase2WindowsTests._counter}"

    def _unlocked(self):
        Vault.initialize(PASSWORD)
        return Vault.open_locked().unlock_with_password(PASSWORD)

    def test_pipe_injects_and_authenticates_sid(self):
        import base64
        import threading

        from blindvault.broker import server as broker_mod, winpipe

        received = {}
        up, up_port = _start_tcp_upstream(received)

        vault = self._unlocked()
        vault.add("STRIPE_KEY", "sk_live_PIPESECRET")
        vault.set_policy("STRIPE_KEY", [], [f"127.0.0.1:{up_port}"])

        my_sid = winpipe.current_user_sid()
        broker = broker_mod.Broker(
            Vault.open_locked().unlock_with_password(PASSWORD), allowed_sids={my_sid}
        )
        pipe = self._pipe_name()
        server = winpipe.PipeServer(pipe, winpipe.build_sddl(my_sid, {my_sid}), broker.pipe_handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            resp = winpipe.request(pipe, {"secret": "STRIPE_KEY", "path": "v1/charges",
                                          "method": "GET", "headers": {}, "body_b64": None})
        finally:
            server.close()
            up.shutdown()

        self.assertEqual(resp["status"], 200)
        self.assertEqual(received["auth"], "Bearer sk_live_PIPESECRET")  # injected by broker
        self.assertNotIn(b"sk_live_PIPESECRET", base64.b64decode(resp["body_b64"]))  # not leaked

    def test_pipe_rejects_unauthorized_sid(self):
        import threading

        from blindvault.broker import server as broker_mod, winpipe

        self._unlocked()
        my_sid = winpipe.current_user_sid()
        # The DACL lets us connect, but the app allow-list only trusts SYSTEM's SID:
        broker = broker_mod.Broker(
            Vault.open_locked().unlock_with_password(PASSWORD), allowed_sids={"S-1-5-18"}
        )
        pipe = self._pipe_name()
        server = winpipe.PipeServer(pipe, winpipe.build_sddl(my_sid, {my_sid}), broker.pipe_handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            resp = winpipe.request(pipe, {"secret": "X", "path": "y", "method": "GET",
                                          "headers": {}, "body_b64": None})
        finally:
            server.close()
        self.assertEqual(resp["status"], 403)  # peer SID not authorized


class PgProtocolTests(unittest.TestCase):
    def test_scram_rfc7677_vector(self):
        from blindvault.broker import pgproxy
        client_first_bare = b"n=user,r=rOprNGfwEbeRWgbNEkqO"
        server_first = (b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                        b"s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
        client_final, server_sig, _nonce = pgproxy.scram_client_final(
            "pencil", client_first_bare, server_first)
        self.assertTrue(client_final.endswith(b"p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="))
        self.assertEqual(server_sig, b"6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")

    def test_md5_vector(self):
        from blindvault.broker import pgproxy
        self.assertEqual(
            pgproxy.md5_password("secret", "alice", b"\x01\x02\x03\x04"),
            "md598a0412b9c31436fc53776e863350083",
        )

    def test_framing_roundtrip(self):
        import socket
        import struct

        from blindvault.broker import pgproxy
        a, b = socket.socketpair()
        try:
            pgproxy.write_message(a, b"R", struct.pack("!I", 0))
            t, p = pgproxy.read_message(b)
            self.assertEqual((t, p), (b"R", struct.pack("!I", 0)))
        finally:
            a.close()
            b.close()


class PgConnectorTests(TempVaultCase):
    def test_cleartext_end_to_end(self):
        import socket
        import struct
        import threading

        from blindvault.broker import pgproxy
        from blindvault.core.service import Vault

        received = {}
        backend = socket.create_server(("127.0.0.1", 0))
        backend_port = backend.getsockname()[1]

        def mock_backend():
            conn, _ = backend.accept()
            try:
                length = struct.unpack("!I", pgproxy._recv_exact(conn, 4))[0]
                received["startup"] = pgproxy._recv_exact(conn, length - 4)
                pgproxy.write_message(conn, b"R", struct.pack("!I", 3))   # cleartext request
                _t, payload = pgproxy.read_message(conn)
                received["password"] = payload.rstrip(b"\x00").decode()
                pgproxy.write_message(conn, b"R", struct.pack("!I", 0))   # AuthenticationOk
                pgproxy.write_message(conn, b"S", b"server_version\x00test\x00")
                pgproxy.write_message(conn, b"K", struct.pack("!II", 1, 2))
                pgproxy.write_message(conn, b"Z", b"I")                   # ReadyForQuery
                while True:                                               # echo (splice target)
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
            finally:
                conn.close()

        threading.Thread(target=mock_backend, daemon=True).start()

        Vault.initialize(PASSWORD)
        vault = Vault.open_locked().unlock_with_password(PASSWORD)
        vault.add("PGPASS", "s3cr3t-db-pw")
        vault.set_policy("PGPASS", [], ["127.0.0.1"])  # may only be used against the backend host

        connector = pgproxy.PgConnector(
            Vault.open_locked().unlock_with_password(PASSWORD),
            "PGPASS", "127.0.0.1", backend_port, user="blindvault", database="blindvault",
        )

        listener = socket.create_server(("127.0.0.1", 0))
        cport = listener.getsockname()[1]
        agent = socket.create_connection(("127.0.0.1", cport))
        agent.settimeout(10)
        client_conn, _ = listener.accept()
        threading.Thread(target=connector._handle, args=(client_conn,), daemon=True).start()

        try:
            agent.sendall(struct.pack("!II", 8, pgproxy.SSL_REQUEST_CODE))
            self.assertEqual(agent.recv(1), b"N")                         # SSL declined
            body = (struct.pack("!I", pgproxy.PROTOCOL_30)
                    + b"user\x00blindvault\x00database\x00blindvault\x00\x00")
            agent.sendall(struct.pack("!I", len(body) + 4) + body)

            seen = []
            while True:
                t, _p = pgproxy.read_message(agent)
                seen.append(t)
                if t == b"Z":
                    break
            self.assertIn(b"R", seen)   # AuthenticationOk reached the agent
            self.assertIn(b"Z", seen)   # ReadyForQuery

            agent.sendall(b"hello-splice")                                # raw stream after Z
            self.assertEqual(pgproxy._recv_exact(agent, 12), b"hello-splice")
        finally:
            agent.close()
            listener.close()
            backend.close()

        self.assertEqual(received["password"], "s3cr3t-db-pw")            # broker injected it
        self.assertIn(b"blindvault", received["startup"])                 # connector's own startup user

    @unittest.skipUnless(os.environ.get("BLINDVAULT_TEST_PG"),
                         "set BLINDVAULT_TEST_PG to run against a real PostgreSQL")
    def test_real_postgres_scram(self):
        import socket
        import struct
        import threading

        from blindvault.broker import pgproxy
        from blindvault.core.service import Vault

        host = os.environ.get("PGHOST", "127.0.0.1")
        port = int(os.environ.get("PGPORT", "5432"))
        user = os.environ.get("PGUSER", "postgres")
        password = os.environ.get("PGPASSWORD", "postgres")
        database = os.environ.get("PGDATABASE", "postgres")

        Vault.initialize(PASSWORD)
        vault = Vault.open_locked().unlock_with_password(PASSWORD)
        vault.add("PGPASS", password)
        vault.set_policy("PGPASS", [], [host])

        connector = pgproxy.PgConnector(
            Vault.open_locked().unlock_with_password(PASSWORD),
            "PGPASS", host, port, user=user, database=database,
        )
        listener = socket.create_server(("127.0.0.1", 0))
        cport = listener.getsockname()[1]
        agent = socket.create_connection(("127.0.0.1", cport))
        agent.settimeout(20)
        client_conn, _ = listener.accept()
        threading.Thread(target=connector._handle, args=(client_conn,), daemon=True).start()

        try:
            kv = f"user\x00{user}\x00database\x00{database}\x00".encode() + b"\x00"
            body = struct.pack("!I", pgproxy.PROTOCOL_30) + kv
            agent.sendall(struct.pack("!I", len(body) + 4) + body)
            while True:                                   # real SCRAM happens behind this
                t, p = pgproxy.read_message(agent)
                if t == b"E":
                    self.fail("startup error: " + pgproxy._parse_error(p))
                if t == b"Z":
                    break
            query = b"SELECT 1\x00"
            agent.sendall(b"Q" + struct.pack("!I", len(query) + 4) + query)
            value = None
            while True:
                t, p = pgproxy.read_message(agent)
                if t == b"D":                             # DataRow
                    off = 2
                    flen = struct.unpack("!i", p[off:off + 4])[0]
                    off += 4
                    value = p[off:off + flen]
                if t == b"Z":
                    break
            self.assertEqual(value, b"1")                 # queried real PG via SCRAM, no password
        finally:
            agent.close()
            listener.close()


class GuiImportTest(unittest.TestCase):
    def test_gui_module_imports(self):
        try:
            gui = importlib.import_module("blindvault.gui")
        except ImportError as exc:
            self.skipTest(f"GUI dependencies unavailable: {exc}")
        self.assertTrue(hasattr(gui, "main"))


if __name__ == "__main__":
    unittest.main()
