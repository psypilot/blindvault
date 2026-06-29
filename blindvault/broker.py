"""The resolver broker: a credential-injecting reverse proxy.

The agent points its HTTP requests at this proxy:

    http://127.0.0.1:8771/<SECRET_NAME>/<path...>          (Phase 1, TCP loopback)
    curl --unix-socket <path> http://localhost/<SECRET>/…  (Phase 2, Unix socket)

The broker holds the unlocked vault, looks up <SECRET_NAME>, derives the upstream
host from that secret's ``allow_hosts`` policy (so the AGENT cannot choose the
destination), injects the real value as an ``Authorization: Bearer`` header on its
own side of the wire, forwards to the upstream, and returns the response with the
secret scrubbed out. The plaintext secret never enters the agent's process.

Phase 2 adds the OS boundary: serve over a **Unix-domain socket** and authenticate
the connecting process by its **UID** (``SO_PEERCRED``), against an allow-list.
Run as a dedicated OS user (docs/DEPLOY-linux.md) so the agent's user cannot read
the broker's memory or the vault file.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

from . import peercred
from .crypto import VaultError

DEFAULT_PORT = 8771
MAX_RESPONSE_BYTES = 1 << 20  # 1 MiB cap on what we read/return
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host",
    "authorization",
}
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Broker:
    """Holds an unlocked vault and serves the injecting proxy."""

    def __init__(self, vault, audit_path=None, max_response: int = MAX_RESPONSE_BYTES,
                 allowed_uids: set | None = None, allowed_sids: set | None = None) -> None:
        self.vault = vault                  # an UNLOCKED Vault
        self.audit_path = audit_path
        self.max_response = max_response
        self.allowed_uids = allowed_uids    # None => no UID restriction (TCP/Phase 1)
        self.allowed_sids = allowed_sids    # Windows named-pipe SID allow-list

    # -- authorization ---------------------------------------------------- #
    def authorize_uid(self, uid: int | None) -> bool:
        if self.allowed_uids is None:
            return True
        return uid is not None and uid in self.allowed_uids

    def authorize_sid(self, sid: str | None) -> bool:
        if self.allowed_sids is None:
            return True
        return sid is not None and sid in self.allowed_sids

    # -- audit ------------------------------------------------------------ #
    def audit(self, **fields) -> None:
        if not self.audit_path:
            return
        try:
            with open(self.audit_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"ts": _now(), **fields}) + "\n")
        except OSError:
            pass

    # -- the core operation ---------------------------------------------- #
    def proxy(self, secret_name: str, rest: str, method: str, headers: dict,
              body: bytes | None, uid: int | None = None) -> tuple[int, dict, bytes]:
        """Resolve, enforce policy, inject, forward. Returns (status, headers, body)."""
        try:
            value, policy = self.vault.resolve(secret_name)
        except VaultError:
            self.audit(event="proxy", uid=uid, secret=secret_name, decision="blocked",
                       reason="unknown secret")
            return 404, {}, b"unknown secret\n"

        hosts = (policy or {}).get("allow_hosts") or []
        if not hosts:
            self.audit(event="proxy", uid=uid, secret=secret_name, decision="blocked",
                       reason="no allow_hosts policy")
            return 403, {}, (
                f"secret '{secret_name}' has no allow_hosts policy; refusing to proxy "
                f"(set one with: bv policy {secret_name} --allow-host HOST)\n"
            ).encode()

        host = hosts[0]
        scheme = "http" if host.split(":")[0] in _LOOPBACK else "https"
        upstream = f"{scheme}://{host}/{rest}"

        req = urllib.request.Request(upstream, data=body, method=method)
        for name, val in headers.items():
            if name.lower() in _HOP_BY_HOP:
                continue
            req.add_header(name, val)
        req.add_header("Authorization", f"Bearer {value}")  # the real secret, our side only

        ctx = ssl.create_default_context() if scheme == "https" else None
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                status, raw, resp_headers = resp.status, resp.read(self.max_response), resp.headers
        except urllib.error.HTTPError as exc:
            status, raw, resp_headers = exc.code, exc.read(self.max_response), exc.headers
        except Exception:
            self.audit(event="proxy", uid=uid, secret=secret_name, target=host,
                       decision="blocked", reason="upstream error")
            return 502, {}, b"upstream request failed\n"

        # Scrub the secret out of the response, in case the upstream echoes it.
        raw = raw.replace(value.encode("utf-8"), b"[redacted:" + secret_name.encode() + b"]")

        out_headers = {k: v for k, v in resp_headers.items()
                       if k.lower() not in _HOP_BY_HOP and k.lower() != "content-encoding"}
        self.audit(event="proxy", uid=uid, secret=secret_name, target=host, decision="allowed",
                   method=method, status=status, bytes_out=len(raw))
        return status, out_headers, raw

    # -- servers ---------------------------------------------------------- #
    def make_server(self, host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
        server = ThreadingHTTPServer((host, port), _ProxyHandler)
        server.broker = self  # type: ignore[attr-defined]
        return server

    def serve(self, host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> int:
        server = self.make_server(host, port)
        bound_host, bound_port = server.server_address[:2]
        print(f"BlindVault proxy listening on http://{bound_host}:{bound_port}")
        print(f"Point the agent at:  http://{bound_host}:{bound_port}/<SECRET_NAME>/<path>")
        print("The agent never sees the secret; it is injected here. Ctrl+C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping.")
        finally:
            server.shutdown()
        return 0

    def make_unix_server(self, path: str):
        if _UnixHTTPServer is None:
            raise VaultError("Unix-domain sockets are not available on this platform.")
        server = _UnixHTTPServer(path, _ProxyHandler)
        server.broker = self  # type: ignore[attr-defined]
        return server

    # -- Windows named pipe (Phase 2) ------------------------------------- #
    def pipe_handler(self, client_sid: str, request: dict) -> dict:
        """Authenticate the client SID, then run the proxy. Returns a JSON-able dict."""
        import base64

        if not self.authorize_sid(client_sid):
            self.audit(event="request", sid=client_sid, decision="blocked",
                       reason="sid-not-authorized")
            return {"status": 403, "headers": {},
                    "body_b64": base64.b64encode(b"connection not authorized\n").decode()}
        secret = request.get("secret", "")
        path = request.get("path", "")
        method = request.get("method", "GET")
        headers = request.get("headers") or {}
        body = base64.b64decode(request["body_b64"]) if request.get("body_b64") else None
        status, out_headers, out = self.proxy(secret, path, method, headers, body, uid=client_sid)
        return {"status": status, "headers": dict(out_headers),
                "body_b64": base64.b64encode(out).decode()}

    def serve_pipe(self, pipe_name: str) -> int:
        from . import winpipe

        service_sid = winpipe.current_user_sid()
        dacl_sids = set(self.allowed_sids or set()) | {service_sid}
        sddl = winpipe.build_sddl(service_sid, dacl_sids)
        server = winpipe.PipeServer(pipe_name, sddl, self.pipe_handler)
        print(f"BlindVault proxy listening on pipe:{pipe_name}")
        print(f'Point the agent at:  bv proxy --pipe "{pipe_name}" GET <SECRET> <path>')
        if self.allowed_sids is not None:
            print(f"Authorized SIDs: {sorted(self.allowed_sids)}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping.")
        finally:
            server.close()
        return 0

    def serve_unix(self, path: str) -> int:
        server = self.make_unix_server(path)
        print(f"BlindVault proxy listening on unix:{path}")
        print(f"Point the agent at:  curl --unix-socket {path} http://localhost/<SECRET>/<path>")
        if self.allowed_uids is not None:
            print(f"Authorized UIDs: {sorted(self.allowed_uids)}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping.")
        finally:
            server.server_close()
        return 0


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:  # keep stdout clean; we have the audit log
        pass

    def _dispatch(self) -> None:
        broker: Broker = self.server.broker  # type: ignore[attr-defined]
        uid = peercred.peer_uid(self.connection)
        if not broker.authorize_uid(uid):
            broker.audit(event="request", uid=uid, decision="blocked", reason="uid-not-authorized")
            self._send(403, {}, b"connection not authorized\n")
            return

        path = self.path.lstrip("/")
        secret_name, _, rest = path.partition("/")
        if not secret_name:
            self._send(400, {}, b"usage: /<SECRET_NAME>/<path>\n")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        status, headers, out = broker.proxy(secret_name, rest, self.command,
                                            dict(self.headers.items()), body, uid=uid)
        self._send(status, headers, out)

    def _send(self, status: int, headers: dict, body: bytes) -> None:
        self.send_response(status)
        for name, val in headers.items():
            self.send_header(name, val)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _dispatch


# Unix-socket HTTP server, defined only where AF_UNIX exists (keeps Windows imports safe).
if hasattr(socket, "AF_UNIX"):

    class _UnixHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        address_family = socket.AF_UNIX
        daemon_threads = True

        def __init__(self, path: str, handler) -> None:
            self._path = path
            super().__init__(path, handler)

        def server_bind(self) -> None:
            # Replace a stale socket, bind, then restrict to owner+group.
            try:
                os.unlink(self._path)
            except OSError:
                pass
            socketserver.TCPServer.server_bind(self)  # bypass HTTPServer's host/port logic
            self.server_name = "localhost"
            self.server_port = 0
            try:
                os.chmod(self._path, 0o660)
            except OSError:
                pass

        def server_close(self) -> None:
            super().server_close()
            try:
                os.unlink(self._path)
            except OSError:
                pass

else:  # pragma: no cover - Windows without AF_UNIX
    _UnixHTTPServer = None
