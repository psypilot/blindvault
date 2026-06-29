"""PostgreSQL credential-injecting connector (Secretless-style).

The agent's psql/libpq connects to a local listener with **no password**. The
broker holds the real DB password, completes the PostgreSQL auth handshake with
the backend itself (cleartext / md5 / SCRAM-SHA-256), tells the agent it logged
in, and then transparently streams bytes. The password never reaches the agent.

Wire-format notes: integers are big-endian; a message's Int32 length includes
itself but not the leading type byte; StartupMessage/SSLRequest have no type byte.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import socket
import struct
import threading

SSL_REQUEST_CODE = 80877103
GSSENC_REQUEST_CODE = 80877104
CANCEL_REQUEST_CODE = 80877102
PROTOCOL_30 = 196608


# --------------------------------------------------------------------------- #
# low-level framing
# --------------------------------------------------------------------------- #
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def read_message(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read one typed message -> (type_byte, payload)."""
    type_byte = _recv_exact(sock, 1)
    (length,) = struct.unpack("!I", _recv_exact(sock, 4))
    payload = _recv_exact(sock, length - 4) if length > 4 else b""
    return type_byte, payload


def write_message(sock: socket.socket, type_byte: bytes, payload: bytes = b"") -> None:
    sock.sendall(type_byte + struct.pack("!I", len(payload) + 4) + payload)


def write_startup(sock: socket.socket, params: dict) -> None:
    body = struct.pack("!I", PROTOCOL_30)
    for key, value in params.items():
        body += key.encode() + b"\x00" + value.encode() + b"\x00"
    body += b"\x00"
    sock.sendall(struct.pack("!I", len(body) + 4) + body)


def _send_error(sock: socket.socket, message: str, code: str = "28000") -> None:
    fields = b"SFATAL\x00" + b"C" + code.encode() + b"\x00" + b"M" + message.encode() + b"\x00" + b"\x00"
    try:
        write_message(sock, b"E", fields)
    except OSError:
        pass


def _parse_error(payload: bytes) -> str:
    for field in payload.split(b"\x00"):
        if field[:1] == b"M":
            return field[1:].decode("utf-8", "replace")
    return "error"


# --------------------------------------------------------------------------- #
# auth credential computation (pure, unit-tested against RFC vectors)
# --------------------------------------------------------------------------- #
def md5_password(password: str, username: str, salt: bytes) -> str:
    inner = hashlib.md5((password + username).encode("utf-8")).hexdigest()
    outer = hashlib.md5(inner.encode("ascii") + salt).hexdigest()
    return "md5" + outer


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def scram_client_final(password: str, client_first_bare: bytes, server_first: bytes):
    """Given the client-first-bare and the server-first-message, return
    (client_final_message, expected_server_signature_b64, full_nonce)."""
    parts = dict(p.split("=", 1) for p in server_first.decode("ascii").split(","))
    nonce = parts["r"]
    salt = base64.b64decode(parts["s"])
    iters = int(parts["i"])

    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, 32)
    client_key = _hmac(salted, b"Client Key")
    stored_key = hashlib.sha256(client_key).digest()
    final_no_proof = b"c=biws,r=" + nonce.encode("ascii")
    auth_message = client_first_bare + b"," + server_first + b"," + final_no_proof
    client_signature = _hmac(stored_key, auth_message)
    proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
    client_final = final_no_proof + b",p=" + base64.b64encode(proof)

    server_key = _hmac(salted, b"Server Key")
    server_signature = base64.b64encode(_hmac(server_key, auth_message))
    return client_final, server_signature, nonce


# --------------------------------------------------------------------------- #
# backend authentication
# --------------------------------------------------------------------------- #
def _scram_exchange(backend: socket.socket, password: str) -> None:
    cnonce = base64.b64encode(os.urandom(18)).decode("ascii")
    client_first_bare = b"n=,r=" + cnonce.encode("ascii")     # PG: empty username field
    client_first = b"n,," + client_first_bare
    init = b"SCRAM-SHA-256\x00" + struct.pack("!I", len(client_first)) + client_first
    write_message(backend, b"p", init)

    type_byte, payload = read_message(backend)
    if type_byte == b"E":
        raise ConnectionError("SCRAM: " + _parse_error(payload))
    if struct.unpack("!I", payload[:4])[0] != 11:
        raise ConnectionError("SCRAM: expected SASLContinue")
    server_first = payload[4:]
    if not dict(p.split("=", 1) for p in server_first.decode().split(","))["r"].startswith(cnonce):
        raise ConnectionError("SCRAM: server nonce does not start with client nonce")

    client_final, server_sig, _nonce = scram_client_final(password, client_first_bare, server_first)
    write_message(backend, b"p", client_final)

    type_byte, payload = read_message(backend)
    if type_byte == b"E":
        raise ConnectionError("SCRAM: " + _parse_error(payload))
    if struct.unpack("!I", payload[:4])[0] != 12:
        raise ConnectionError("SCRAM: expected SASLFinal")
    server_final = payload[4:]
    got = dict(p.split("=", 1) for p in server_final.decode().split(","))["v"]
    if got.encode("ascii") != server_sig:
        raise ConnectionError("SCRAM: server signature mismatch (possible MITM)")


def _authenticate_backend(backend: socket.socket, user: str, password: str) -> None:
    while True:
        type_byte, payload = read_message(backend)
        if type_byte == b"E":
            raise ConnectionError("backend auth failed: " + _parse_error(payload))
        if type_byte != b"R":
            raise ConnectionError(f"unexpected message during auth: {type_byte!r}")
        sub = struct.unpack("!I", payload[:4])[0]
        if sub == 0:                       # AuthenticationOk
            return
        if sub == 3:                       # cleartext
            write_message(backend, b"p", password.encode("utf-8") + b"\x00")
        elif sub == 5:                     # md5
            write_message(backend, b"p", md5_password(password, user, payload[4:8]).encode() + b"\x00")
        elif sub == 10:                    # SASL
            if b"SCRAM-SHA-256" not in payload[4:].split(b"\x00"):
                raise ConnectionError("backend requires an unsupported SASL mechanism")
            _scram_exchange(backend, password)
        else:
            raise ConnectionError(f"unsupported authentication request {sub}")


# --------------------------------------------------------------------------- #
# startup negotiation + the bridge
# --------------------------------------------------------------------------- #
def negotiate_and_read_startup(client: socket.socket) -> dict:
    """Decline SSL/GSS, then read the StartupMessage; return its parameters."""
    while True:
        length, code = struct.unpack("!II", _recv_exact(client, 8))
        if code in (SSL_REQUEST_CODE, GSSENC_REQUEST_CODE):
            client.sendall(b"N")           # decline; client proceeds in cleartext
            continue
        if code == CANCEL_REQUEST_CODE:
            raise ConnectionError("query cancellation is not supported by the connector")
        if code != PROTOCOL_30:
            raise ConnectionError(f"unexpected startup code {code}")
        rest = _recv_exact(client, length - 8)
        params, fields, i = {}, rest.split(b"\x00"), 0
        while i + 1 < len(fields) and fields[i]:
            params[fields[i].decode()] = fields[i + 1].decode()
            i += 2
        return params


def _splice(a: socket.socket, b: socket.socket) -> None:
    def pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def bridge(client: socket.socket, backend_host: str, backend_port: int,
           user: str, password: str, database: str | None, client_params: dict) -> None:
    backend = socket.create_connection((backend_host, backend_port), timeout=30)
    try:
        params = {"user": user}
        db = database or client_params.get("database")
        if db:
            params["database"] = db
        for key in ("application_name", "client_encoding"):
            if key in client_params:
                params[key] = client_params[key]
        write_startup(backend, params)
        _authenticate_backend(backend, user, password)

        # Tell the passwordless client it authenticated, then forward the backend's
        # ParameterStatus/BackendKeyData up to ReadyForQuery, then splice raw.
        write_message(client, b"R", struct.pack("!I", 0))   # AuthenticationOk
        while True:
            type_byte, payload = read_message(backend)
            write_message(client, type_byte, payload)
            if type_byte in (b"Z", b"E"):                    # ReadyForQuery or fatal error
                if type_byte == b"E":
                    return
                break
        _splice(client, backend)
    finally:
        backend.close()


# --------------------------------------------------------------------------- #
# the listener
# --------------------------------------------------------------------------- #
class PgConnector:
    def __init__(self, vault, secret_name, backend_host, backend_port, user,
                 database=None, audit=None) -> None:
        self.vault = vault
        self.secret_name = secret_name
        self.backend_host = backend_host
        self.backend_port = int(backend_port)
        self.user = user
        self.database = database
        self._audit = audit or (lambda **_: None)

    def _handle(self, client: socket.socket) -> None:
        from ..agent import policy

        try:
            client_params = negotiate_and_read_startup(client)
            value, pol = self.vault.resolve(self.secret_name)
            allowed = [h.split(":")[0] for h in (pol or {}).get("allow_hosts") or []]
            if not allowed or not policy.host_allowed(self.backend_host, allowed):
                self._audit(event="pg", secret=self.secret_name, target=self.backend_host,
                            decision="blocked", reason="backend host not in allow_hosts")
                _send_error(client, f"secret '{self.secret_name}' may not be used with "
                                    f"{self.backend_host} (set --allow-host accordingly)")
                return
            self._audit(event="pg", secret=self.secret_name, target=self.backend_host,
                        decision="allowed", user=self.user)
            bridge(client, self.backend_host, self.backend_port, self.user, value,
                   self.database, client_params)
        except Exception as exc:
            _send_error(client, f"connector error: {exc}")
        finally:
            try:
                client.close()
            except OSError:
                pass

    def serve(self, listen_host: str, listen_port: int) -> int:
        server = socket.create_server((listen_host, listen_port), reuse_port=False)
        print(f"BlindVault PostgreSQL connector on {listen_host}:{listen_port}"
              f"  ->  {self.backend_host}:{self.backend_port} (as {self.user})")
        print(f"Connect with NO password, e.g.:  psql -h {listen_host} -p {listen_port} -U {self.user}")
        try:
            while True:
                client, _addr = server.accept()
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
        except KeyboardInterrupt:
            print("\nStopping.")
        finally:
            server.close()
        return 0
