"""Windows named-pipe transport with SID peer authentication (Phase 2, Windows).

The OS boundary on Windows: the broker is a named-pipe server with a tight DACL
(no ``Everyone`` access; the agent's SID gets read + write-data only, never the
right to create pipe instances). It authenticates every client by its **token
SID** via ``ImpersonateNamedPipeClient`` — never the spoofable client PID
(``GetNamedPipeClientProcessId``). Run the broker under a dedicated account and a
non-admin agent (without ``SeDebugPrivilege``) cannot read its memory or the vault.

Frames are length-prefixed (4-byte big-endian) JSON over a byte-mode pipe — the
same wire shape as docs/DESIGN-resolver.md. Requires ``pip install pywin32``.
"""

from __future__ import annotations

import struct

try:
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32pipe
    import win32security
    _HAVE_PYWIN32 = True
except ImportError:  # pragma: no cover - non-Windows or pywin32 missing
    _HAVE_PYWIN32 = False

DEFAULT_PIPE = r"\\.\pipe\BlindVault"
MAX_FRAME = 4 << 20  # 4 MiB

# Win32 numeric constants (defined explicitly to avoid version-specific attrs).
_PIPE_ACCESS_DUPLEX = 0x00000003
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_PIPE_TYPE_BYTE = 0x0
_PIPE_READMODE_BYTE = 0x0
_PIPE_WAIT = 0x0
_PIPE_REJECT_REMOTE_CLIENTS = 0x8
_PIPE_UNLIMITED_INSTANCES = 255
_GENERIC_RW = 0x80000000 | 0x40000000
_OPEN_EXISTING = 3
_SECURITY_SQOS_PRESENT = 0x00100000
_SECURITY_IDENTIFICATION = 0x00010000
# Read + write-data, WITHOUT FILE_CREATE_PIPE_INSTANCE (== FILE_APPEND_DATA, 0x4).
_CLIENT_ACCESS_MASK = 0x0012019B


def _require() -> None:
    if not _HAVE_PYWIN32:
        raise RuntimeError(
            "The Windows named-pipe broker needs pywin32. Install it with: pip install pywin32"
        )


def current_user_sid() -> str:
    _require()
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    sid, _attrs = win32security.GetTokenInformation(token, win32security.TokenUser)
    return win32security.ConvertSidToStringSid(sid)


def build_sddl(service_sid: str, client_sids) -> str:
    """A protected DACL: the service gets full control; each client SID gets
    read + write-data only (never create-instance). Everyone else: no access."""
    aces = f"(A;;GA;;;{service_sid})"
    for sid in client_sids:
        if sid and sid != service_sid:
            aces += f"(A;;0x{_CLIENT_ACCESS_MASK:08x};;;{sid})"
    return "D:P" + aces


def _read_exact(pipe, n: int) -> bytes:
    data = b""
    while len(data) < n:
        _hr, chunk = win32file.ReadFile(pipe, n - len(data))
        if not chunk:
            raise IOError("pipe closed")
        data += chunk
    return data


def _read_frame(pipe) -> bytes:
    (length,) = struct.unpack(">I", _read_exact(pipe, 4))
    if length > MAX_FRAME:
        raise IOError("frame too large")
    return _read_exact(pipe, length) if length else b""


def _write_frame(pipe, data: bytes) -> None:
    win32file.WriteFile(pipe, struct.pack(">I", len(data)) + data)


def client_sid_of(pipe) -> str:
    """The SID of the connected client (call AFTER reading a request frame)."""
    win32security.ImpersonateNamedPipeClient(pipe)  # lives in win32security, not win32pipe
    try:
        thread_token = win32security.OpenThreadToken(
            win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True
        )
        sid, _attrs = win32security.GetTokenInformation(thread_token, win32security.TokenUser)
        return win32security.ConvertSidToStringSid(sid)
    finally:
        win32security.RevertToSelf()  # never touch the vault while impersonating


class PipeServer:
    """Serves length-prefixed JSON frames; ``handler(client_sid, request) -> response``."""

    def __init__(self, pipe_name: str, sddl: str, handler) -> None:
        _require()
        self.pipe_name = pipe_name
        self.sddl = sddl
        self.handler = handler
        self._stop = False

    def _security_attributes(self):
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            self.sddl, win32security.SDDL_REVISION_1
        )
        sa.bInheritHandle = False
        return sa

    def _create_instance(self, first: bool):
        open_mode = _PIPE_ACCESS_DUPLEX
        if first:
            open_mode |= _FILE_FLAG_FIRST_PIPE_INSTANCE  # fail if the name is squatted
        pipe_mode = (_PIPE_TYPE_BYTE | _PIPE_READMODE_BYTE | _PIPE_WAIT
                     | _PIPE_REJECT_REMOTE_CLIENTS)
        return win32pipe.CreateNamedPipe(
            self.pipe_name, open_mode, pipe_mode, _PIPE_UNLIMITED_INSTANCES,
            65536, 65536, 0, self._security_attributes(),
        )

    def serve_forever(self) -> None:
        import json

        first = True
        while not self._stop:
            pipe = self._create_instance(first)
            first = False
            try:
                win32pipe.ConnectNamedPipe(pipe, None)
                if self._stop:
                    break
                request = json.loads(_read_frame(pipe).decode("utf-8"))
                client_sid = client_sid_of(pipe)            # after reading the frame
                response = self.handler(client_sid, request)
                _write_frame(pipe, json.dumps(response).encode("utf-8"))
                win32file.FlushFileBuffers(pipe)            # let the client drain before disconnect
            except (pywintypes.error, IOError, ValueError):
                pass
            finally:
                try:
                    win32pipe.DisconnectNamedPipe(pipe)
                except Exception:
                    pass
                try:
                    win32file.CloseHandle(pipe)
                except Exception:
                    pass

    def close(self) -> None:
        self._stop = True
        try:  # unblock a ConnectNamedPipe that is waiting
            handle = win32file.CreateFile(
                self.pipe_name, win32con.GENERIC_READ, 0, None, _OPEN_EXISTING, 0, None
            )
            win32file.CloseHandle(handle)
        except Exception:
            pass


def request(pipe_name: str, payload: dict, timeout_ms: int = 10000) -> dict:
    """Client: connect, send one JSON request, read one JSON response."""
    _require()
    import json

    win32pipe.WaitNamedPipe(pipe_name, timeout_ms)
    handle = win32file.CreateFile(
        pipe_name, _GENERIC_RW, 0, None, _OPEN_EXISTING,
        # SECURITY_IDENTIFICATION: let the server identify us, but NOT impersonate us.
        _SECURITY_SQOS_PRESENT | _SECURITY_IDENTIFICATION, None,
    )
    try:
        _write_frame(handle, json.dumps(payload).encode("utf-8"))
        return json.loads(_read_frame(handle).decode("utf-8"))
    finally:
        win32file.CloseHandle(handle)
