"""Authenticate the OS user on the other end of a Unix-domain socket.

The whole Phase 2 boundary rests on this: the daemon authorizes on the connecting
process's **UID**, captured by the kernel at connect time and unforgeable by the
peer. We never authorize on PID (PIDs are reused and spoofable — the polkit
CVE-2019-6133 and Project Zero named-pipe lessons).

Returns ``None`` when peer credentials are unavailable (non-Unix socket, or an
unsupported platform such as Windows), so callers must decide what that means.
"""

from __future__ import annotations

import socket
import struct
import sys


def peer_uid(conn: socket.socket) -> int | None:
    """The effective UID of the process connected on ``conn`` (AF_UNIX only)."""
    try:
        if conn.family != socket.AF_UNIX:
            return None
    except (AttributeError, OSError):
        return None

    if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
        try:
            # struct ucred { pid_t pid; uid_t uid; gid_t gid; } -> three ints
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
            return uid
        except OSError:
            return None

    if sys.platform == "darwin":
        return _getpeereid_uid(conn.fileno())

    return None


def _getpeereid_uid(fd: int) -> int | None:
    """macOS/BSD: getpeereid(2) yields the peer's effective uid/gid."""
    import ctypes
    import ctypes.util

    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        euid = ctypes.c_uint32()
        egid = ctypes.c_uint32()
        if libc.getpeereid(fd, ctypes.byref(euid), ctypes.byref(egid)) != 0:
            return None
        return euid.value
    except (OSError, AttributeError):
        return None
