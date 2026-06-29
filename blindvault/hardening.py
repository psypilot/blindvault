"""Process self-protection for the broker daemon (Linux; no-ops elsewhere).

These reduce the ways the data key can leak out of the broker's own memory and
make it harder for a same-user process to inspect it. They are defense-in-depth;
the real boundary is running the broker as a separate OS user (see
docs/DEPLOY-linux.md). Everything here is best-effort and never fatal.
"""

from __future__ import annotations

import os
import sys


def harden_process() -> dict:
    """Apply best-effort hardening; return a map of what succeeded."""
    results: dict[str, bool] = {}
    if not sys.platform.startswith("linux"):
        return results
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return results

    PR_SET_DUMPABLE = 4      # 0 => no /proc/<pid>/mem, no core, no same-uid PTRACE_ATTACH
    PR_SET_NO_NEW_PRIVS = 38
    MCL_CURRENT, MCL_FUTURE = 1, 2

    results["dumpable_off"] = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
    results["no_new_privs"] = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
    results["mlockall"] = libc.mlockall(MCL_CURRENT | MCL_FUTURE) == 0  # needs RLIMIT_MEMLOCK

    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        results["core_off"] = True
    except (ValueError, OSError, ImportError):
        results["core_off"] = False
    return results


def ptrace_scope_warning() -> str | None:
    """Warn if same-user ptrace is unrestricted (key memory is then exposed)."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope", encoding="ascii") as handle:
            scope = handle.read().strip()
    except OSError:
        return None
    if scope == "0":
        return (
            "WARNING: kernel.yama.ptrace_scope=0 — a same-user process can ptrace this "
            "broker and read secrets from its memory. Set it to 1 or higher "
            "(`sysctl -w kernel.yama.ptrace_scope=1`) and run the broker as a dedicated "
            "OS user (see docs/DEPLOY-linux.md)."
        )
    return None


def drop_privileges(user: str) -> None:
    """If running as root, drop to ``user`` (groups -> gid -> uid) and verify the
    drop is irreversible. No-op if not POSIX or not root."""
    if os.name != "posix" or not hasattr(os, "getuid") or os.getuid() != 0:
        return
    import pwd

    pw = pwd.getpwnam(user)
    os.initgroups(user, pw.pw_gid)   # set supplementary groups (needs root)
    os.setgid(pw.pw_gid)             # gid before uid
    os.setuid(pw.pw_uid)             # the last root privilege goes here
    if os.getuid() != pw.pw_uid or os.geteuid() != pw.pw_uid:
        raise SystemExit("blindvault: failed to drop privileges")
    try:
        os.setuid(0)
        raise SystemExit("blindvault: FATAL — regained root after dropping privileges")
    except PermissionError:
        pass  # good: cannot regain root
