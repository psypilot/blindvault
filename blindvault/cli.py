"""Command line interface: ``blindvault <command> ...``  (short alias: ``bv``)

The vault is protected by a master password. Names are visible while locked;
values require an unlock.

Agent-facing (safe — never print a value):
    init    create the vault (sets the master password)
    set     store a secret
    gen     generate a random secret the agent never sees
    ls      list secret names + descriptions (works while locked)
    rm      delete a secret
    run     run a program, injecting values and scrubbing them from output
    unlock  start a time-limited session so `run` needs no further prompts
    lock    end the session
    gui     launch the human-facing desktop app

Human-only escape hatch (always requires the master password, never a session):
    reveal  print a plaintext value
    passwd  change the master password
"""

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys

from . import __version__
from .agent import envfile, policy, resolver
from .core import config, session
from .core.crypto import MIN_SCRYPT_N, AuthError, VaultError
from .core.service import SOURCE_MANUAL, Vault


class CliError(Exception):
    """User-facing error; turned into a clean message + exit code 1."""


# --------------------------------------------------------------------------- #
# password / input helpers
# --------------------------------------------------------------------------- #
def _password_from_env() -> str | None:
    return os.environ.get(config.ENV_PASSWORD)


def _prompt_password(prompt: str = "Master password: ", confirm: bool = False) -> str:
    try:
        pw = getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt) as exc:
        raise CliError("No password provided.") from exc
    if confirm:
        again = getpass.getpass("Confirm master password: ")
        if pw != again:
            raise CliError("Passwords do not match.")
    return pw


def _read_value_from_stdin() -> str:
    # Read bytes and decode with utf-8-sig so a UTF-8 BOM (which PowerShell and
    # some other shells prepend when piping) is stripped regardless of the
    # console's locale encoding. Fall back to text mode for test doubles
    # (StringIO) that have no binary buffer.
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is not None:
        data = buffer.read().decode("utf-8-sig", errors="replace")
    else:
        data = sys.stdin.read()
        if data[:1] == chr(0xFEFF):
            data = data[1:]
    # Drop one trailing newline (\r\n or \n) so piped input works, but keep any
    # internal newlines for multi-line secrets such as PEM keys.
    if data.endswith("\r\n"):
        data = data[:-2]
    elif data.endswith("\n"):
        data = data[:-1]
    return data


def _parse_env_spec(spec: str) -> tuple[str, str]:
    if "=" not in spec:
        raise CliError(f"--env expects VAR=SECRET_NAME, got '{spec}'")
    var, name = spec.split("=", 1)
    if not var or not name:
        raise CliError(f"--env expects VAR=SECRET_NAME, got '{spec}'")
    return var, name


def _warn_weak_kdf(vault: Vault) -> None:
    n = vault.kdf_n()
    if isinstance(n, int) and n < MIN_SCRYPT_N and os.environ.get("BLINDVAULT_ALLOW_WEAK_KDF") != "1":
        print(
            f"warning: this vault's key-derivation cost is weak (scrypt n={n} < {MIN_SCRYPT_N}); "
            "run `blindvault passwd --rekey` to strengthen it.",
            file=sys.stderr,
        )


def _open_locked() -> Vault:
    try:
        vault = Vault.open_locked()
    except VaultError as exc:
        raise CliError(str(exc)) from exc
    _warn_weak_kdf(vault)
    return vault


def _split_hostport(value: str, default_port: int) -> tuple[str, int]:
    if value and ":" in value:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, default_port


def _open_unlocked() -> Vault:
    """For `set`/`gen`/`run`: unlock via an active session, then env, then prompt.

    A session lets an agent use secrets after a human unlocks once. ``reveal``
    deliberately does NOT go through here.
    """
    vault = _open_locked()
    cached = session.load()
    if cached is not None:
        try:
            return vault.unlock_with_data_key(cached)
        except (VaultError, ValueError):
            session.clear()  # stale/invalid/corrupt session
    password = _password_from_env() or _prompt_password()
    try:
        return vault.unlock_with_password(password)
    except AuthError as exc:
        raise CliError(str(exc)) from exc


def _unlock_with_password_only(vault: Vault, password_stdin: bool) -> None:
    """Unlock using the master password directly — never a session or env var.

    Used by operations that must not be reachable through an unlocked session:
    ``reveal`` and changing a usage ``policy``.
    """
    password = _read_value_from_stdin() if password_stdin else _prompt_password()
    try:
        vault.unlock_with_password(password)
    except AuthError as exc:
        raise CliError(str(exc)) from exc


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_init(args: argparse.Namespace) -> int:
    if Vault.is_legacy_v1() and not args.force:
        raise CliError(
            "Found an older (v1) vault from before master-password support.\n"
            "Run `blindvault migrate` to upgrade it without losing secrets, "
            "or `init --force` to wipe it and start fresh."
        )
    if Vault.is_initialized() and not args.force:
        raise CliError(
            f"A vault already exists at {Vault.location()}.\n"
            "Use --force to reset it (this permanently destroys every stored secret)."
        )
    password = _password_from_env()
    if password is None:
        print("Choose a master password. It encrypts your vault and cannot be recovered.")
        password = _prompt_password("New master password: ", confirm=True)
    Vault.initialize(password, force=args.force)
    session.clear()
    print(f"Initialized vault at {Vault.location()}")
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    vault = _open_unlocked()
    if args.stdin:
        value = _read_value_from_stdin()
    else:
        value = getpass.getpass(f"Enter value for '{args.name}' (hidden): ")
    if not value:
        raise CliError("Refusing to store an empty value.")
    vault.add(args.name, value, args.desc or "", source=SOURCE_MANUAL)
    print(f"Stored '{args.name}' ({len(value)} chars, encrypted). Value not displayed.")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    path = args.path
    if not os.path.exists(path):
        raise CliError(f"File not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        pairs = envfile.parse(handle.read())
    if not pairs:
        raise CliError(f"No KEY=VALUE pairs found in {path}.")
    vault = _open_unlocked()
    imported = skipped = 0
    for key, value in pairs:
        if not value:
            skipped += 1
            continue
        if vault.exists(key) and not args.overwrite:
            skipped += 1
            continue
        vault.add(key, value, description=f"imported from {os.path.basename(path)}")
        imported += 1
    msg = f"Imported {imported} secret(s)"
    if skipped:
        msg += f", skipped {skipped} (already present or empty; use --overwrite to replace)"
    print(msg + ". Values were not displayed.")
    return 0


def cmd_gen(args: argparse.Namespace) -> int:
    vault = _open_unlocked()
    vault.generate(args.name, length=args.length, description=args.desc or "")
    print(
        f"Generated and stored '{args.name}' ({args.length} chars). "
        "The value was never displayed."
    )
    return 0


def cmd_ls(args: argparse.Namespace) -> int:
    vault = _open_locked()
    rows = vault.entries()
    if not rows:
        print("(vault is empty)")
        return 0
    width = max(len(row["name"]) for row in rows)
    for row in rows:
        line = f"{row['name'].ljust(width)}  {row['description']}".rstrip()
        if args.long:
            extras = [e for e in (row["source"], f"updated {row['updated']}" if row["updated"] else "") if e]
            if extras:
                line = f"{line}  ({', '.join(extras)})"
        print(line)
    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    vault = _open_unlocked()  # deletion requires auth (session or password)
    try:
        vault.delete(args.name)
    except VaultError as exc:
        raise CliError(str(exc)) from exc
    print(f"Removed '{args.name}'.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    command = args.command
    if not command:
        raise CliError(
            "No command given. Usage: blindvault run [--env VAR=NAME] -- PROGRAM ARGS"
        )
    # A reference in the program slot would inject the plaintext into argv[0] and
    # could surface it in an OS error — forbid it outright.
    if resolver.find_references(command[0]):
        raise CliError("A secret reference cannot be used as the program name.")

    vault = _open_unlocked()
    env_specs = [_parse_env_spec(spec) for spec in (args.env or [])]
    needed = set(resolver.references_in_args(command)) | {name for _, name in env_specs}

    resolved: dict[str, str] = {}
    policies: dict[str, dict | None] = {}
    for name in needed:
        if not vault.exists(name):
            raise CliError(f"Unknown secret referenced: '{name}'")
        resolved[name], policies[name] = vault.resolve(name)

    final_command = resolver.inject(command, lambda n: resolved[n])

    # Enforce each secret's usage policy before the value is ever injected.
    for name in needed:
        try:
            policy.enforce(name, policies[name], command, final_command[0])
        except policy.PolicyError as exc:
            raise CliError(f"blocked by usage policy: {exc}") from exc

    child_env = os.environ.copy()
    child_env.pop(config.ENV_PASSWORD, None)  # never leak the master password to children
    for var, name in env_specs:
        # A host-restricted secret delivered via --env could be sent anywhere by
        # the child; require it to be used directly in the command instead.
        if policies.get(name) and policies[name].get("allow_hosts"):
            raise CliError(
                f"secret '{name}' has a host policy and cannot be delivered via --env; "
                "reference it directly in the command instead."
            )
        child_env[var] = resolved[name]

    scrub = resolver.make_scrubber(resolved)
    try:
        proc = subprocess.run(  # noqa: S603 - intentional, shell=False
            final_command,
            env=child_env,
            capture_output=True,
            text=True,
        )
    except OSError:
        # Never echo final_command back — it may contain an injected secret value.
        raise CliError("Could not run the program (not found or not executable).") from None

    sys.stdout.write(scrub(proc.stdout))
    sys.stderr.write(scrub(proc.stderr))
    return proc.returncode


def cmd_unlock(args: argparse.Namespace) -> int:
    vault = _open_locked()
    password = _password_from_env() or _prompt_password()
    try:
        vault.unlock_with_password(password)
    except AuthError as exc:
        raise CliError(str(exc)) from exc
    session.save(vault.data_key, ttl_minutes=args.ttl)
    print(f"Unlocked. `run` will not prompt again for {args.ttl} minutes (until `bv lock`).")
    return 0


def cmd_lock(args: argparse.Namespace) -> int:
    session.clear()
    print("Locked. Any active session has been cleared.")
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    if not Vault.is_legacy_v1():
        raise CliError("No older (v1) vault found to migrate.")
    password = _password_from_env()
    if password is None:
        print("Set a master password to encrypt your upgraded vault.")
        password = _prompt_password("New master password: ", confirm=True)
    count = Vault.migrate_from_v1(password)
    session.clear()
    print(f"Migrated {count} secret(s) to the password-protected format. "
          "The old plaintext key file was removed.")
    return 0


def cmd_passwd(args: argparse.Namespace) -> int:
    vault = _open_locked()
    old = _prompt_password("Current master password: ")
    new = _prompt_password("New master password: ", confirm=True)
    try:
        vault.change_password(old, new, rekey=args.rekey)
    except AuthError as exc:
        raise CliError(str(exc)) from exc
    session.clear()
    extra = " Data key rotated; previously exposed keys can no longer decrypt." if args.rekey else ""
    print("Master password changed. Existing sessions were cleared." + extra)
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    vault = _open_locked()
    if not vault.exists(args.name):
        raise CliError(f"No such secret: '{args.name}'")
    # Reading or changing a policy requires the master password (never a session),
    # so an agent with only an unlocked session cannot weaken a restriction.
    _unlock_with_password_only(vault, args.password_stdin)

    changing = bool(args.clear or args.allow_command or args.allow_host)
    if changing and not args.clear:
        vault.set_policy(args.name, args.allow_command or [], args.allow_host or [])
        print(f"Set usage policy for '{args.name}'.")
    elif args.clear:
        vault.set_policy(args.name, [], [])
        print(f"Cleared usage policy for '{args.name}'.")
    else:
        pol = vault.get_policy(args.name)
        if not pol:
            print(f"'{args.name}' has no usage restrictions (usable anywhere).")
        else:
            print(f"Usage policy for '{args.name}':")
            print(f"  allowed commands: {pol.get('allow_commands') or '(any)'}")
            print(f"  allowed hosts:    {pol.get('allow_hosts') or '(any)'}")
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    vault = _open_locked()
    if not vault.exists(args.name):
        raise CliError(f"No such secret: '{args.name}'")
    if not args.force:
        raise CliError(
            "reveal exposes a plaintext secret. Re-run with --force if you really "
            "mean to. (Agents should never need this - use `run` instead.)"
        )
    # reveal NEVER uses a session or the env password: printing plaintext always
    # requires the master password itself, so an agent cannot trigger it.
    _unlock_with_password_only(vault, args.password_stdin)
    sys.stderr.write(f"WARNING: printing plaintext for '{args.name}'.\n")
    print(vault.reveal(args.name))
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from . import gui

    return gui.main()


def cmd_serve(args: argparse.Namespace) -> int:
    from .broker import hardening, server as broker

    # systemd LoadCredential support: read the master password from the credential
    # directory so the service can unlock unattended without it being in argv/env.
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir and not os.environ.get(config.ENV_PASSWORD):
        cred_file = os.path.join(cred_dir, "password")
        if os.path.exists(cred_file):
            with open(cred_file, encoding="utf-8") as handle:
                os.environ[config.ENV_PASSWORD] = handle.read().rstrip("\n")

    vault = _open_unlocked()
    if args.user:
        hardening.drop_privileges(args.user)  # no-op unless started as root
    hardening.harden_process()                # best-effort: dumpable off, mlock, no core
    warning = hardening.ptrace_scope_warning()
    if warning:
        print(warning, file=sys.stderr)

    audit_path = str(config.vault_home() / "audit.log")
    allowed = {int(u) for u in args.allow_uid} if args.allow_uid else None
    allowed_sids = set(args.allow_sid) if args.allow_sid else None
    served = broker.Broker(vault, audit_path=audit_path,
                           allowed_uids=allowed, allowed_sids=allowed_sids)
    if args.pg_listen:
        from .broker import pgproxy

        if not (args.pg_secret and args.pg_backend and args.pg_user):
            raise CliError("--pg-listen requires --pg-secret, --pg-backend, and --pg-user")
        lhost, lport = _split_hostport(args.pg_listen, 6432)
        bhost, bport = _split_hostport(args.pg_backend, 5432)
        connector = pgproxy.PgConnector(vault, args.pg_secret, bhost, bport,
                                        args.pg_user, args.pg_db, audit=served.audit)
        return connector.serve(lhost, lport)
    if args.pipe:
        try:
            return served.serve_pipe(args.pipe)
        except (VaultError, RuntimeError) as exc:
            raise CliError(str(exc)) from exc
    if args.unix:
        try:
            return served.serve_unix(args.unix)
        except VaultError as exc:
            raise CliError(str(exc)) from exc
    if allowed is not None:
        print("warning: --allow-uid only applies to --unix sockets; ignoring for TCP.",
              file=sys.stderr)
    return served.serve(host=args.bind, port=args.port)


def cmd_proxy(args: argparse.Namespace) -> int:
    import base64

    from .broker import winpipe

    payload = {"secret": args.secret, "path": args.path, "method": args.method,
               "headers": {}, "body_b64": None}
    try:
        resp = winpipe.request(args.pipe, payload)
    except Exception as exc:
        raise CliError(f"could not reach the broker pipe '{args.pipe}': {exc}") from exc
    sys.stdout.buffer.write(base64.b64decode(resp.get("body_b64", "")))
    status = resp.get("status", 0)
    return 0 if 200 <= status < 300 else 1


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blindvault",
        description="A secrets vault your AI agents can use but never read.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="create a new vault and set the master password")
    p_init.add_argument("--force", action="store_true", help="reset an existing vault")
    p_init.set_defaults(func=cmd_init)

    p_set = sub.add_parser("set", help="store a secret value")
    p_set.add_argument("name")
    p_set.add_argument("--desc", help="human-readable note shown by `ls`")
    p_set.add_argument("--stdin", action="store_true", help="read the value from stdin")
    p_set.set_defaults(func=cmd_set)

    p_import = sub.add_parser("import", help="import secrets from a .env file")
    p_import.add_argument("path", nargs="?", default=".env", help="path to the .env file")
    p_import.add_argument("--overwrite", action="store_true",
                          help="replace secrets that already exist")
    p_import.set_defaults(func=cmd_import)

    p_gen = sub.add_parser("gen", help="generate a random secret nobody sees")
    p_gen.add_argument("name")
    p_gen.add_argument("--length", type=int, default=32)
    p_gen.add_argument("--desc")
    p_gen.set_defaults(func=cmd_gen)

    p_ls = sub.add_parser("ls", help="list secret names (never values)")
    p_ls.add_argument("-l", "--long", action="store_true", help="show origin + update times")
    p_ls.set_defaults(func=cmd_ls)

    p_rm = sub.add_parser("rm", help="delete a secret")
    p_rm.add_argument("name")
    p_rm.set_defaults(func=cmd_rm)

    p_run = sub.add_parser(
        "run", help="run a program, injecting secrets and scrubbing them from output"
    )
    p_run.add_argument("-e", "--env", action="append", metavar="VAR=NAME",
                       help="set environment variable VAR to the value of secret NAME")
    p_run.set_defaults(func=cmd_run, command=[])

    p_unlock = sub.add_parser("unlock", help="start a time-limited unlock session")
    p_unlock.add_argument("--ttl", type=int, default=session.DEFAULT_TTL_MINUTES,
                          metavar="MINUTES", help="how long the session stays unlocked")
    p_unlock.set_defaults(func=cmd_unlock)

    p_lock = sub.add_parser("lock", help="end the unlock session")
    p_lock.set_defaults(func=cmd_lock)

    p_migrate = sub.add_parser("migrate", help="upgrade an older (v1) vault to master-password format")
    p_migrate.set_defaults(func=cmd_migrate)

    p_passwd = sub.add_parser("passwd", help="change the master password")
    p_passwd.add_argument("--rekey", action="store_true",
                          help="also rotate the data key (re-encrypt every secret)")
    p_passwd.set_defaults(func=cmd_passwd)

    p_policy = sub.add_parser(
        "policy", help="view or set a secret's usage policy (allowed commands/hosts)"
    )
    p_policy.add_argument("name")
    p_policy.add_argument("--allow-command", action="append", metavar="CMD",
                          help="restrict the secret to this program (repeatable)")
    p_policy.add_argument("--allow-host", action="append", metavar="HOST",
                          help="restrict the secret to this destination host (repeatable)")
    p_policy.add_argument("--clear", action="store_true", help="remove all restrictions")
    p_policy.add_argument("--password-stdin", action="store_true",
                          help="read the master password from stdin")
    p_policy.set_defaults(func=cmd_policy)

    p_reveal = sub.add_parser("reveal", help="[escape hatch] print a plaintext value")
    p_reveal.add_argument("name")
    p_reveal.add_argument("--force", action="store_true")
    p_reveal.add_argument("--password-stdin", action="store_true",
                          help="read the master password from stdin instead of prompting")
    p_reveal.set_defaults(func=cmd_reveal)

    p_gui = sub.add_parser("gui", help="launch the desktop app for humans")
    p_gui.set_defaults(func=cmd_gui)

    p_serve = sub.add_parser(
        "serve", help="run the credential-injecting proxy so agents use secrets without seeing them"
    )
    p_serve.add_argument("--port", type=int, default=8771, help="TCP port (Phase 1)")
    p_serve.add_argument("--bind", default="127.0.0.1", help="TCP bind address (keep it loopback)")
    p_serve.add_argument("--unix", metavar="PATH",
                         help="serve over a Unix socket with UID peer-auth (Phase 2, Linux/macOS)")
    p_serve.add_argument("--allow-uid", action="append", metavar="UID",
                         help="UID permitted to connect to the --unix socket (repeatable)")
    p_serve.add_argument("--pipe", metavar="NAME",
                         help="serve over a Windows named pipe with SID peer-auth (Phase 2, Windows)")
    p_serve.add_argument("--allow-sid", action="append", metavar="SID",
                         help="SID permitted to connect to the --pipe (repeatable)")
    p_serve.add_argument("--user", metavar="NAME",
                         help="drop to this OS user if started as root")
    # PostgreSQL credential-injecting connector
    p_serve.add_argument("--pg-listen", metavar="HOST:PORT",
                         help="run a PostgreSQL connector on this address (e.g. 127.0.0.1:6432)")
    p_serve.add_argument("--pg-secret", metavar="NAME", help="vault secret holding the DB password")
    p_serve.add_argument("--pg-backend", metavar="HOST:PORT", help="real PostgreSQL backend address")
    p_serve.add_argument("--pg-user", metavar="USER", help="database user to authenticate as")
    p_serve.add_argument("--pg-db", metavar="DBNAME", help="default database (else from the client)")
    p_serve.set_defaults(func=cmd_serve)

    p_proxy = sub.add_parser("proxy", help="make a request through the broker's Windows pipe")
    p_proxy.add_argument("method", help="HTTP method, e.g. GET or POST")
    p_proxy.add_argument("secret", help="the secret name to use")
    p_proxy.add_argument("path", nargs="?", default="", help="upstream path, e.g. v1/charges")
    p_proxy.add_argument("--pipe", default=r"\\.\pipe\BlindVault", help="broker pipe name")
    p_proxy.set_defaults(func=cmd_proxy)

    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    # Split off the program to run: everything after the first standalone `--`.
    command_after: list[str] | None = None
    if "--" in raw:
        idx = raw.index("--")
        command_after = raw[idx + 1 :]
        raw = raw[:idx]

    parser = build_parser()
    args = parser.parse_args(raw)
    if args.cmd == "run":
        args.command = command_after or []

    try:
        return args.func(args)
    except (CliError, VaultError) as exc:
        print(f"blindvault: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
