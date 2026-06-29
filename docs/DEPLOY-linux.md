# Deploying the BlindVault resolver on Linux (Phase 2)

This turns the Phase 1 proxy (a *process* boundary) into an **OS-enforced**
boundary: the broker runs as a dedicated user the agent cannot inspect, and it
authenticates every connection by the caller's **UID**.

## What you get

- The broker runs as user **`blindvault`**, which owns the vault and holds the data
  key in RAM. The agent's user has **no read access** to either.
- The agent reaches the broker only over a **Unix-domain socket**, and the broker
  checks the connecting process's **UID** (`SO_PEERCRED`) against an allow-list —
  never the PID (PIDs are spoofable/reused).
- Process hardening: `PR_SET_DUMPABLE=0`, `mlockall`, no core dumps, plus the
  systemd sandbox (`ProtectSystem`, `MemoryDenyWriteExecute`, syscall filter, …).

## Why this is the real boundary

On Linux one user cannot `ptrace`/read `/proc/<pid>/mem` of a **different** user's
process (with `kernel.yama.ptrace_scope ≥ 1`). So once the broker runs as
`blindvault` and the agent runs as its own non-root user, the agent **cannot** read
the broker's memory, the data key, or the master password — the kernel forbids it.
This holds only if the agent is **not root and lacks `CAP_SYS_PTRACE`**.

## One-time setup

```bash
sudo bash deploy/setup-linux.sh <AGENT_UNIX_USER>
```

That script creates the `blindvault` user and `blindvault-clients` group, locks
`/var/lib/blindvault` to `0700 blindvault`, writes
`/etc/blindvault/blindvault.env` with `--allow-uid <agent uid>`, and installs the
systemd unit. Then finish the manual steps it prints:

1. **Create the vault** as the service user:
   ```bash
   sudo -u blindvault env BLINDVAULT_HOME=/var/lib/blindvault blindvault init
   sudo -u blindvault env BLINDVAULT_HOME=/var/lib/blindvault blindvault set STRIPE_KEY
   sudo -u blindvault env BLINDVAULT_HOME=/var/lib/blindvault \
     blindvault policy STRIPE_KEY --allow-host api.stripe.com
   ```
2. **Provide the master password** as an encrypted systemd credential (so it is
   never in argv/env or a world-readable file):
   ```bash
   printf '%s' 'your-master-password' > /tmp/pw
   systemd-creds encrypt /tmp/pw /etc/blindvault/password.cred
   shred -u /tmp/pw
   ```
   The unit's `LoadCredentialEncrypted=` makes it available as
   `$CREDENTIALS_DIRECTORY/password`, which `bv serve` reads at startup.
3. **Harden ptrace and start:**
   ```bash
   sudo sysctl -w kernel.yama.ptrace_scope=1   # persist via /etc/sysctl.d/
   sudo systemctl enable --now blindvault
   ```

## Using it from the agent

The agent (running as `<AGENT_UNIX_USER>`) never holds the secret:

```bash
curl --unix-socket /run/blindvault/proxy.sock \
  http://localhost/STRIPE_KEY/v1/charges
# broker injects Authorization: Bearer <real key> and forwards ONLY to api.stripe.com
```

Most HTTP clients/SDKs can target a Unix socket (curl `--unix-socket`, many
languages via a custom transport). A loopback-TCP mode (`bv serve --port`) also
exists for clients that cannot, but it lacks UID peer-auth — prefer the socket.

## Manual (non-systemd) start

```bash
sudo -u blindvault env BLINDVAULT_HOME=/var/lib/blindvault \
  blindvault serve --unix /run/blindvault/proxy.sock --allow-uid <AGENT_UID>
# prompts for the master password once, then serves in the foreground
```

## Verifying the boundary

```bash
# As the agent user, you must NOT be able to read the vault or the broker memory:
sudo -u <AGENT_USER> cat /var/lib/blindvault/vault.json     # -> Permission denied
sudo -u <AGENT_USER> gdb -p "$(pgrep -u blindvault -f 'blindvault serve')"  # -> ptrace denied
```

## Limits (read the threat model)

- The agent can still **use** the secret within its policy (confused-deputy);
  contain with tight host scoping, rate limits, and approval tiers — see
  [DESIGN-resolver.md](DESIGN-resolver.md).
- A **root / `CAP_SYS_PTRACE`** agent defeats the memory boundary — out of scope.
- CPython cannot perfectly zero secret memory; `mlock` keeps the key out of swap,
  best-effort.
