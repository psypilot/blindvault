# BlindVault Resolver — Design

> Status: **design + Phase 1 + Phase 2 (Linux) implemented.** This document is the
> security specification for BlindVault's "real boundary": a privilege-separated
> resolver that lets an AI agent **use** secrets it can never **read**, enforced by
> the operating system rather than by the agent's cooperation. Linux deployment:
> [DEPLOY-linux.md](DEPLOY-linux.md).
>
> It synthesizes four independent security research reviews (POSIX internals,
> Windows internals, the secretless-broker prior art, and protocol/threat
> modeling). Sources are listed at the end.

---

## 1. Goal and non-goals

**Goal.** An AI agent (running as a *less-trusted* OS user) can cause a secret to
be *used* — sent to an API, used to connect to a database — without the agent's
process ever holding the plaintext, the data key, or the master password. Usage
is constrained by per-secret policy at a boundary the agent cannot bypass.

**Non-goals / honest limits.**
- We do **not** try to let the agent run an *arbitrary, agent-authored* command
  with a secret injected and keep that secret hidden. That is **impossible in any
  language**: a program the agent controls (or whose output it reads) legitimately
  receives the value and can print it. We constrain the *operation*, not just the
  *process*.
- We do **not** defend against an agent that is **local admin / root / holds
  `SeDebugPrivilege`**. Such a principal can read any process's memory; the only
  defense is hardware/VBS isolation (Credential Guard, PPL) that a Python program
  cannot join. **The whole design assumes a non-admin agent account.**

## 2. The one principle that governs everything

> The OS can robustly enforce *"the agent cannot read the daemon's RAM, the data
> key, the master password, or the vault file."* It **cannot** enforce *"the agent
> cannot learn a secret it was handed."*

Therefore BlindVault must be a **broker that performs the secret-using operation
itself and returns only the result** — the `ssh-agent` / HSM / Windows Credential
Guard model ("delegation without disclosure"). The plaintext never crosses the
IPC boundary, in either direction, ever.

For **static bearer secrets** (API keys, tokens — BlindVault's main case) the
strongest realization of this is a **credential-injecting proxy**: the agent
sends a request carrying a *phantom token*; the broker splices in the real secret
on its side of the wire and forwards **only to allow-listed hosts**. Two
orthogonal guarantees meet at one OS-isolated chokepoint:

1. **Confidentiality** — the plaintext never enters the agent's process, so under
   prompt injection there is *nothing to exfiltrate*.
2. **Egress control** — default-deny host allow-list, so even a fully compromised
   agent can only reach approved destinations.

## 3. Trust model and boundaries

```
        OS user: "agent"  (untrusted)              │   OS user: "blindvault"  (trusted, separate)
 ┌────────────────────────────────────────────┐    │   ┌──────────────────────────────────────────────┐
 │  AI agent / its tools                        │    │   │  blindvault broker daemon                       │
 │   HTTPS_PROXY = 127.0.0.1:PORT  (or base URL)│    │   │   • encrypted static-secret store (vault.json) │
 │   API_KEY = <phantom-token>   (NOT the key)  │    │   │   • data key in mlock'd RAM (unlocked by human)│
 │                                              │    │   │   • policy engine (per-secret allow-host/cmd)  │
 │   curl https://api.stripe.com/... ───────────┼──loopback│   • credential injector (phantom → real)    │
 │     carries the phantom token only           │  socket  │   • egress chokepoint + audit log            │
 └────────────────────────────────────────────┘    │   └───────────────────┬───────────────────────────┘
   • cannot ptrace / ReadProcessMemory the broker   │     1. authenticate peer by UID (Linux/macOS) / SID (Windows)
   • cannot read vault.json (file ACL) or key (RAM) │     2. validate phantom token (constant-time)
   • cannot reach the network except via the proxy  │     3. host ∈ allow-list? else 403; deny metadata/private IPs
                                                     │     4. inject the REAL secret; open proper TLS upstream ─► api.stripe.com
```

The boundary is the **OS user account**. On Linux/macOS the agent's user cannot
`ptrace`/read `/proc/<pid>/mem` of a different user's process; on Windows
`OpenProcess(PROCESS_VM_READ)` against a different non-admin user's process is
`ACCESS_DENIED`. The vault file is owned/ACL'd to the broker user only; the data
key lives solely in the broker's locked RAM.

## 4. Operations the broker exposes

The agent never asks "give me secret X." It asks the broker to *do* something:

| Operation | What the broker does | Secret crosses to agent? |
|---|---|---|
| `proxy-request` *(primary)* | Makes the outbound HTTP(S) call itself, injecting the real credential, only to an allow-listed host; returns the scrubbed response. | **No** |
| `resolve-and-run` *(fallback)* | Spawns a **fixed, allow-listed** command (no shell) **as the broker/sandbox user**, injects the secret via env/fd (never argv), captures + scrubs output. | **No** (but see §8) |
| `list-names` / `get-policy` | Returns names + policy the caller is granted — never values. | No |
| `unlock` / `lock` | **Operator-only** (agent UID denied). Master password supplied out-of-band to the daemon's TTY; never over the socket. | No |

**Connectors (future):** for non-HTTP static secrets (Postgres, MySQL, SSH), a
CyberArk-Secretless-style protocol connector behind the same daemon: the agent
connects to a local socket, the broker completes the backend auth and streams
bytes — the password is never in the agent.

## 5. Phantom-token credential injection (the proxy)

1. At unlock, the broker mints a random, unguessable **phantom token** per secret
   (or per session) and gives it to the operator to place in the agent's env
   (e.g. `STRIPE_KEY=bv-phantom-…`). The agent treats it as the key.
2. The agent makes a normal request; the phantom token rides where the real key
   would (Authorization header / `X-Api-Key` / query param).
3. The broker **validates the phantom in constant time**, looks up the bound
   secret, checks the **target host against that secret's `allow_hosts` policy**,
   plus a hardcoded deny-list for cloud-metadata (`169.254.169.254`) and
   private/link-local ranges, with **resolve-once-then-validate** to defeat
   DNS-rebinding.
4. It substitutes the **real** secret, opens a correct TLS connection to the
   upstream, and returns the response with the secret value scrubbed.

Two wirings (we ship the first; the second is opt-in):
- **Reverse-proxy / phantom-token** *(preferred)* — agent points a base URL or
  `HTTPS_PROXY` at the broker; **no CA trust to weaken** because the broker
  originates the upstream TLS. (nono.sh model.)
- **MITM forward proxy** — most transparent for arbitrary HTTPS tools, but the
  agent must trust the broker's CA. Offer only where tool transparency demands it.
  (Infisical agent-vault model.)

## 6. IPC and peer authentication

**Transport.** Pathname `AF_UNIX SOCK_STREAM` on Linux/macOS (mode `0660`, owner
`blindvault`, group `blindvault-clients`; parent dir `0750`); a named pipe on
Windows. The loopback proxy port is bound to `127.0.0.1` only.

**Authenticate on the kernel-verified identity, captured at connect — never the
PID:**
- **Linux:** `getsockopt(SO_PEERCRED)` → `{pid, uid, gid}`; authorize on **uid**.
  (Optionally `SO_PEERPIDFD` on ≥6.5 if a process handle is ever needed.)
- **macOS/BSD:** `getpeereid()` (via `ctypes`) → effective uid/gid.
- **Windows:** the pipe **DACL** grants connect to only the agent SID (so any
  client *is* the agent by construction); optionally confirm via
  `ImpersonateNamedPipeClient` → `OpenThreadToken` → `GetTokenInformation(TokenUser)`
  → SID → `RevertToSelf` **immediately** (never touch the vault while impersonating).

**Why never PID:** PIDs are reused and spoofable — polkit's CVE-2019-6133 (non-atomic
`fork`) and Project Zero's named-pipe PID spoofs. Authorize on uid/SID.

## 7. Authorization — default-deny capabilities

Authorization is a deny-by-default table keyed on **(principal_uid/SID,
secret_id)**. Each grant is a **capability to *use***, not read:

```
grant { principal: uid=4007, secret: STRIPE_KEY,
        actions: [proxy-request], allowed_hosts: [api.stripe.com],
        inject: header "Authorization: Bearer {secret}",
        rate_limit: 60/min, not_after: 2026-12-31 }
```

Per request the broker: resolve capability for `(conn.uid, secret)` → check
`action ∈ allowed` → validate `target` **after canonicalization** → only then
dereference the plaintext internally, act, and return scrubbed output. Policy
lives entirely in the daemon; the client supplies inputs to validate, never
decisions to trust. This is what defeats the **confused-deputy** class.

## 8. Wire protocol

**Framing:** 4-byte big-endian length prefix + exactly one UTF-8 **JSON** object.
JSON is schema-validatable and has no parse-time code execution (never
`pickle`/`yaml.load`/`eval`). Reject `length > MAX_FRAME` before allocating;
reject trailing bytes, unknown/duplicate keys, wrong types. Every message:
`{"v":1,"id":"<uuid>","type":"…",…}`; responses echo `id`.

**Invariant:** IN = references + targets + non-secret payload; OUT = status +
**scrubbed, size-capped** output. **No plaintext crosses the boundary in either
direction.**

## 9. Daemon self-protection

- **Never SUID, never root at steady state.** Run as a dedicated stable user via
  systemd `User=` / launchd / a Windows service account — not via setuid dances.
  (SUID is the recurring escalation surface: PwnKit, Baron Samedit.)
- **Linux/macOS:** `prctl(PR_SET_DUMPABLE,0)` (blocks same-user `/proc/<pid>/mem`
  + ptrace), `PR_SET_NO_NEW_PRIVS`, `setrlimit(RLIMIT_CORE,0)`, `mlockall()`;
  require system `kernel.yama.ptrace_scope ≥ 1`. If ever started as root, drop
  privileges **setgroups → setgid → setuid** and *verify* root cannot be regained.
- **Windows:** virtual service account `NT SERVICE\BlindVault`;
  `sc sidtype BlindVault restricted` (write-restricted token); strip privileges —
  **must not hold `SeDebug`/`SeImpersonate`**; `icacls vault … /grant "NT SERVICE\BlindVault:(R)"`
  with inheritance removed and `Users`/`Everyone` removed.
- **Memory hygiene in CPython is best-effort:** hold the data key in a
  `bytearray`/`ctypes` buffer that is explicitly zeroized on lock/exit and
  `mlock`/`VirtualLock`'d; accept that immutable `str`/`bytes` and the GC leave
  residual copies (documented).

## 10. Child sandboxing (only if `resolve-and-run` is used)

The secret-bearing child must run under a user the **agent cannot inspect** —
the broker user or a dedicated `blindvault-run`, **never the agent's uid/SID** (or
the agent would `ptrace`/`ReadProcessMemory` it). Inject via **env or an inherited
fd, never argv** (`/proc/<pid>/cmdline` and `ps` are world-readable). Then:
- **Linux:** `ptrace_scope ≥ 1` + different uid → no `PTRACE_ATTACH`; child sets
  `PR_SET_DUMPABLE,0` + seccomp; wrap in **bubblewrap** (unprivileged userns) for
  a minimal fs/net.
- **Windows:** `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` + low/untrusted
  integrity + a **Job Object** (`KILL_ON_JOB_CLOSE`, limits) + ideally an
  **AppContainer** (zero capabilities).

Even then, restrict `resolve-and-run` to a **fixed, trusted set of binaries** — it
cannot stop an *agent-authored* program from disclosing the secret.

## 11. Audit log

Append-only, broker-owned, `0600`, one JSON object per line. **Every unlock, lock,
and secret use (allowed *and* blocked)** is logged with **references only** — never
the value, passphrase, or secret-bearing argv. Fields: `ts`, `seq`,
`event`, `principal_uid/sid`, `pid` (informational), `secret_name`, `action`,
`target`, `decision`, `reason`, `result`, `bytes_out`, `truncated`, `duration_ms`.
Support **canary credentials** so any leak surfaces on first use.

## 12. Residual risks (stated honestly)

- **Confused deputy is contained, not eliminated.** The agent can still *use* what
  it is allowed to (and could exfiltrate *data* through an allowed host). Mitigate
  with tight per-secret host/path/method scoping, rate limits, and human-approval
  tiers for consequential actions — never claim it's gone.
- **`resolve-and-run` cannot hide a secret from an agent-authored binary** — keep it
  to a trusted command set, or prefer the proxy.
- **Local admin / `SeDebugPrivilege` / root agent** breaks everything (out of scope).
- **CPython memory hygiene** leaves residual plaintext copies (best-effort zeroing).
- **TLS-MITM mode** weakens the agent's CA trust — prefer the phantom-token proxy.

## 13. Invariants the implementation must never violate

1. No plaintext secret crosses the IPC boundary, either direction, ever.
2. Identity = the connection's kernel-verified UID/SID, captured at connect — never PID.
3. Default deny; a secret is unusable without an explicit `(uid, secret, action, target)` grant.
4. Policy is enforced in the daemon; client input is references/targets, validated server-side.
5. Constraints checked **after canonicalization**; no shell; no cross-host redirect following.
6. The secret-bearing child (if any) runs under a user the agent cannot `ptrace`/`ReadProcessMemory`.
7. KDF/unlock runs only at unlock; the data key is cached in locked RAM, never derived per request.
8. All returned output is size-capped and scrubbed of the secret value.
9. One JSON object per length-prefixed, size-capped, strictly-validated frame; no `pickle`/`eval`/shell.
10. Every unlock and secret use is audit-logged, references only.
11. The socket/pipe ACL restricts connection to the agent uid/SID only.
12. Keys are zeroized on lock, idle timeout, and daemon exit.

## 14. Phased implementation plan

- **Phase 1 — broker + phantom-token proxy (shipping now).** `bv serve` runs the
  broker (unlocked vault in RAM) and a loopback **credential-injecting reverse
  proxy** that enforces each secret's `allow_hosts`, injects the real value, and
  scrubs responses. Runs **same-user first** to prove the architecture — already a
  real security win (key off-disk in RAM, plaintext never in the agent for network
  calls, egress chokepoint, audit log). Fully cross-platform, pure-Python.
- **Phase 2 — OS-user separation.** ✅ **Shipped for Linux and Windows.**
  *Linux:* a Unix-socket transport with `SO_PEERCRED` UID peer-auth + a UID
  allow-list, process self-protection (`PR_SET_DUMPABLE=0`, `mlockall`, no core,
  ptrace-scope check), root→user privilege-drop, a systemd unit + `setup-linux.sh`,
  systemd-credential unlock — [DEPLOY-linux.md](DEPLOY-linux.md). *Windows:* a
  named-pipe transport with a protected DACL (no `Everyone`; agent SID gets
  read+write-data, not create-instance; `FIRST_PIPE_INSTANCE` +
  `REJECT_REMOTE_CLIENTS`) and per-connection **token-SID** auth via
  `ImpersonateNamedPipeClient`, plus a `bv proxy` client —
  [DEPLOY-windows.md](DEPLOY-windows.md). Remaining: macOS (`getpeereid` + launchd).
  This is what turns Phase 1 from "process boundary" into "OS boundary."
- **Phase 3 — `resolve-and-run` + sandboxed children**, and protocol connectors for
  DB/SSH (Secretless style).
- **Phase 4 — packaging**: signed installers that create the service user and set
  permissions; `ptrace_scope`/privilege checks at startup that refuse to run
  unsafely.

Each phase is independently shippable and testable; we do not claim the OS-level
guarantee until Phase 2's user separation and peer auth are in place and audited.

## 15. Sources

POSIX/IPC: `SO_PEERCRED`/`getpeereid` (man7 unix(7), Apple getpeereid(3)),
`SO_PEERPIDFD` (kernel ≥6.5), YAMA ptrace_scope, `prctl(PR_SET_DUMPABLE)`, systemd
socket activation + hardening, bubblewrap/seccomp; prior art ssh-agent, gpg-agent
(`T1211`), polkit **CVE-2019-6133**, PwnKit **CVE-2021-4034**, Baron Samedit.
Windows: MS "Named Pipe Security and Access Rights", "Process Security and Access
Rights", `ImpersonateNamedPipeClient`, Credential Guard/LSAIso, LSA Protection/PPL,
service SID types, `icacls`, AppContainer/Job Objects; Project Zero "Spoofing Named
Pipe Client PID", Tyranid "Named Pipe Secure Prefixes", the Potato family,
**CVE-2019-19470**. Broker prior art: CyberArk **Secretless Broker**, HashiCorp
**Vault Agent**, AWS IMDS/`credential_process`, ssh-agent, **Infisical agent-vault**,
nono.sh **phantom-token** proxy, **SANS** "AI agent as confused deputy / credential
broker". Protocol: length-prefix framing, confused-deputy (AWS IAM), strict-JSON /
no-pickle.
