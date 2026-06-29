# Deploying the BlindVault resolver on Windows (Phase 2)

This is the Windows counterpart to [DEPLOY-linux.md](DEPLOY-linux.md): run the
broker as a **dedicated Windows account** and let the agent reach it only over a
**named pipe** whose every connection is authenticated by the client's **token
SID** — never the (spoofable) PID.

Requires `pip install pywin32` (or `pip install "blindvault[windows]"`).

## What you get

- The broker runs as a dedicated account; the agent's (non-admin) user **cannot**
  `OpenProcess(PROCESS_VM_READ)` it — `ACCESS_DENIED` across users — so it cannot
  read the broker's memory, the data key, or the master password.
- The named pipe has a **protected DACL**: no `Everyone` access; the agent's SID
  gets read + write-data only (**not** the right to create pipe instances), and
  `FILE_FLAG_FIRST_PIPE_INSTANCE` + `PIPE_REJECT_REMOTE_CLIENTS` block squatting and
  remote clients.
- Each request is authenticated via `ImpersonateNamedPipeClient` → token **SID**,
  checked against the `--allow-sid` allow-list.

> **Assumption:** the agent runs as a **non-admin** user without `SeDebugPrivilege`.
> A local admin can read any process's memory — no userland tool can stop that
> (that's why Windows itself uses VBS/Credential Guard). Stated plainly in the
> [threat model](DESIGN-resolver.md#12-residual-risks-stated-honestly).

## Set up the accounts and vault

```powershell
# 1) A dedicated, low-privilege service user for the broker, and a separate
#    non-admin user for the agent (create per your environment / AD).
net user blindvault-svc <StrongPassword> /add
# (remove it from 'Users'-only as appropriate; do NOT add to Administrators)

# 2) Put the vault under the service account and lock it down:
$home = "C:\ProgramData\BlindVault"
New-Item -ItemType Directory -Force $home | Out-Null
icacls $home /inheritancelevel:r /grant "blindvault-svc:(OI)(CI)(F)"
#   (no Users/Everyone entries — only blindvault-svc can read the vault)

# 3) Create the vault AS the service account (set BLINDVAULT_HOME to $home):
#    run a shell as blindvault-svc, then:
#      $env:BLINDVAULT_HOME="C:\ProgramData\BlindVault"
#      blindvault init
#      blindvault set STRIPE_KEY
#      blindvault policy STRIPE_KEY --allow-host api.stripe.com
```

## Run the broker

Find the **agent's SID** and start the broker as the service account:

```powershell
# the agent's SID (run as the agent user, or look it up):
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value   # e.g. S-1-5-21-...-1001

# as blindvault-svc (BLINDVAULT_HOME set, vault unlocked via prompt or a credential):
blindvault serve --pipe \\.\pipe\BlindVault --allow-sid S-1-5-21-...-1001
```

Run it unattended as a **service** with `sc.exe` (or NSSM), running as
`blindvault-svc`, and supply the master password via `BLINDVAULT_PASSWORD` from a
protected source (e.g. a service-only environment) — never world-readable. A
signed service installer is a planned follow-up.

## Using it from the agent

The agent (the `--allow-sid` user) never holds the secret:

```powershell
blindvault proxy GET STRIPE_KEY v1/charges
#  -> broker injects "Authorization: Bearer <real key>" and forwards ONLY to
#     api.stripe.com (the host comes from the secret's policy, not the request)
```

`bv proxy METHOD SECRET PATH [--pipe NAME]` is a thin client to the pipe; the
broker performs the call and returns the (scrubbed) response. Any program that can
open the named pipe and speak the 4-byte-length-prefixed JSON protocol works too.

## Verify the boundary

```powershell
# As the agent user you must NOT be able to read the vault:
Get-Content C:\ProgramData\BlindVault\vault.json     # -> Access denied
# ...nor read the broker's memory (no SeDebugPrivilege, different account).
```
