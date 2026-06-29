#!/usr/bin/env bash
# Set up the BlindVault resolver as a dedicated OS user on Linux.
# Run as root:  sudo bash deploy/setup-linux.sh <AGENT_UNIX_USER>
#
# Creates the 'blindvault' service user and 'blindvault-clients' group, locks down
# the vault directory, and installs the systemd unit. See docs/DEPLOY-linux.md.
set -euo pipefail

AGENT_USER="${1:-}"
if [[ -z "$AGENT_USER" ]]; then
  echo "usage: sudo bash deploy/setup-linux.sh <AGENT_UNIX_USER>" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

# 1) Dedicated, no-login service user + a group the agent joins to reach the socket.
getent group blindvault-clients >/dev/null || groupadd --system blindvault-clients
id -u blindvault >/dev/null 2>&1 || \
  useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/blindvault \
          --create-home --user-group blindvault
usermod -aG blindvault-clients "$AGENT_USER"

# 2) Lock down the vault directory to the service user only.
install -d -o blindvault -g blindvault -m 0700 /var/lib/blindvault
echo "Vault home: /var/lib/blindvault  (set BLINDVAULT_HOME=/var/lib/blindvault when running bv as blindvault)"

# 3) Config dir for the env file and the encrypted password credential.
install -d -o root -g root -m 0750 /etc/blindvault
AGENT_UID="$(id -u "$AGENT_USER")"
printf 'BLINDVAULT_ALLOW=--allow-uid %s\n' "$AGENT_UID" > /etc/blindvault/blindvault.env
chmod 0640 /etc/blindvault/blindvault.env

# 4) Install the unit.
install -m 0644 "$(dirname "$0")/systemd/blindvault.service" /etc/systemd/system/blindvault.service
systemctl daemon-reload

cat <<EOF

Done. Remaining manual steps (see docs/DEPLOY-linux.md):
  1. Create the vault as the service user:
       sudo -u blindvault env BLINDVAULT_HOME=/var/lib/blindvault blindvault init
       sudo -u blindvault env BLINDVAULT_HOME=/var/lib/blindvault blindvault set MY_KEY
       sudo -u blindvault env BLINDVAULT_HOME=/var/lib/blindvault blindvault policy MY_KEY --allow-host api.example.com
  2. Store the master password as an encrypted systemd credential:
       printf '%s' 'your-master-password' > /tmp/pw && \
         systemd-creds encrypt /tmp/pw /etc/blindvault/password.cred && shred -u /tmp/pw
  3. Harden ptrace and start:
       sysctl -w kernel.yama.ptrace_scope=1   # make it persistent in /etc/sysctl.d
       systemctl enable --now blindvault
  4. The agent (user '$AGENT_USER') reaches it at:
       curl --unix-socket /run/blindvault/proxy.sock http://localhost/MY_KEY/<path>
EOF
