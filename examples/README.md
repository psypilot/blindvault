# Examples

Hands-on walkthroughs for using BlindVault day to day. They assume you've installed
it (`pip install git+https://github.com/psypilot/blindvault.git`, which gives you the
`bv` command — or run `python -m blindvault`).

## 1. Set up a vault and a secret

```bash
bv init                                   # choose a master password (once)
echo "sk_live_xxx" | bv set STRIPE_KEY --stdin --desc "prod payments"
bv policy STRIPE_KEY --allow-host api.stripe.com   # this key may ONLY go to Stripe
bv ls                                     # names only — never values
```

Have a `.env` already? Import it in one step (see [`sample.env`](sample.env)):

```bash
bv import examples/sample.env
```

## 2. Let an AI agent use a secret (without ever seeing it)

Drop [`AGENTS.md`](../AGENTS.md) into your project, then the agent does:

```bash
bv ls                                     # discovers STRIPE_KEY exists
bv run -- curl -H "Authorization: Bearer {{secret:STRIPE_KEY}}" https://api.stripe.com/v1/charges
# value injected at runtime; if it echoes back it's [redacted:STRIPE_KEY]
```

## 3. The airtight way — the resolver proxy

The agent never holds the secret at all; the broker injects it on its side:

```bash
bv unlock                                 # you enter the password once
bv serve                                  # local credential-injecting proxy
# the agent only ever talks to the proxy:
curl http://127.0.0.1:8771/STRIPE_KEY/v1/charges
```

For the OS-enforced boundary (broker as a separate OS user), see
[`../docs/DEPLOY-linux.md`](../docs/DEPLOY-linux.md) and
[`../docs/DEPLOY-windows.md`](../docs/DEPLOY-windows.md).

## 4. PostgreSQL with no password in the app

```bash
bv set PGPASS --stdin            # the real DB password
bv policy PGPASS --allow-host db.internal
bv unlock
bv serve --pg-listen 127.0.0.1:6432 --pg-secret PGPASS \
         --pg-backend db.internal:5432 --pg-user blindvault

# your app / psql connects passwordless; the broker authenticates for it:
psql "host=127.0.0.1 port=6432 user=blindvault dbname=blindvault"
```
