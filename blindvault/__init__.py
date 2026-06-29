"""BlindVault — a secrets vault your AI agents can use but never read.

Agents work with *references* like ``{{secret:STRIPE_KEY}}``. They can list,
reason about, and place secrets where they are needed — but the plaintext value
is substituted by a trusted resolver only at the moment a child process runs,
and any value that comes back in the output is scrubbed before the agent sees it.
"""

__version__ = "0.9.0"
