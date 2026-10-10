"""Remote devices: agents that dial out to the gateway over authenticated WebSocket/TLS.

* :mod:`.registry` — devices, one-time enrollment codes, revocation (gateway state)
* :mod:`.hub`      — the gateway's agent listener and request routing
* :mod:`.agent`    — the agent that runs on each machine under its own local policy
* :mod:`.admin`    — gateway-side CLI: TLS setup, pairing, listing, revocation
"""
