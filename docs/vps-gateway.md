# Running the gateway on a VPS (Cloudflare Tunnel, no Tailscale)

This guide moves the ContextBridge gateway onto a small Linux VPS, so the gateway no longer depends on a machine in your home. Every other computer, including the one that used to host the gateway, becomes an agent that dials out to it.

```
 ChatGPT / Claude ──HTTPS──▶ Cloudflare ──tunnel──▶ VPS 127.0.0.1:8793  remote listener (OAuth)
 agents (any network) ─WSS─▶ Cloudflare ──tunnel──▶ VPS 127.0.0.1:8792  agent listener
                                                    VPS 127.0.0.1:8791  local listener (static token)
```

- **No inbound ports** except SSH. `cloudflared` connects out to Cloudflare, and every ContextBridge listener stays on loopback.
- **No Tailscale.** The agent listener is on loopback, which means `agents.admission: device-key`: agents are admitted by their enrolled Ed25519 device key alone, new devices still need a one-time pairing code, and repeated failures from one client address are refused for a while.
- **No local device.** The gateway on the VPS has no `filesystem` section, so no tool can touch the VPS itself.

Examples below use `vps` as the server's hostname, `mcp.example.com` for the MCP endpoint, and `agents.example.com` for agents. Substitute your own.

**What Cloudflare can see:** Cloudflare terminates TLS for both hostnames, so it can read MCP and agent traffic, including commands and file contents. That is already true of the MCP endpoint. If you need agent traffic hidden from Cloudflare, keep the agent link on a private network instead (see [Remote devices](../README.md#remote-devices)).

## 1. Prepare the server

Start from Ubuntu 24.04 with key-only SSH, root login disabled, and `ufw` allowing only OpenSSH. Then, as root:

```sh
apt update && apt full-upgrade -y
apt install -y python3-venv git unattended-upgrades fail2ban
dpkg-reconfigure -plow unattended-upgrades
```

Create a dedicated account for the gateway, separate from your login and from any account an AI assistant uses:

```sh
adduser --system --group --home /opt/contextbridge contextbridge
```

## 2. Install ContextBridge

```sh
cd /opt/contextbridge
runuser -u contextbridge -- git clone https://github.com/Deep-Sixed/ContextBridge.git app
runuser -u contextbridge -- python3 -m venv venv
runuser -u contextbridge -- venv/bin/pip install ./app
install -d -o contextbridge -g contextbridge -m 700 state audit
install -d -o root -g contextbridge -m 750 config
```

To upgrade later: `runuser -u contextbridge -- git -C app pull`, then `runuser -u contextbridge -- venv/bin/pip install ./app`, then restart the service.

## 3. Configure the gateway

Create `/opt/contextbridge/config/computer.yaml` (owner root, group `contextbridge`, mode 640). Relative paths resolve against this file's folder.

```yaml
name: ContextBridge

serve:
  host: 127.0.0.1
  port: 8791
  audit_log: ../audit/computer.audit.jsonl

auth:
  scopes: [computer:read, computer:write, computer:execute, computer:process]

agents:
  enabled: true
  host: 127.0.0.1          # loopback: cloudflared publishes it; no TLS files or tailnet IDs needed
  port: 8792
  admission: device-key    # the loopback default, stated for clarity: agents from any network
  client_ip_header: CF-Connecting-IP   # count failed attempts per real client, not per tunnel
  public_url: wss://agents.example.com # what `pair` tells new devices
  max_failed_attempts: 10
  failure_window_seconds: 600
  registry: ../state/devices.json
  heartbeat_seconds: 15
  call_timeout_seconds: 660

remote:
  enabled: true
  host: 127.0.0.1
  port: 8793
  public_url: https://mcp.example.com
  state: ../state/oauth.json
  allow_scopes: [computer:read]   # widen deliberately
  allow_devices: ["*"]            # or list device names
  allowed_redirect_hosts: [claude.ai, claude.com, chatgpt.com]   # add 127.0.0.1 and "::1" for desktop MCP clients

# No filesystem/commands/processes sections: the VPS has no "local" device.
```

Do not set `agents.tls_cert`/`tls_key`: on loopback without them the listener speaks plain WebSocket to `cloudflared`, and Cloudflare provides the public TLS.

`client_ip_header` matters: every connection reaches the gateway from `cloudflared` on `127.0.0.1`, so without it the failed-attempt limit would treat all agents as one client, and one attacker could lock everyone out for the window. Cloudflare sets `CF-Connecting-IP` itself, and the header is trusted only because the listener is reachable from this host alone.

Create the static token for the local listener (only reachable from the VPS itself):

```sh
install -d -m 700 /etc/contextbridge
printf 'CONTEXTBRIDGE_COMPUTER_TOKEN=%s\n' "$(openssl rand -hex 32)" > /etc/contextbridge/gateway.env
chmod 600 /etc/contextbridge/gateway.env
```

Admin commands run as the gateway account. Add this to root's `~/.bashrc` so `cb-admin` exists in every root shell:

```sh
cb-admin() { (cd /opt/contextbridge && runuser -u contextbridge -- /opt/contextbridge/venv/bin/contextbridge-admin --config /opt/contextbridge/config/computer.yaml "$@"); }
```

The `cd` matters: at startup FastMCP looks for a `.env` file in the current directory, and the `contextbridge` account cannot look inside `/root`, so running from root's home fails with `PermissionError: '.env'`. The parentheses run it in a subshell, so your own shell stays where it was.

## 4. Run it as a service

Create `/etc/systemd/system/contextbridge-gateway.service`. This guide uses the name `contextbridge-gateway` throughout; if you name the unit differently, use your name in the `systemctl` and `journalctl` commands.

```ini
[Unit]
Description=ContextBridge gateway
After=network-online.target
Wants=network-online.target

[Service]
User=contextbridge
Group=contextbridge
EnvironmentFile=/etc/contextbridge/gateway.env
ExecStart=/opt/contextbridge/venv/bin/contextbridge-computer --config /opt/contextbridge/config/computer.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/opt/contextbridge/state /opt/contextbridge/audit

[Install]
WantedBy=multi-user.target
```

Do not start it yet if you are migrating an existing gateway (section 6); otherwise run `cb-admin owner-init` first, then:

```sh
systemctl daemon-reload
systemctl enable --now contextbridge-gateway
journalctl -u contextbridge-gateway -f
```

## 5. Publish it with Cloudflare Tunnel

1. In the Cloudflare dashboard, create a new tunnel for the VPS and install its connector there using the dashboard's Debian/Ubuntu instructions. Keep the tunnel token out of chats, logs, and git.
2. Add two **Published application** routes, each with a blank path:

   | Hostname | Service URL |
   |---|---|
   | `mcp.example.com` | `http://127.0.0.1:8793` |
   | `agents.example.com` | `http://127.0.0.1:8792` |

   A hostname can belong to only one tunnel. If `mcp.example.com` is still routed by an old gateway's tunnel, remove it there first (section 6 does this at cutover).
3. Check from any machine:
   - `curl -i https://mcp.example.com/mcp` returns **401** with a `WWW-Authenticate` header.
   - `curl -i https://mcp.example.com/.well-known/oauth-protected-resource/mcp` returns **200**, with `resource` set to `https://mcp.example.com/mcp`.

## 6. Migrate from an existing gateway

Copying the old gateway's state keeps every enrolled device (same `gateway_id`, so agents need no re-enrollment) and every ChatGPT/Claude approval (same `public_url`, so tokens stay valid).

1. **Stop the old gateway** and its tunnel route for `mcp.example.com`. Never run both gateways with the same state.
2. **Copy two files** from the old gateway's state folder: `devices.json` (the device registry) and `oauth.json` (owner passphrase hash, authenticator secret, client grants). Treat `oauth.json` like a password: copy it over SSH, and delete any intermediate copy afterwards. The old TLS certificate and key are not needed.
3. **Install them** on the VPS:

   ```sh
   install -o contextbridge -g contextbridge -m 600 devices.json oauth.json /opt/contextbridge/state/
   ```
4. **Copy settings** from the old config's `remote` section (`allow_scopes`, `allow_devices`, token lifetimes) into the new one. Keep `public_url` identical.
5. **Start the gateway** (section 4) and add the `mcp.example.com` route to the new tunnel (section 5).
6. **Repoint each agent.** In its agent config, set `gateway.url: wss://agents.example.com` and delete the `gateway.fingerprint` line (the agent then trusts the certificate Cloudflare presents through the system's CA store). Restart the agent. `cb-admin devices` and `list_devices` should show it online.
7. **Turn the old gateway machine into an agent.** Its files were the `local` device; on the VPS there is no `local`. Pair it as a normal device (`cb-admin pair <name>`), give it an agent config with the policy its old `filesystem`/`commands`/`processes` sections had, and enroll it. `pair` prints the `agents.public_url` address to use.
8. **Re-approve clients for the new device.** Existing grants name `local`, which no longer exists. Revoke and reconnect each client (`cb-admin oauth-clients`, `cb-admin oauth-revoke <id>`) and tick the new device on the consent page.

9. **Retire the old gateway** once the old machine works as an agent and has survived a reboot:
   - stop and disable its gateway service, and check with `ss -tlnp` that none of its old ports are still listening;
   - in Cloudflare, delete its old tunnel if no hostnames route to it any more, and uninstall `cloudflared` there;
   - clean up old copies of `oauth.json`, including any in backup archives. First confirm which copy is live: it is the one in the VPS's `state` folder, and `cb-admin oauth-clients` should list your clients from it. Keep at most one backup of that live file, mode 600, somewhere only you can read. Delete every other copy; each holds a passphrase hash and an authenticator secret.

**Starting fresh instead:** if the old gateway is unreachable, run `cb-admin owner-init` on the VPS, enroll each machine with `cb-admin pair` (set aside its old identity file first), and reconnect each client. The old `oauth.json` is then useless; delete it when you can.

**Rollback:** stop the VPS gateway, move the `mcp.example.com` route back to the old tunnel, restore the old agent configs (URL and fingerprint), and start the old gateway. Keep the old state folder untouched until the VPS has run cleanly for a while.

## 7. Adding a new machine later

```sh
cb-admin pair laptop --scopes computer:read     # prints a one-time code (default 15 minutes)
```

On the new machine, copy `configs/agent.yaml`, set `name: laptop`, `gateway.url: wss://agents.example.com`, no fingerprint, and its own policy, then run `contextbridge-agent enroll --config <file> --code <code>` and start the agent. The machine needs nothing but outbound HTTPS.

Existing ChatGPT and Claude approvals name their devices, so they can't see the new machine yet. Revoke and reconnect each client that should use it, ticking the new device on the consent page.

## 8. Upgrading

Upgrade the gateway first, then each agent, all to the same git revision.

1. **Gateway:** the upgrade steps in section 2, then `systemctl restart contextbridge-gateway`.
2. **Each agent, one at a time:** install the new revision into a new folder or virtual environment next to the old one, point the agent's service or scheduled task at it, and restart it. Keep the agent config and identity file where they are; no re-enrollment is needed.
3. **Check:** `list_devices` shows each agent online with the new `agent_version`, and a test command runs on it. Move on to the next agent only after that.
4. **Clean up:** after a few days without problems, delete the old installation folders.

New versions can add tools. Review the client's tool permissions after upgrading, and set any new write or delete tools to require approval.

## Checks

```sh
systemctl status contextbridge-gateway cloudflared --no-pager
cb-admin devices
cb-admin oauth-clients
ufw status        # only OpenSSH
ss -tlnp          # ContextBridge ports on 127.0.0.1 only
```
