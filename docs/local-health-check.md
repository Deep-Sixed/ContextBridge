# Local health check (Friday and Thanatos)

The daily cloud review reads GitHub only: PRs, CI on GitHub's runners, and test results already written down. It cannot see whether the gateway and agent are running, which revision is installed, or whether recovery works today. This checklist covers that part. Run it on the machines themselves.

**When to run it:** weekly, after deploying a new revision, after a reboot, and before and after merging the security PRs (#27, #29, #33).

## 1. Automated checks

Both scripts are read-only by default. They print `PASS`, `WARN`, `FAIL`, `SKIP` or `INFO` lines, write a Markdown report to `audit/healthcheck/` (git-ignored), and exit `1` if anything failed. They never print tokens or file contents.

**Friday (gateway, Linux):**

```sh
scripts/healthcheck/check-gateway.sh --fetch --drill
```

**Thanatos (agent, Windows PowerShell):**

```powershell
.\scripts\healthcheck\check-agent.ps1 -Fetch
```

`--drill` runs `contextbridge-failover` (read-only probes on every device) and needs `CONTEXTBRIDGE_COMPUTER_TOKEN` in the shell. `--hours N` / `-Hours N` changes the audit window from 24 hours.

| Area | Friday (`check-gateway.sh`) | Thanatos (`check-agent.ps1`) |
|---|---|---|
| Deployed revision | HEAD compared with `origin/main`; uncommitted changes; installed package version | Same |
| Service running | One gateway process; no stray local agents or leftover test processes | Scheduled task state, last result, logon type (S4U or sign-in); exactly one agent process |
| Listeners and exposure | 8791 (and 8793 if enabled) on loopback; agent listener on its tailnet IP; no 8790–8794 on `0.0.0.0`; Tailscale Funnel off | Gateway reachable over TCP; firewall profiles on; no inbound allow rule for Python |
| Enrollment | `contextbridge-admin devices` (active and pending); `tailnet_node_ids` pinned | Identity file present; gateway fingerprint is not the placeholder |
| Connection history | `device_connected`, `disconnected`, `heartbeat_lost`, `auth_failed`, `duplicate_refused`, `tailnet_admission_denied`; each device's last connect and agent version | `gateway_connected`, `disconnected`, `unreachable`, `result_undelivered`; restarts since boot |
| Reboot recovery | n/a | Seconds from boot to first `gateway_connected` (WARN over 180 s) |
| Duplicate launches | `device_duplicate_refused` count | Instance-lock refusals in `audit\agent.log`; Task Scheduler start, skip and failure counts |
| Tailscale | Backend running; Thanatos peer online | Backend running; unattended mode (`ForceDaemon`) on |
| Known open issues | `git` in the allowlist (#29); filesystem token missing from `ALWAYS_STRIPPED_ENV` (#33); remote endpoint and `allow_devices: "*"` | `git` or a shell in the agent allowlist (#29) |

The known-issue lines should turn `PASS` once the matching PR is merged and deployed. If one stays `WARN` after that, the host is running an older revision or an old config.

## 2. Recovery tests (disruptive, opt-in)

Run these in a maintenance window, one at a time, and keep both reports.

**a. Agent crash recovery (Thanatos).** Kills the agent and times the scheduled task's relaunch and the new gateway connection. Expect a relaunch within about 60 s (the task repeats every minute).

```powershell
.\scripts\healthcheck\check-agent.ps1 -RecoveryTest
```

Then, on Friday, confirm the device serves calls again:

```sh
contextbridge-failover --config configs/computer.yaml --device thanatos
```

**b. Gateway restart recovery (Friday).** Restarts the gateway with your own command, waits for every agent to log `device_connected`, then runs the drill.

```sh
scripts/healthcheck/check-gateway.sh --recovery-test 'systemctl --user restart contextbridge-computer'
```

Use whatever command actually manages your gateway. The script only runs it; it does not guess.

**c. Reboot recovery (Thanatos), manual.**
1. Reboot. Don't sign in unless the task uses `-AtLogOn`.
2. Wait 2 minutes, then from Friday run `contextbridge-failover --config configs/computer.yaml --device thanatos`. This is the post-reboot MCP read that was never recorded.
3. Sign in and run `check-agent.ps1`. Record the "boot to gateway_connected" seconds and the duplicate-launch lines.

**d. Half-open takeover (Friday ↔ Thanatos), manual.** Never yet validated live.
1. With Thanatos connected, cut its network without closing the socket. For example, block outbound traffic to the gateway IP and port in Windows Firewall, or pause the VM.
2. Within 45 s (3 missed heartbeats), Friday's audit log should show `device_heartbeat_lost`.
3. Remove the block. The agent should reconnect and the gateway should log `device_connected`. If the old socket was still registered, it should be replaced (`device_disconnected` with reason `replaced`), not refused.
4. Run the failover drill for `thanatos`. Match the `request_id` of one call in both audit logs.

## 3. Recording results

Attach the two Markdown reports (and the `-drill.txt` file) to the PR or issue that the test validates, or commit a summary under `docs/`. The daily cloud review can only count a host test that was written down somewhere it can read.
