#!/usr/bin/env python3
"""Summarize a ContextBridge config and audit log for the local health check.

Read-only. Prints one JSON object that the gateway and agent check scripts turn into
PASS / WARN / FAIL lines. Never prints tokens, keys, or file contents beyond event names.

    python scripts/healthcheck/audit_summary.py --kind gateway --config configs/computer.yaml --hours 24
    python scripts/healthcheck/audit_summary.py --kind agent   --config configs/agent.yaml    --hours 24
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

GATEWAY_EVENTS = (
    "service_started",
    "device_enrolled",
    "device_enroll_rejected",
    "device_connected",
    "device_disconnected",
    "device_auth_failed",
    "device_duplicate_refused",
    "device_revoked",
    "device_heartbeat_lost",
    "tailnet_admission_denied",
    "denied",
)
AGENT_EVENTS = (
    "agent_started",
    "gateway_connected",
    "gateway_disconnected",
    "gateway_unreachable",
    "result_undelivered",
    "denied",
)
SHELLS = {"bash", "sh", "zsh", "powershell", "pwsh", "cmd", "python", "python3", "py", "node"}


def parse_ts(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def iso(ts: float | None) -> str | None:
    return None if ts is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def resolve(config_path: Path, value: object) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_absolute() else (config_path.parent / path).resolve()


def boot_time() -> float | None:
    try:
        import psutil

        return float(psutil.boot_time())
    except Exception:  # psutil missing or unsupported
        return None


def read_events(path: Path, since: float, wanted: tuple[str, ...]) -> dict:
    counts: Counter[str] = Counter()
    last: dict[str, float] = {}
    per_device: dict[str, dict[str, object]] = {}
    timeline: list[tuple[float, str]] = []
    bad_lines = 0
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                bad_lines += 1
                continue
            event = entry.get("event")
            ts = parse_ts(entry.get("ts"))
            if event not in wanted or ts is None or ts < since:
                continue
            counts[event] += 1
            last[event] = ts
            timeline.append((ts, event))
            device = entry.get("device")
            if isinstance(device, str) and event.startswith("device_"):
                slot = per_device.setdefault(device, {})
                slot[event] = int(slot.get(event, 0)) + 1  # type: ignore[arg-type]
                slot[f"last_{event}"] = iso(ts)
                if event == "device_connected" and isinstance(entry.get("info"), dict):
                    info = entry["info"]
                    slot["agent_version"] = info.get("agent_version")
                    slot["reported_hostname"] = info.get("hostname")
    return {
        "counts": dict(counts),
        "last": {k: iso(v) for k, v in last.items()},
        "devices": per_device,
        "timeline": [(iso(ts), ev) for ts, ev in timeline[-40:]],
        "unparsable_lines": bad_lines,
        "_timeline_raw": timeline,
    }


def gateway_findings(cfg: dict) -> list[dict]:
    findings: list[dict] = []
    agents = cfg.get("agents") or {}
    if agents.get("enabled"):
        host = str(agents.get("host", ""))
        if host in {"0.0.0.0", "::", ""}:
            findings.append({"level": "FAIL", "check": "agents.host", "detail": f"binds {host!r}; use a tailnet IP"})
        loopback = host in {"127.0.0.1", "::1", "localhost"} or host.startswith("127.")
        admission = agents.get("admission") or ("device-key" if loopback else "tailnet")
        if admission == "device-key":
            findings.append({
                "level": "INFO" if loopback else "WARN",
                "check": "agents.admission",
                "detail": "device-key: agents from any network, protected by pairing codes and device keys"
                + ("" if loopback else f"; listener bound directly on {host}"),
            })
            if loopback and not agents.get("client_ip_header"):
                findings.append({
                    "level": "WARN",
                    "check": "agents.client_ip_header",
                    "detail": "unset; behind a tunnel every agent shares one address, so failed-attempt limits apply to all",
                })
        elif not agents.get("tailnet_node_ids"):
            findings.append({"level": "FAIL", "check": "agents.tailnet_node_ids", "detail": "empty; agents cannot be admitted"})
        else:
            findings.append({"level": "PASS", "check": "agents.tailnet_node_ids", "detail": f"{len(agents['tailnet_node_ids'])} node id(s) pinned"})
    else:
        findings.append({"level": "WARN", "check": "agents.enabled", "detail": "agent listener is off in this config"})
    remote = cfg.get("remote") or {}
    if remote.get("enabled"):
        url = str(remote.get("public_url", ""))
        findings.append({
            "level": "WARN" if ".ts.net" in url else "INFO",
            "check": "remote.public_url",
            "detail": f"OAuth endpoint published at {url}; confirm it is tailnet-only (no Funnel) unless intended",
        })
        if "*" in (remote.get("allow_devices") or []):
            findings.append({"level": "WARN", "check": "remote.allow_devices", "detail": "'*' offers every enrolled device to remote clients"})
    findings.extend(command_findings(cfg, "local device"))
    return findings


def command_findings(cfg: dict, label: str) -> list[dict]:
    findings: list[dict] = []
    cmds = cfg.get("commands") or {}
    mode = cmds.get("mode", "allowlist")
    allow = [str(a).lower() for a in (cmds.get("allow") or [])]
    if mode == "unrestricted":
        findings.append({"level": "WARN", "check": f"{label} commands.mode", "detail": "unrestricted"})
    if "git" in allow:
        findings.append({
            "level": "WARN",
            "check": f"{label} commands.allow",
            "detail": "git is allowlisted; `git diff --no-index` reads files outside the deny list (PR #29 removes it)",
        })
    shells = sorted(SHELLS.intersection(allow))
    if shells:
        findings.append({"level": "WARN", "check": f"{label} commands.allow", "detail": f"shell/interpreter allowlisted: {shells}"})
    return findings


def env_strip_finding() -> dict:
    try:
        from contextbridge.computer.policy import ALWAYS_STRIPPED_ENV
    except Exception as exc:  # not importable from this interpreter
        return {"level": "SKIP", "check": "ALWAYS_STRIPPED_ENV", "detail": f"cannot import policy: {exc}"}
    if "CONTEXTBRIDGE_FS_AUTH_TOKEN" in ALWAYS_STRIPPED_ENV:
        return {"level": "PASS", "check": "ALWAYS_STRIPPED_ENV", "detail": "includes the filesystem token"}
    return {
        "level": "WARN",
        "check": "ALWAYS_STRIPPED_ENV",
        "detail": "omits CONTEXTBRIDGE_FS_AUTH_TOKEN (relies on the *TOKEN* glob; PR #33)",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kind", choices=("gateway", "agent"), required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--hours", type=float, default=24.0)
    args = ap.parse_args()

    config_path = Path(args.config).expanduser().resolve()
    try:
        cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(json.dumps({"error": f"cannot read {config_path}: {exc}"}))
        return 2

    since = time.time() - args.hours * 3600
    boot = boot_time()
    out: dict = {"kind": args.kind, "config": str(config_path), "window_hours": args.hours, "boot_time": iso(boot)}

    if args.kind == "gateway":
        audit_path = resolve(config_path, (cfg.get("serve") or {}).get("audit_log"))
        out["agents_listener"] = {
            "enabled": bool((cfg.get("agents") or {}).get("enabled")),
            "host": (cfg.get("agents") or {}).get("host"),
            "port": (cfg.get("agents") or {}).get("port"),
        }
        out["serve_port"] = (cfg.get("serve") or {}).get("port")
        out["remote_port"] = (cfg.get("remote") or {}).get("port") if (cfg.get("remote") or {}).get("enabled") else None
        out["findings"] = gateway_findings(cfg) + [env_strip_finding()]
        wanted = GATEWAY_EVENTS
    else:
        audit_path = resolve(config_path, cfg.get("audit_log"))
        gateway = cfg.get("gateway") or {}
        out["device_name"] = cfg.get("name")
        out["gateway_url"] = gateway.get("url")
        fingerprint = str(gateway.get("fingerprint", ""))
        out["findings"] = command_findings(cfg, "agent")
        if "REPLACE" in fingerprint:
            out["findings"].append({"level": "FAIL", "check": "gateway.fingerprint", "detail": "still the placeholder"})
        identity = resolve(config_path, cfg.get("identity"))
        out["identity_present"] = bool(identity and identity.exists())
        out["lock_file"] = str(identity.with_name(identity.name + ".run.lock")) if identity else None
        wanted = AGENT_EVENTS

    out["audit_log"] = str(audit_path) if audit_path else None
    out["since_boot"] = None
    out["audit_last_write"] = None
    if audit_path is None or not audit_path.exists():
        out["audit"] = None
        out["findings"].append({"level": "FAIL", "check": "audit_log", "detail": f"missing: {audit_path}"})
    else:
        summary = read_events(audit_path, since, wanted)
        raw = summary.pop("_timeline_raw")
        out["audit"] = summary
        out["audit_last_write"] = iso(audit_path.stat().st_mtime)
        if args.kind == "agent" and boot is not None:
            after_boot = [ts for ts, ev in raw if ts >= boot]
            first_conn = next((ts for ts, ev in raw if ts >= boot and ev == "gateway_connected"), None)
            starts = [ts for ts, ev in raw if ts >= boot and ev == "agent_started"]
            out["since_boot"] = {
                "agent_started": len(starts),
                "first_agent_started_after_boot_s": round(starts[0] - boot, 1) if starts else None,
                "first_gateway_connected_after_boot_s": round(first_conn - boot, 1) if first_conn else None,
                "events": len(after_boot),
            }
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
