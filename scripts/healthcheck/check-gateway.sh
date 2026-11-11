#!/usr/bin/env bash
# ContextBridge local health check for the gateway host (Friday).
#
# Read-only unless --recovery-test is passed. Prints PASS/WARN/FAIL/SKIP lines and writes a
# Markdown report to audit/healthcheck/. Never prints tokens or file contents.
#
#   scripts/healthcheck/check-gateway.sh                       # read-only checks
#   scripts/healthcheck/check-gateway.sh --fetch               # also `git fetch` to compare with origin/main
#   scripts/healthcheck/check-gateway.sh --drill               # also run the read-only failover drill
#   scripts/healthcheck/check-gateway.sh --recovery-test 'systemctl --user restart contextbridge-computer'
#                                                              # DISRUPTIVE: restart the gateway with your
#                                                              # command, time agent reconnects, re-run the drill
# Options: --config PATH (default configs/computer.yaml), --hours N (audit window, default 24),
#          --timeout S (reconnect wait for --recovery-test, default 180)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${CONTEXTBRIDGE_COMPUTER_CONFIG:-$ROOT/configs/computer.yaml}"
HOURS=24
FETCH=0
DRILL=0
RESTART_CMD=""
TIMEOUT=180

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2 ;;
    --hours) HOURS="$2"; shift 2 ;;
    --fetch) FETCH=1; shift ;;
    --drill) DRILL=1; shift ;;
    --recovery-test) RESTART_CMD="$2"; DRILL=1; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
  if [[ -x "$ROOT/.venv/bin/python" ]]; then PY="$ROOT/.venv/bin/python"; else PY="python3"; fi
fi
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_DIR="$ROOT/audit/healthcheck"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/gateway-$STAMP.md"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILS=0; WARNS=0
line() {  # level check detail
  local level="$1" check="$2" detail="$3"
  case "$level" in FAIL) FAILS=$((FAILS+1)) ;; WARN) WARNS=$((WARNS+1)) ;; esac
  printf '%-5s %-34s %s\n' "$level" "$check" "$detail"
  printf '| %s | %s | %s |\n' "$level" "$check" "${detail//|/\\|}" >> "$WORK/rows.md"
}
have() { command -v "$1" >/dev/null 2>&1; }

echo "ContextBridge gateway check on $(hostname) at $STAMP"
echo "config: $CONFIG"
echo

# ---------------------------------------------------------------- 1. code revision
cd "$ROOT" || exit 2
# Explicit refspec so origin/main is updated even in a clone that tracks only some branches.
if [[ $FETCH -eq 1 ]]; then git fetch --quiet origin '+refs/heads/main:refs/remotes/origin/main' 2>/dev/null || line WARN "git fetch" "could not reach origin"; fi
HEAD_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
MAIN_SHA="$(git rev-parse --short origin/main 2>/dev/null || echo '?')"
if [[ "$HEAD_SHA" == "$MAIN_SHA" ]]; then
  line PASS "revision" "$BRANCH @ $HEAD_SHA (= origin/main)"
else
  BEHIND="$(git rev-list --count HEAD..origin/main 2>/dev/null || echo '?')"
  AHEAD="$(git rev-list --count origin/main..HEAD 2>/dev/null || echo '?')"
  line WARN "revision" "$BRANCH @ $HEAD_SHA; origin/main $MAIN_SHA ($BEHIND behind, $AHEAD ahead)"
fi
if [[ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
  line WARN "working tree" "uncommitted changes to tracked files"
else
  line PASS "working tree" "clean"
fi
PKG_VER="$("$PY" -c 'import contextbridge; print(contextbridge.__version__)' 2>/dev/null || echo '')"
if [[ -n "$PKG_VER" ]]; then line PASS "package" "contextbridge $PKG_VER via $PY"; else line FAIL "package" "contextbridge not importable with $PY"; fi

# ---------------------------------------------------------------- 2. config + audit summary
if ! "$PY" "$ROOT/scripts/healthcheck/audit_summary.py" --kind gateway --config "$CONFIG" --hours "$HOURS" > "$WORK/summary.json" 2>"$WORK/summary.err"; then
  line FAIL "audit summary" "$(head -c 200 "$WORK/summary.err")"
fi
summary() { "$PY" - "$WORK/summary.json" "$@" <<'EOF'
import json, sys
data = json.load(open(sys.argv[1]))
expr = sys.argv[2]
val = eval(expr, {}, {"d": data})
print("" if val is None else val)
EOF
}
if [[ -s "$WORK/summary.json" ]]; then
  "$PY" - "$WORK/summary.json" <<'EOF' > "$WORK/findings.tsv"
import json, sys
for f in json.load(open(sys.argv[1])).get("findings", []):
    print(f"{f['level']}\t{f['check']}\t{f['detail']}")
EOF
  while IFS=$'\t' read -r lvl chk det; do line "$lvl" "$chk" "$det"; done < "$WORK/findings.tsv"
  SERVE_PORT="$(summary 'd.get("serve_port")')"
  AG_ENABLED="$(summary 'd["agents_listener"]["enabled"]')"
  AG_HOST="$(summary 'd["agents_listener"]["host"]')"
  AG_PORT="$(summary 'd["agents_listener"]["port"]')"
  REMOTE_PORT="$(summary 'd.get("remote_port")')"
else
  SERVE_PORT=8791; AG_ENABLED=False; AG_HOST=""; AG_PORT=8792; REMOTE_PORT=""
fi

# ---------------------------------------------------------------- 3. processes + listeners
GW_PIDS="$(pgrep -f 'contextbridge\.computer( |$)|contextbridge-computer' | tr '\n' ' ')"
GW_COUNT="$(wc -w <<<"$GW_PIDS")"
case "$GW_COUNT" in
  0) line FAIL "gateway process" "not running" ;;
  1) line PASS "gateway process" "pid $GW_PIDS(up $(ps -o etime= -p ${GW_PIDS%% *} | tr -d ' '))" ;;
  *) line WARN "gateway process" "$GW_COUNT running: $GW_PIDS(stale test gateway?)" ;;
esac
LOCAL_AGENTS="$(pgrep -fc 'contextbridge\.remote\.agent run' || true)"
[[ "${LOCAL_AGENTS:-0}" -gt 0 ]] && line WARN "local agent processes" "$LOCAL_AGENTS agent(s) running on the gateway host; expected 0 unless intended"
STRAY_TESTS="$(pgrep -fc 'pytest|failover_jail' || true)"
[[ "${STRAY_TESTS:-0}" -gt 0 ]] && line WARN "test processes" "$STRAY_TESTS pytest/jail process(es) still running"

if have ss; then
  ss -Hltn > "$WORK/listen.txt" 2>/dev/null
  if grep -qE "127\.0\.0\.1:${SERVE_PORT}\b" "$WORK/listen.txt"; then line PASS "local MCP listener" "127.0.0.1:$SERVE_PORT"; else line FAIL "local MCP listener" "nothing on 127.0.0.1:$SERVE_PORT"; fi
  if [[ "$AG_ENABLED" == "True" ]]; then
    if grep -qE "${AG_HOST//./\\.}:${AG_PORT}\b" "$WORK/listen.txt"; then line PASS "agent listener" "$AG_HOST:$AG_PORT"; else line FAIL "agent listener" "nothing on $AG_HOST:$AG_PORT"; fi
  fi
  if [[ -n "$REMOTE_PORT" ]]; then
    if grep -qE "127\.0\.0\.1:${REMOTE_PORT}\b" "$WORK/listen.txt"; then line PASS "remote OAuth listener" "127.0.0.1:$REMOTE_PORT"; else line FAIL "remote OAuth listener" "nothing on 127.0.0.1:$REMOTE_PORT"; fi
  fi
  EXPOSED="$(grep -E '(0\.0\.0\.0|\[::\]|\*):(879[0-4])\b' "$WORK/listen.txt" | awk '{print $4}' | tr '\n' ' ')"
  if [[ -n "$EXPOSED" ]]; then line FAIL "wildcard binds" "ContextBridge port on all interfaces: $EXPOSED"; else line PASS "wildcard binds" "no 8790-8794 port on 0.0.0.0/::"; fi
else
  line SKIP "listeners" "ss not installed"
fi

# ---------------------------------------------------------------- 4. tailscale + exposure
if have tailscale; then
  if tailscale status --json > "$WORK/ts.json" 2>/dev/null; then
    "$PY" - "$WORK/ts.json" <<'EOF' > "$WORK/ts.tsv"
import json, sys
d = json.load(open(sys.argv[1]))
state = d.get("BackendState")
print(f"{'PASS' if state == 'Running' else 'FAIL'}\ttailscale\tbackend {state}; self {d.get('Self', {}).get('HostName')}")
for peer in (d.get("Peer") or {}).values():
    name = (peer.get("HostName") or "").lower()
    if "thanatos" in name:
        lvl = "PASS" if peer.get("Online") else "FAIL"
        print(f"{lvl}\ttailscale peer {name}\tonline={peer.get('Online')} id={peer.get('ID')} lastSeen={peer.get('LastSeen')}")
EOF
    while IFS=$'\t' read -r lvl chk det; do line "$lvl" "$chk" "$det"; done < "$WORK/ts.tsv"
  else
    line FAIL "tailscale" "status unavailable"
  fi
  FUNNEL="$(tailscale funnel status 2>/dev/null || true)"
  if grep -qi "funnel on" <<<"$FUNNEL"; then
    line WARN "tailscale funnel" "Funnel is ON (public internet); remote clients use Cloudflare Tunnel, so turn it off: tailscale funnel reset"
  else
    line PASS "tailscale funnel" "no public Funnel"
  fi
else
  line SKIP "tailscale" "CLI not installed"
fi

if have ufw && ufw status >/dev/null 2>&1; then
  line INFO "firewall" "ufw: $(ufw status | head -1)"
elif have nft && nft list ruleset >/dev/null 2>&1; then
  line INFO "firewall" "nftables rules: $(nft list ruleset | grep -c 'dport') port rules"
else
  line SKIP "firewall" "needs root to read (re-run with sudo for this line)"
fi

# ---------------------------------------------------------------- 5. enrolled devices + audit events
if "$PY" -m contextbridge.remote.admin --config "$CONFIG" devices > "$WORK/devices.txt" 2>&1; then
  ACTIVE="$(grep -c ' active ' "$WORK/devices.txt" || true)"
  PENDING="$(grep -c 'pending enrollment' "$WORK/devices.txt" || true)"
  line PASS "enrolled devices" "$ACTIVE active, $PENDING pending"
  [[ "$PENDING" -gt 0 ]] && line WARN "pending enrollments" "unused pairing code(s) outstanding; revoke if not expected"
else
  line FAIL "enrolled devices" "$(head -c 200 "$WORK/devices.txt")"
fi

if [[ -s "$WORK/summary.json" ]]; then
  "$PY" - "$WORK/summary.json" <<'EOF' > "$WORK/events.tsv"
import json, sys
d = json.load(open(sys.argv[1]))
a = d.get("audit") or {}
c = a.get("counts", {})
h = d["window_hours"]
def n(k): return c.get(k, 0)
print(f"INFO\taudit window\tlast {h}h; log last written {d.get('audit_last_write')}")
print(f"{'WARN' if n('device_auth_failed') or n('device_enroll_rejected') or n('tailnet_admission_denied') else 'PASS'}\tauth failures\t"
      f"auth_failed={n('device_auth_failed')} enroll_rejected={n('device_enroll_rejected')} tailnet_denied={n('tailnet_admission_denied')}")
print(f"{'WARN' if n('device_duplicate_refused') else 'PASS'}\tduplicate connections\trefused={n('device_duplicate_refused')}")
print(f"{'WARN' if n('device_heartbeat_lost') > 2 else 'INFO'}\tconnection churn\t"
      f"connected={n('device_connected')} disconnected={n('device_disconnected')} heartbeat_lost={n('device_heartbeat_lost')}")
for name, s in sorted((a.get("devices") or {}).items()):
    print(f"INFO\tdevice {name}\tlast connected {s.get('last_device_connected')} "
          f"agent {s.get('agent_version')} host {s.get('reported_hostname')}")
EOF
  while IFS=$'\t' read -r lvl chk det; do line "$lvl" "$chk" "$det"; done < "$WORK/events.tsv"
fi

# ---------------------------------------------------------------- 6. recovery test (opt-in, disruptive)
AUDIT_LOG="$(summary 'd.get("audit_log")' 2>/dev/null)"
if [[ -n "$RESTART_CMD" ]]; then
  echo
  echo ">>> RECOVERY TEST: restarting the gateway with: $RESTART_CMD"
  T0="$(date -u +%s)"; T0_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Every active enrolled device must reconnect; one device coming back is not enough.
  EXPECTED="$(awk '$3 == "active" {print $1}' "$WORK/devices.txt" 2>/dev/null | tr '\n' ' ')"
  if [[ -z "${EXPECTED// /}" ]]; then
    line FAIL "gateway restart recovery" "no active enrolled devices to wait for; not restarting"
  elif bash -c "$RESTART_CMD"; then
    DEADLINE=$((T0 + TIMEOUT)); STATE=""
    while :; do
      # Prints "<reconnected device@seconds ...>\t<missing device ...>"
      STATE="$("$PY" - "$AUDIT_LOG" "$T0_ISO" "$T0" $EXPECTED <<'EOF'
import json, sys
from datetime import datetime, timezone
log, t0_iso, t0, expected = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
first = {}
for raw in open(log, encoding="utf-8", errors="replace"):
    try: e = json.loads(raw)
    except ValueError: continue
    dev, ts = e.get("device"), e.get("ts", "")
    if e.get("event") == "device_connected" and ts >= t0_iso and dev in expected and dev not in first:
        secs = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp() - t0
        first[dev] = int(secs)
done = " ".join(f"{d}@{first[d]}s" for d in expected if d in first)
missing = " ".join(d for d in expected if d not in first)
print(f"{done}\t{missing}")
EOF
)"
      [[ -z "${STATE#*$'\t'}" || $(date -u +%s) -ge $DEADLINE ]] && break
      sleep 2
    done
    DONE="${STATE%%$'\t'*}"; MISSING="${STATE#*$'\t'}"
    if [[ -z "$MISSING" ]]; then
      line PASS "gateway restart recovery" "all devices reconnected: $DONE"
    else
      line FAIL "gateway restart recovery" "not reconnected within ${TIMEOUT}s: $MISSING (reconnected: ${DONE:-none})"
    fi
  else
    line FAIL "gateway restart recovery" "restart command failed"
  fi
fi

# ---------------------------------------------------------------- 7. failover drill (opt-in)
if [[ $DRILL -eq 1 ]]; then
  if [[ -z "${CONTEXTBRIDGE_COMPUTER_TOKEN:-}" ]]; then
    line SKIP "failover drill" "CONTEXTBRIDGE_COMPUTER_TOKEN not set in this shell"
  else
    "$PY" -m contextbridge.failover --config "$CONFIG" > "$WORK/drill.txt" 2>&1
    case $? in
      0) line PASS "failover drill" "READY (read-only probes on every device)" ;;
      1) line FAIL "failover drill" "NOT READY: $(grep -m3 FAIL "$WORK/drill.txt" | tr '\n' ';' | head -c 300)" ;;
      *) line FAIL "failover drill" "could not run: $(tail -1 "$WORK/drill.txt" | head -c 200)" ;;
    esac
    cp "$WORK/drill.txt" "$REPORT_DIR/gateway-$STAMP-drill.txt"
  fi
else
  line SKIP "failover drill" "pass --drill to run the read-only drill"
fi

# ---------------------------------------------------------------- report
{
  echo "# ContextBridge gateway check: $(hostname), $STAMP"
  echo
  echo "Revision \`$HEAD_SHA\` on \`$BRANCH\` (origin/main \`$MAIN_SHA\`). Config \`$CONFIG\`."
  echo "Result: **$FAILS fail, $WARNS warn**."
  echo
  echo "| Level | Check | Detail |"
  echo "|---|---|---|"
  cat "$WORK/rows.md"
  echo
  echo "Recent connection events (UTC):"
  echo
  echo '```'
  [[ -s "$WORK/summary.json" ]] && "$PY" -c 'import json,sys; [print(t, e) for t, e in (json.load(open(sys.argv[1])).get("audit") or {}).get("timeline", []) if e.startswith("device_")]' "$WORK/summary.json"
  echo '```'
} > "$REPORT"

echo
echo "Result: $FAILS fail, $WARNS warn. Report: $REPORT"
[[ $FAILS -eq 0 ]]
