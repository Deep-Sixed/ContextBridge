#!/bin/sh
# ContextBridge agent installer for Linux.
#
#   curl -fsSL __CONTEXTBRIDGE_SERVER__/install/remote-linux.sh | sh
#   curl -fsSL __CONTEXTBRIDGE_SERVER__/install/remote-linux.sh | sh -s -- --name laptop --policy full
#
# Installs the agent for the user who runs it, in ~/.local/share/contextbridge, as a systemd user service.
# It asks for sudo only to install missing system packages (Python, venv, Git) and to let the service run
# while that user is signed out. The agent itself never runs as root: installing it and what it may do are
# separate choices, and what it may do is this machine's own config (the --policy preset to start with).
#
# The device is added by browser approval: the script prints a code, you open the gateway's /activate page,
# sign in, check the device, and approve. Running it again upgrades an installed agent in place.
set -eu

SERVER="${CONTEXTBRIDGE_SERVER:-__CONTEXTBRIDGE_SERVER__}"
AGENTS_URL="${CONTEXTBRIDGE_AGENTS_URL:-__CONTEXTBRIDGE_AGENTS_URL__}"
REPO_URL="https://github.com/Deep-Sixed/ContextBridge"
REVISION="main"
NAME=""
POLICY="readonly"
PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/contextbridge"
UNIT="contextbridge-agent.service"
DRY_RUN=0
LINGER=1

usage() {
    cat <<'EOF'
Usage: remote-linux.sh [options]
  --name NAME          device name (default: this computer's hostname in lower case)
  --policy PRESET      readonly (default): read your home folder, run a few diagnostic programs
                       full: read and write your home folder, run any command, end processes
  --server URL         the gateway's https address (preset when downloaded from the gateway)
  --agents-url URL     the wss:// address agents connect to (preset when downloaded from the gateway)
  --revision REV       ContextBridge branch, tag or commit (default: main)
  --dir DIR            install here (default: ~/.local/share/contextbridge)
  --no-linger          do not keep the agent running while you are signed out (skips that sudo step)
  --dry-run            show what would be done and the config, change nothing
EOF
}

step() { printf '==> %s\n' "$*"; }
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --name) NAME="${2:?--name needs a value}"; shift 2 ;;
        --policy) POLICY="${2:?--policy needs a value}"; shift 2 ;;
        --server) SERVER="${2:?--server needs a value}"; shift 2 ;;
        --agents-url) AGENTS_URL="${2:?--agents-url needs a value}"; shift 2 ;;
        --revision) REVISION="${2:?--revision needs a value}"; shift 2 ;;
        --dir) PREFIX="${2:?--dir needs a value}"; shift 2 ;;
        --no-linger) LINGER=0; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; fail "unknown option: $1" ;;
    esac
done

case "$SERVER" in
    https://*|http://127.0.0.1*|http://localhost*) SERVER="${SERVER%/}" ;;
    *) fail "pass --server with the gateway's https address (for example https://mcp.example.com)" ;;
esac
case "$AGENTS_URL" in
    wss://*|ws://127.0.0.1*|ws://localhost*) ;;
    *) fail "pass --agents-url with the wss:// address agents connect to" ;;
esac
case "$POLICY" in
    readonly|full) ;;
    *) fail "--policy must be readonly or full" ;;
esac
[ "$(uname -s)" = "Linux" ] || fail "this installer is for Linux"
if [ "$(id -u)" = "0" ] && [ "$DRY_RUN" = "0" ]; then
    fail "run this as the user the agent should run as, not as root; it asks for sudo when it needs it"
fi

CONFIG="$PREFIX/agent.yaml"
IDENTITY="$PREFIX/state/agent-identity.json"
AUDIT="$PREFIX/audit/agent.audit.jsonl"
VENV="$PREFIX/venv"
APP="$PREFIX/app"

if [ -f "$CONFIG" ]; then
    # Keep the name of an existing install: it is enrolled under it.
    existing=$(sed -n 's/^name:[[:space:]]*\([a-z0-9-]*\).*/\1/p' "$CONFIG" | head -n 1)
    if [ -n "$NAME" ] && [ -n "$existing" ] && [ "$NAME" != "$existing" ]; then
        fail "this machine is installed as '$existing'; leave out --name (to rename it, revoke it on the gateway and remove $PREFIX)"
    fi
    NAME="$existing"
fi
if [ -z "$NAME" ]; then
    NAME=$(hostname 2>/dev/null || cat /etc/hostname)
    NAME=$(printf '%s' "$NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g; s/^-*//; s/-*$//' | cut -c1-63)
fi
case "$NAME" in
    local|all|gateway|"") fail "device name '$NAME' is not allowed; pass --name" ;;
esac
printf '%s' "$NAME" | grep -Eq '^[a-z0-9][a-z0-9-]{0,62}$' || fail "device name '$NAME' is not valid: use lowercase letters, digits or '-'; pass --name"

write_config() {
    cat <<EOF
# ContextBridge agent config written by remote-linux.sh ($POLICY preset).
# This file is this machine's own policy: the gateway cannot widen it. See configs/agent.yaml for every option.
name: $NAME

gateway:
  url: $AGENTS_URL

identity: state/agent-identity.json
audit_log: audit/agent.audit.jsonl
max_concurrent_calls: 8

EOF
    if [ "$POLICY" = "full" ]; then
        cat <<'EOF'
filesystem:
  roots: ["~"]
  writable_roots: ["~"]
  delete: trash

commands:
  mode: unrestricted
  max_timeout_seconds: 600

processes:
  list: true
  command_lines: false
  allow_kill: true

desktop:
  observe: false

media:
  discover: false
EOF
    else
        cat <<'EOF'
filesystem:
  roots: ["~"]
  writable_roots: []
  delete: trash

commands:
  mode: allowlist
  allow: [ls, df, du, uptime, whoami, hostname, uname, date, pwd]
  max_timeout_seconds: 600

processes:
  list: true
  command_lines: false
  allow_kill: false

desktop:
  observe: false

media:
  discover: false
EOF
    fi
}

if [ "$DRY_RUN" = "1" ]; then
    printf 'Device:    %s\n' "$NAME"
    printf 'Server:    %s\n' "$SERVER"
    printf 'Agents:    %s\n' "$AGENTS_URL"
    printf 'Install:   %s (revision %s)\n' "$PREFIX" "$REVISION"
    if [ -f "$IDENTITY" ]; then echo "Enroll:    already enrolled ($IDENTITY)"; else echo "Enroll:    browser activation at $SERVER/activate"; fi
    if [ -f "$CONFIG" ]; then echo "Config:    keep $CONFIG"; else echo "Config:    write $CONFIG ($POLICY preset)"; fi
    printf 'Service:   systemd user unit %s\n' "$UNIT"
    echo '--- agent.yaml ---'
    write_config
    exit 0
fi

# 1. Prerequisites
python_ok() {
    command -v python3 >/dev/null 2>&1 &&
        python3 -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3, 11))' >/dev/null 2>&1
}
install_packages() {
    step "Installing $* (needs sudo)"
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y -qq "$@"
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y -q "$@"
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --needed --noconfirm "$@"
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper --non-interactive install "$@"
    else
        fail "install $* yourself, then run this again"
    fi
}
step "Checking for Python 3.11+, venv and Git"
if ! python_ok; then
    if command -v apt-get >/dev/null 2>&1; then install_packages python3 python3-venv python3-pip
    elif command -v pacman >/dev/null 2>&1; then install_packages python python-pip
    else install_packages python3 python3-pip
    fi
    python_ok || fail "Python 3.11 or newer with venv is needed; this system's python3 is older or lacks venv"
fi
command -v git >/dev/null 2>&1 || install_packages git
command -v systemctl >/dev/null 2>&1 || fail "systemd is needed to keep the agent running"

# 2. Code
mkdir -p "$PREFIX/state" "$PREFIX/audit"
chmod 700 "$PREFIX" "$PREFIX/state"
if [ -d "$APP/.git" ]; then
    step "Fetching ContextBridge into $APP"
    git -C "$APP" fetch --quiet --tags origin
else
    step "Cloning ContextBridge into $APP"
    git clone --quiet "$REPO_URL" "$APP"
fi
target=$(git -C "$APP" rev-parse --verify --quiet "origin/$REVISION^{commit}" || git -C "$APP" rev-parse --verify --quiet "$REVISION^{commit}") ||
    fail "revision '$REVISION' was not found"
git -C "$APP" -c advice.detachedHead=false checkout --quiet --detach "$target"
echo "    Revision: $(git -C "$APP" rev-parse --short HEAD)"

# 3. Package
[ -x "$VENV/bin/python" ] || { step "Creating the virtual environment"; python3 -m venv "$VENV"; }
step "Installing ContextBridge (this takes a minute or two)"
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade "$APP"

# 4. Config
if [ -f "$CONFIG" ]; then
    step "Keeping the existing $CONFIG"
else
    step "Writing $CONFIG ($POLICY preset)"
    write_config > "$CONFIG"
fi
"$VENV/bin/python" -c 'import sys; from contextbridge.remote.agent import load_agent_config; c = load_agent_config(sys.argv[1]); print("    Device:", c.name, " Gateway:", c.gateway_url)' "$CONFIG"

# 5. Activation (browser approval)
if [ -f "$IDENTITY" ]; then
    step "Already enrolled; keeping the device identity"
else
    step "Activating this device"
    "$VENV/bin/contextbridge-agent" activate --config "$CONFIG" --server "$SERVER"
fi

# 6. Service
step "Starting the agent as a systemd user service ($UNIT)"
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/$UNIT" <<EOF
[Unit]
Description=ContextBridge agent ($NAME)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$VENV/bin/contextbridge-agent run --config $CONFIG
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
systemctl --user daemon-reload
systemctl --user enable --quiet "$UNIT"
systemctl --user restart "$UNIT"
if [ "$LINGER" = "1" ] && [ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || echo no)" != "yes" ]; then
    step "Letting the agent run while you are signed out (needs sudo; skip with --no-linger)"
    sudo loginctl enable-linger "$(id -un)" || echo "    Could not enable lingering; the agent runs only while you are signed in."
fi

# 7. Connection check: the agent records gateway_connected in its audit log once the gateway accepts it.
step "Waiting for the agent to connect"
i=0
while [ $i -lt 30 ]; do
    if [ -f "$AUDIT" ] && grep '"event":"gateway_connected"' "$AUDIT" | sed -n 's/.*"ts":"\([^"]*\)".*/\1/p' | awk -v s="$started" '$0 >= s {found=1} END {exit !found}'; then
        printf 'ContextBridge agent %s installed and connected.\n' "$NAME"
        echo "To use it from Claude or ChatGPT, reconnect the client and tick $NAME on the consent page."
        exit 0
    fi
    sleep 2
    i=$((i + 1))
done
fail "the service is installed, but the agent has not connected within 60 seconds; check: journalctl --user -u $UNIT"
