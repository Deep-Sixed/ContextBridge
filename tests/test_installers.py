"""The one-command installers the gateway serves at /install/<name>."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from test_activation import AGENTS_URL, gw  # noqa: F401 -- the gateway fixture
from test_oauth import PUBLIC

from contextbridge.oauth.activation import INSTALLERS
from contextbridge.remote.agent import load_agent_config

LINUX = Path(__file__).resolve().parents[1] / "src" / "contextbridge" / "oauth" / "installers" / "remote-linux.sh"
posix_sh = pytest.mark.skipif(os.name == "nt" or shutil.which("sh") is None, reason="needs a POSIX sh")


def test_gateway_serves_each_installer_with_its_own_addresses(gw):  # noqa: F811
    async def scenario():
        async with gw.client() as http:
            pages = {name: await http.get(f"/install/{name}") for name in INSTALLERS}
            missing = await http.get("/install/other.sh")
            traversal = await http.get("/install/..%2Factivation.py")
            return pages, missing, traversal

    pages, missing, traversal = asyncio.run(scenario())
    for name, page in pages.items():
        assert page.status_code == 200, name
        assert "__CONTEXTBRIDGE" not in page.text, name
        assert PUBLIC in page.text and page.headers["cache-control"] == "no-store"
    assert f'AGENTS_URL="${{CONTEXTBRIDGE_AGENTS_URL:-{AGENTS_URL}}}"' in pages["remote-linux.sh"].text
    assert f"GatewayUrl = '{AGENTS_URL}'" in pages["remote-windows.ps1"].text
    assert "attachment" in pages["ContextBridgeSetup.cmd"].headers["content-disposition"]
    # Whatever line endings the checkout has: CRLF for cmd.exe, LF for sh.
    cmd = pages["ContextBridgeSetup.cmd"].content
    assert cmd.count(b"\r\n") == cmd.count(b"\n") > 5
    assert b"\r" not in pages["remote-linux.sh"].content
    assert missing.status_code == 404 and traversal.status_code == 404


def run_linux(*args: str, home: Path, check: bool = True) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ["PATH"], "HOME": str(home)}
    result = subprocess.run(["sh", str(LINUX), *args], capture_output=True, text=True, env=env, timeout=60)
    if check:
        assert result.returncode == 0, result.stderr
    return result


@posix_sh
def test_linux_installer_is_valid_sh():
    subprocess.run(["sh", "-n", str(LINUX)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-s", "sh", "-S", "warning", str(LINUX)], check=True)


@posix_sh
@pytest.mark.parametrize("preset", ["readonly", "full"])
def test_linux_installer_writes_a_config_the_agent_loads(tmp_path, preset):
    plan = run_linux(
        "--dry-run", "--server", "https://mcp.example.com/", "--agents-url", "wss://agents.example.com",
        "--name", "laptop", "--policy", preset, "--dir", str(tmp_path / "cb"), home=tmp_path,
    ).stdout
    assert "browser activation at https://mcp.example.com/activate" in plan
    config_file = tmp_path / "cb" / "agent.yaml"
    config_file.parent.mkdir()
    config_file.write_text(plan.split("--- agent.yaml ---\n", 1)[1], encoding="utf-8")
    config = load_agent_config(config_file)
    assert config.name == "laptop" and config.gateway_url == "wss://agents.example.com"
    assert config.identity_path == tmp_path / "cb" / "state" / "agent-identity.json"
    summary = config.policy.summary()
    assert summary["process_command_lines"] is False
    if preset == "readonly":
        assert summary["writable_roots"] == [] and summary["command_mode"] == "allowlist"
        assert summary["allow_kill"] is False
    else:
        assert summary["command_mode"] == "unrestricted" and summary["allow_kill"] is True


@posix_sh
def test_linux_installer_names_the_device_after_the_host_and_keeps_an_installed_name(tmp_path):
    base = ("--dry-run", "--server", "https://mcp.example.com", "--agents-url", "wss://agents.example.com",
            "--dir", str(tmp_path / "cb"))
    plan = run_linux(*base, home=tmp_path).stdout
    host = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip().lower()
    expected = "".join(c if c.isalnum() or c == "-" else "-" for c in host).strip("-")[:63]
    assert f"Device:    {expected}" in plan
    (tmp_path / "cb").mkdir()
    (tmp_path / "cb" / "agent.yaml").write_text("name: raven\n", encoding="utf-8")
    assert "Device:    raven" in run_linux(*base, home=tmp_path).stdout
    renamed = run_linux(*base, "--name", "other", home=tmp_path, check=False)
    assert renamed.returncode != 0 and "installed as 'raven'" in renamed.stderr


@posix_sh
@pytest.mark.parametrize(
    ("args", "message"),
    [
        ((), "pass --server"),  # run from the repository, the placeholders are not filled in
        (("--server", "http://mcp.example.com", "--agents-url", "wss://a"), "pass --server"),
        (("--server", "https://mcp.example.com"), "pass --agents-url"),
        (("--server", "https://m", "--agents-url", "wss://a", "--policy", "admin"), "readonly or full"),
        (("--server", "https://m", "--agents-url", "wss://a", "--name", "local"), "not allowed"),
        (("--server", "https://m", "--agents-url", "wss://a", "--name", "Bad_Name!"), "not valid"),
    ],
)
def test_linux_installer_refuses_bad_options(tmp_path, args, message):
    result = run_linux("--dry-run", *args, home=tmp_path, check=False)
    assert result.returncode != 0 and message in result.stderr
