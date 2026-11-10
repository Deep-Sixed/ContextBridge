from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from helpers import REPO, symlink_or_skip

from contextbridge.computer.policy import PolicyError, PolicyViolation, load_policy

posix_only = pytest.mark.skipif(os.name == "nt", reason="uses POSIX programs and shells")


def test_relative_paths_resolve_against_first_root(policy, workspace):
    assert policy.resolve("docs/notes.md") == workspace / "docs" / "notes.md"


def test_paths_outside_roots_are_denied(policy, workspace):
    with pytest.raises(PolicyViolation, match="outside the readable roots"):
        policy.resolve(str(workspace.parent / "outside.txt"))
    with pytest.raises(PolicyViolation):
        policy.resolve("../outside.txt")


def test_symlink_cannot_escape_roots(policy, workspace):
    link = workspace / "docs" / "escape.txt"
    symlink_or_skip(link, workspace.parent / "outside.txt")
    with pytest.raises(PolicyViolation, match="outside"):
        policy.resolve(str(link))
    assert not policy.is_visible(link)


def test_unfollowed_final_component_cannot_be_dotdot(policy, workspace):
    (workspace / "work" / "sub").mkdir()
    for raw in ("work/sub/..", "work/sub/../", str(workspace / "work" / ".."), ".."):
        with pytest.raises(PolicyViolation, match="must end in a file or directory name"):
            policy.resolve(raw, write=True, follow_symlinks=False)
    assert policy.resolve("work/sub/../sub", write=True, follow_symlinks=False) == workspace / "work" / "sub"


def test_unfollowed_resolution_names_the_symlink_itself(policy, workspace):
    link = symlink_or_skip(workspace / "work" / "notes-link.md", workspace / "docs" / "notes.md")
    assert policy.resolve(str(link), write=True, follow_symlinks=False) == link
    with pytest.raises(PolicyViolation, match="writable"):
        policy.resolve(str(link), write=True)


def test_denied_patterns_apply_to_every_path_component(policy, workspace):
    for raw in (".ssh/id_ed25519", ".ssh", ".env", "docs/server.pem"):
        with pytest.raises(PolicyViolation, match="denied"):
            policy.resolve(raw)


@pytest.mark.parametrize(
    "raw",
    [
        ".npmrc",
        ".pypirc",
        "firefox/key4.db",
        "firefox/key3.db",
        "firefox/cookies.sqlite",
        "PSReadLine/ConsoleHost_history.txt",
        "state/agent-identity.json",
        "state/identity.json",
    ],
)
def test_default_deny_covers_common_credential_files(policy, raw):
    with pytest.raises(PolicyViolation, match="denied"):
        policy.resolve(raw)


# Each of these makes allowlist mode unrestricted: git through its -c options and aliases.
_RUNS_OTHER_PROGRAMS = {"git", "bash", "sh", "zsh", "cmd", "powershell", "pwsh", "python", "python3", "py", "node"}


def test_example_configs_allowlist_no_program_that_runs_others():
    for path in sorted((REPO / "configs").glob("*.yaml")):
        cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
        commands = (cfg.get("commands") if isinstance(cfg, dict) else None) or {}
        allowed = {name.lower().removesuffix(".exe") for name in commands.get("allow") or []}
        assert not allowed & _RUNS_OTHER_PROGRAMS, f"{path.name} allowlists {sorted(allowed & _RUNS_OTHER_PROGRAMS)}"


def test_write_requires_writable_root(policy, workspace):
    assert policy.resolve("work/new.txt", write=True) == workspace / "work" / "new.txt"
    with pytest.raises(PolicyViolation, match="writable"):
        policy.resolve("docs/notes.md", write=True)


def test_protected_paths_are_never_writable(workspace):
    config = workspace / "work" / "computer.yaml"
    config.write_text("x", encoding="utf-8")
    policy = load_policy(
        {"filesystem": {"roots": [str(workspace)], "writable_roots": [str(workspace / "work")]}},
        protected=(config,),
    )
    assert policy.resolve(str(config)) == config
    with pytest.raises(PolicyViolation, match="protected"):
        policy.resolve(str(config), write=True)


def test_empty_and_nul_paths_are_rejected(policy):
    for raw in ("", "   ", "docs/\x00notes.md"):
        with pytest.raises(PolicyViolation):
            policy.resolve(raw)


@pytest.mark.parametrize(
    "cfg, message",
    [
        ({}, "at least one directory"),
        ({"filesystem": {"roots": ["/definitely/not/here"]}}, "not an existing directory"),
        ({"filesystem": {"roots": ["{root}/docs"], "writable_roots": ["{root}/work"]}}, "inside a readable root"),
        ({"filesystem": {"roots": ["{root}"]}, "commands": {"mode": "yolo"}}, "commands.mode"),
        ({"filesystem": {"roots": ["{root}"]}, "commands": {"mode": "allowlist"}}, "commands.allow"),
        ({"filesystem": {"roots": ["{root}"], "max_read_bytes": 0}}, "positive"),
    ],
)
def test_invalid_configs_fail_closed(workspace, cfg, message):
    def fill(value):
        if isinstance(value, dict):
            return {k: fill(v) for k, v in value.items()}
        if isinstance(value, list):
            return [fill(v) for v in value]
        return value.replace("{root}", str(workspace)) if isinstance(value, str) else value

    with pytest.raises(PolicyError, match=message):
        load_policy(fill(cfg))


def test_defaults_are_read_only_without_commands(workspace):
    policy = load_policy({"filesystem": {"roots": [str(workspace)]}})
    assert not policy.can_write
    assert not policy.commands_enabled
    assert not policy.allow_kill
    with pytest.raises(PolicyViolation, match="disabled"):
        policy.command_argv("echo hi")


@posix_only
def test_allowlist_resolves_program_on_path(policy):
    argv = policy.command_argv("echo 'hello world'")
    assert Path(argv[0]).name == "echo"
    assert argv[1:] == ["hello world"]


@pytest.mark.parametrize(
    "command",
    ["rm -rf /", "python3 -c 'print(1)'", "/tmp/evil/echo hi", "./echo hi"],
)
def test_allowlist_rejects_unlisted_programs(policy, command):
    with pytest.raises(PolicyViolation, match="allowlist"):
        policy.command_argv(command)


@posix_only  # Windows operators are covered in test_oscompat.py
@pytest.mark.parametrize(
    "command", ["ls | sh", "echo a; rm x", "echo a && echo b", "echo a > f", "cat < f", "echo $(id) &"]
)
def test_allowlist_rejects_shell_operators(policy, command):
    with pytest.raises(PolicyViolation, match="Shell operators"):
        policy.command_argv(command)


@posix_only  # Windows shells are covered in test_oscompat.py
def test_unrestricted_mode_uses_a_shell(make_policy):
    policy = make_policy(commands={"mode": "unrestricted"})
    argv = policy.command_argv("echo a | cat")
    assert argv[-1] == "echo a | cat"
    assert len(argv) >= 2


def test_child_env_strips_credentials(policy, monkeypatch):
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t1")
    monkeypatch.setenv("CONTEXTBRIDGE_COMPUTER_TOKEN", "t2")
    monkeypatch.setenv("GITHUB_TOKEN", "t3")
    monkeypatch.setenv("DB_PASSWORD", "t4")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "t5")
    monkeypatch.setenv("CB_HARMLESS", "ok")
    env = policy.child_env()
    stripped = ["MCP_AUTH_TOKEN", "CONTEXTBRIDGE_COMPUTER_TOKEN", "GITHUB_TOKEN", "DB_PASSWORD"]
    stripped.append("AWS_SECRET_ACCESS_KEY")
    for key in stripped:
        assert key not in env
    assert env["CB_HARMLESS"] == "ok"
    assert env.get("PATH") == os.environ.get("PATH")


def test_gateway_tokens_are_stripped_even_with_empty_env_strip(make_policy, monkeypatch):
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t1")
    policy = make_policy(commands={"env_strip": []})
    assert "MCP_AUTH_TOKEN" not in policy.child_env()


def test_route_tokens_are_stripped_with_a_custom_env_strip(make_policy, monkeypatch):
    route_tokens = {"MCP_AUTH_TOKEN", "CONTEXTBRIDGE_FS_AUTH_TOKEN", "CONTEXTBRIDGE_COMPUTER_TOKEN"}
    for key in route_tokens:
        monkeypatch.setenv(key, "secret")
    monkeypatch.setenv("GITHUB_TOKEN", "kept")
    env = make_policy(commands={"env_strip": ["*PASSWORD*"]}).child_env()
    assert not route_tokens & env.keys()
    assert env["GITHUB_TOKEN"] == "kept"  # the custom list replaced the default *TOKEN* glob


def test_default_timeout_follows_a_lower_max(make_policy):
    assert make_policy(commands={"max_timeout_seconds": 5}).default_timeout_seconds == 5
    with pytest.raises(PolicyError, match="cannot exceed"):
        make_policy(commands={"default_timeout_seconds": 10, "max_timeout_seconds": 5})


def test_timeouts_are_clamped(make_policy):
    policy = make_policy(commands={"default_timeout_seconds": 5, "max_timeout_seconds": 20})
    assert policy.clamp_timeout(None) == 5
    assert policy.clamp_timeout(0) == 5
    assert policy.clamp_timeout(10) == 10
    assert policy.clamp_timeout(999) == 20


def test_allowlist_warns_about_programs_that_print_other_processes_environments(make_policy, workspace):
    def warnings(allow, *, windows, mode="allowlist"):
        cfg = {"filesystem": {"roots": [str(workspace)]}, "commands": {"mode": mode, "allow": allow}}
        return load_policy(cfg, windows=windows).allowlist_warnings()

    assert make_policy().allowlist_warnings() == []
    for entry in ("ps", "/bin/ps"):
        found = warnings(["ls", entry], windows=False)
        assert len(found) == 1 and "'ps'" in found[0] and "environment" in found[0]
    assert warnings(["PS.EXE"], windows=False) == []  # POSIX program names are exact
    assert len(warnings(["PS.EXE"], windows=True)) == 1  # Windows names ignore case and .exe
    assert warnings(["ps"], windows=False, mode="unrestricted") == []


@pytest.mark.parametrize("name", ["computer.yaml", "agent.yaml", "agent.windows.yaml"])
def test_example_configs_allow_nothing_that_prints_environments(name):
    cfg = yaml.safe_load((REPO / "configs" / name).read_text(encoding="utf-8"))
    assert "ps" not in cfg["commands"]["allow"]
    assert load_policy(cfg).allowlist_warnings() == []
