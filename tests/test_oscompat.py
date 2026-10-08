"""Windows rules, tested on every platform through the explicit ``windows`` flag."""

from __future__ import annotations

import base64
import os
import random
import stat
import subprocess
from dataclasses import replace

import pytest

from contextbridge.computer.oscompat import (
    decode_output,
    program_name,
    resolve_program,
    shell_invocation,
    split_windows_command,
    windows_path_problem,
)
from contextbridge.computer.policy import WINDOWS_DEFAULT_DENY, PolicyError, PolicyViolation, load_policy

# ---------------------------------------------------------------- splitting


def test_windows_splitting_inverts_list2cmdline():
    rng = random.Random(4)
    alphabet = 'ab \t"\\\'x|&^%!:'
    for _ in range(5000):
        args = ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8))) for _ in range(rng.randint(1, 5))]
        assert split_windows_command(subprocess.list2cmdline(args)) == args


@pytest.mark.parametrize(
    "line, argv",
    [
        (r'git -C "C:\Program Files\repo" status', ["git", "-C", r"C:\Program Files\repo", "status"]),
        ("dir C:\\Users\\me\\", ["dir", "C:\\Users\\me\\"]),
        (r'python -c "print(\"hi\")"', ["python", "-c", 'print("hi")']),
        ('echo ""', ["echo", ""]),
        ('a "b ""c"" d"', ["a", 'b "c" d']),
    ],
)
def test_windows_splitting_examples(line, argv):
    assert split_windows_command(line) == argv


def test_windows_splitting_rejects_unterminated_quotes():
    with pytest.raises(ValueError):
        split_windows_command('git log "--format=%h')


# ----------------------------------------------------------- path problems


@pytest.mark.parametrize(
    "raw, problem",
    [
        (r"C:\Users\me\.env::$DATA", "alternate data streams"),
        (r"docs\notes.md:hidden", "alternate data streams"),
        (r"docs\CON", "reserved"),
        (r"docs\nul.txt", "reserved"),
        (r"docs\COM1", "reserved"),
        (".env.", "ending in a dot or space"),
        (".env ", "ending in a dot or space"),
        (r"\\?\C:\Windows", "device-namespace"),
        (r"\\.\PhysicalDrive0", "device-namespace"),
        ("C:secret.txt", "drive-relative"),
        ("docs/a*b", "characters"),
    ],
)
def test_windows_path_problems(raw, problem):
    assert problem in windows_path_problem(raw)


@pytest.mark.parametrize("raw", [r"C:\Users\me\docs\notes.md", "docs/notes.md", r"..\x", r"\\server\share\f.txt", "~"])
def test_ordinary_windows_paths_are_fine(raw):
    assert windows_path_problem(raw) is None


def test_policy_applies_windows_name_rules(workspace):
    policy = replace(load_policy({"filesystem": {"roots": [str(workspace)]}}), windows=True)
    for raw in ("docs/notes.md:secret", ".env.", "docs/CON", "docs/notes.md::$DATA"):
        with pytest.raises(PolicyViolation):
            policy.resolve(raw)
    assert policy.resolve("docs/notes.md") == workspace / "docs" / "notes.md"


def test_windows_default_deny_list(workspace):
    windows = load_policy({"filesystem": {"roots": [str(workspace)]}}, windows=True)
    posix = load_policy({"filesystem": {"roots": [str(workspace)]}}, windows=False)
    assert set(WINDOWS_DEFAULT_DENY) <= set(windows.deny)
    assert not set(WINDOWS_DEFAULT_DENY) & set(posix.deny)


# --------------------------------------------------------- program lookup


def _touch(path, executable=True):
    path.write_text("", encoding="utf-8")
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_windows_lookup_takes_only_exe_and_com(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = _touch(bin_dir / "tool.exe")
    _touch(bin_dir / "script.bat")
    _touch(bin_dir / "script.cmd")
    path = f"relative;{bin_dir}"
    assert resolve_program("tool", path=path, windows=True) == str(exe)
    assert resolve_program("tool.exe", path=path, windows=True) == str(exe)
    assert resolve_program("script", path=path, windows=True) is None
    assert resolve_program("script.bat", path=path, windows=True) is None


def test_lookup_never_uses_relative_path_entries(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _touch(tmp_path / "tool")
    _touch(tmp_path / "tool.exe")
    assert resolve_program("tool", path=os.pathsep.join([".", ""]), windows=False) is None
    assert resolve_program("tool", path=".;", windows=True) is None


def test_program_names_compare_like_windows():
    assert program_name("Git.EXE", windows=True) == "git"
    assert program_name("git.exe", windows=False) == "git.exe"


def test_windows_allowlist(workspace, tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    git = _touch(bin_dir / "git.exe")
    _touch(bin_dir / "deploy.cmd")
    monkeypatch.setenv("PATH", str(bin_dir))
    policy = load_policy(
        {
            "filesystem": {"roots": [str(workspace)]},
            "commands": {"mode": "allowlist", "allow": ["git", "deploy", r"C:\Tools\tool.exe", r"C:\Tools\run.bat"]},
        },
        windows=True,
    )
    assert policy.command_argv('git log --format="%h|%s"') == [str(git), "log", "--format=%h|%s"]
    assert policy.command_argv("git.exe status")[0] == str(git)
    assert policy.command_argv(r"C:\Tools\tool.exe --version") == [r"C:\Tools\tool.exe", "--version"]
    with pytest.raises(PolicyViolation, match=r"\.exe or \.com"):
        policy.command_argv("deploy now")
    with pytest.raises(PolicyViolation, match=r"\.exe or \.com"):
        policy.command_argv(r"C:\Tools\run.bat")
    for line in ("git log | more", "git status & del x", "git log > out.txt", "git log 2>&1"):
        with pytest.raises(PolicyViolation, match="Shell operators"):
            policy.command_argv(line)
    with pytest.raises(PolicyViolation, match="allowlist"):
        policy.command_argv(r".\git.exe status")


# ------------------------------------------------------------------ shells


def test_powershell_preset_uses_an_encoded_command():
    argv = shell_invocation("powershell", "Get-Date; exit 3", windows=True)
    assert argv[:5] == ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"]
    script = base64.b64decode(argv[-1]).decode("utf-16-le")
    assert script.endswith("Get-Date; exit 3") and "OutputEncoding" in script
    assert shell_invocation("pwsh", "x", windows=True)[0] == "pwsh.exe"


def test_cmd_preset_passes_the_line_verbatim():
    assert shell_invocation("cmd", 'echo "a b" & ver', windows=True) == 'cmd.exe /d /s /c "echo "a b" & ver"'


def test_default_shells_and_custom_argv():
    assert shell_invocation(None, "x", windows=True)[0] == "powershell.exe"
    assert shell_invocation(None, "x", windows=False)[-2:] == ["-c", "x"]
    assert shell_invocation(("zsh", "-c"), "x", windows=False) == ["zsh", "-c", "x"]
    with pytest.raises(ValueError):
        shell_invocation("fish", "x", windows=False)


def test_shell_config_validation(workspace):
    base = {"filesystem": {"roots": [str(workspace)]}}
    assert load_policy({**base, "commands": {"mode": "unrestricted", "shell": "cmd"}}).shell == "cmd"
    assert load_policy({**base, "commands": {"mode": "unrestricted", "shell": ["zsh", "-c"]}}).shell == ("zsh", "-c")
    with pytest.raises(PolicyError, match="commands.shell"):
        load_policy({**base, "commands": {"mode": "unrestricted", "shell": "fish"}})


# ------------------------------------------------------------------ output


def test_output_decoding():
    assert decode_output("héllo".encode()) == "héllo"
    cp850 = "Größe: ÄÖÜ".encode("cp850")
    assert "\ufffd" in decode_output(cp850, windows=False)
    assert decode_output(b"ok \xff", windows=True).startswith("ok")  # a stray byte stays UTF-8 with a marker
