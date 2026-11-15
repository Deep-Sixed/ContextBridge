"""Regression tests for failure scenarios publicly reported against file and process servers.

Each test names the weakness class (CWE) it guards against, the failure seen elsewhere,
and what ContextBridge must do instead. Tests marked xfail record a defect found while
writing them: they describe the intended behaviour, fail today, and are strict, so they
start failing loudly once the defect is fixed and the mark should go.
"""

from __future__ import annotations

import os
import time
from dataclasses import replace
from pathlib import Path

import psutil
import pytest
from helpers import python_cmd, symlink_or_skip

from contextbridge.computer import files
from contextbridge.computer.commands import SessionManager, run_command
from contextbridge.computer.oscompat import windows_path_problem
from contextbridge.computer.policy import PolicyViolation, load_policy
from contextbridge.filesystem.fs import Filesystem, FsError, FsLimits, FsRoot

IS_WINDOWS = os.name == "nt"
posix_only = pytest.mark.skipif(IS_WINDOWS, reason="POSIX behaviour")
windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="Windows behaviour")


@pytest.fixture
def fs_dirs(tmp_path: Path) -> dict[str, Path]:
    """A writable root, its sibling sharing the root's name as a prefix, and an outside folder."""
    paths = {name: tmp_path / "prefix" / name for name in ("root", "root_evil", "outside")}
    for path in paths.values():
        path.mkdir(parents=True)
    (paths["root_evil"] / "secret.txt").write_text("secret\n", encoding="utf-8")
    return {name: Path(os.path.realpath(path)) for name, path in paths.items()}


def _alive(pid: int) -> bool:
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def _kill(pid: int) -> None:
    try:
        psutil.Process(pid).kill()
    except psutil.NoSuchProcess:
        pass


def _spawner(pid_file: Path, *, then: str) -> str:
    """Python code that starts a 60-second child, records its PID, prints, then runs ``then``."""
    child = "import time; time.sleep(60)"
    return (
        "import subprocess, sys, time\n"
        f"child = subprocess.Popen([sys.executable, '-c', {child!r}])\n"
        f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
        "print('started', flush=True)\n"
        f"{then}\n"
    )


def _wait_for_pid(pid_file: Path) -> int:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if pid_file.exists() and pid_file.read_text().strip():
            return int(pid_file.read_text())
        time.sleep(0.05)
    raise AssertionError("the child never recorded its PID")


# ------------------------------------------------------------------ path containment


def test_sibling_sharing_a_roots_name_prefix_is_outside_it(fs_dirs):
    """CWE-22. A containment check that compares path strings accepts /data/root_evil as
    inside /data/root, because one string starts with the other. Both routes must compare
    whole path components: the sibling is outside, for reads and writes."""
    policy = load_policy({"filesystem": {"roots": [str(fs_dirs["root"])], "writable_roots": [str(fs_dirs["root"])]}})
    secret = str(fs_dirs["root_evil"] / "secret.txt")
    with pytest.raises(PolicyViolation):
        files.read_file(policy, secret)
    with pytest.raises(PolicyViolation):
        files.write_file(policy, str(fs_dirs["root_evil"] / "new.txt"), "x")

    fs = Filesystem([FsRoot(fs_dirs["root"], writable=True)])
    with pytest.raises(FsError):
        fs.read_file(secret)
    with pytest.raises(FsError):
        fs.write_file(str(fs_dirs["root_evil"] / "new.txt"), "x")
    assert not (fs_dirs["root_evil"] / "new.txt").exists()


@pytest.mark.parametrize("mode", ["rewrite", "append"])
def test_a_dangling_link_cannot_create_a_file_outside_the_roots(fs_dirs, mode):
    """CWE-59. A link inside a root that points at a file that doesn't exist yet passes a
    check that only resolves existing paths, and writing through it creates the file
    outside. Both routes must resolve the link's target and refuse, creating nothing."""
    target = fs_dirs["outside"] / "created.txt"
    link = symlink_or_skip(fs_dirs["root"] / "dangling.txt", target)
    policy = load_policy({"filesystem": {"roots": [str(fs_dirs["root"])], "writable_roots": [str(fs_dirs["root"])]}})
    with pytest.raises(PolicyViolation):
        files.write_file(policy, str(link), "x\n", mode=mode)
    fs = Filesystem([FsRoot(fs_dirs["root"], writable=True)])
    with pytest.raises(FsError):
        fs.write_file(str(link), "x\n", mode=mode)
    assert not target.exists()


def test_link_loops_do_not_hang_listing_or_search(make_policy, workspace):
    """CWE-835. A directory walk that follows links loops forever on a link to an ancestor,
    or on two links pointing at each other. Listing and searching must finish, on both
    routes, and reading a looped link must fail cleanly."""
    work = workspace / "work"
    symlink_or_skip(work / "up", work)
    symlink_or_skip(work / "a", work / "b")
    symlink_or_skip(work / "b", work / "a")
    (work / "note.txt").write_text("needle\n", encoding="utf-8")
    policy = make_policy()
    started = time.monotonic()
    assert files.list_directory(policy, "work", depth=5)["entries"]
    assert files.search_files(policy, "work", "*.txt")["matches"]
    assert files.search_code(policy, "work", "needle")["matches"]
    with pytest.raises((FileNotFoundError, files.FileOperationError, PolicyViolation)):
        files.read_file(policy, "work/a")
    fs = Filesystem([FsRoot(Path(os.path.realpath(work)), writable=True)])
    assert fs.list_directory(str(Path(os.path.realpath(work))), depth=10)["entries"]
    assert time.monotonic() - started < 20


# ------------------------------------------------------------------ data integrity


def test_editing_through_a_link_inside_the_roots_keeps_the_link(make_policy, workspace):
    """Data integrity. An atomic rewrite that renames a temporary file over the path it was
    given replaces a link with a regular file, silently splitting it from its target.
    Writes and edits through a link inside the roots must change the target and leave
    the link in place, on both routes."""
    work = workspace / "work"
    real = work / "real.txt"
    real.write_text("a = 1\n", encoding="utf-8")
    alias = symlink_or_skip(work / "alias.txt", real)
    files.edit_block(make_policy(), "work/alias.txt", "a = 1", "a = 2")
    assert alias.is_symlink() and real.read_text(encoding="utf-8") == "a = 2\n"
    fs = Filesystem([FsRoot(Path(os.path.realpath(work)), writable=True)])
    fs.write_file(str(alias), "b = 3\n")
    assert alias.is_symlink() and real.read_text(encoding="utf-8") == "b = 3\n"


def test_a_refused_write_leaves_the_file_as_it_was(make_policy, workspace):
    """Data integrity. A write that truncates the file before checking the new content's
    size leaves it empty when the write is then refused. A rewrite over the size limit must
    be refused before anything changes, on both routes."""
    target = workspace / "work" / "keep.txt"
    target.write_text("original\n", encoding="utf-8")
    with pytest.raises(files.FileOperationError, match="limit"):
        files.write_file(make_policy(filesystem={"max_write_bytes": 16}), "work/keep.txt", "x" * 100)
    assert target.read_text(encoding="utf-8") == "original\n"

    fs = Filesystem([FsRoot(Path(os.path.realpath(workspace / "work")), writable=True)], FsLimits(max_write_bytes=16))
    with pytest.raises(FsError):
        fs.write_file(str(target), "x" * 100)
    assert target.read_text(encoding="utf-8") == "original\n"


# ------------------------------------------------------------------ command execution


@posix_only  # Windows quoting rules are covered in test_oscompat.py
@pytest.mark.parametrize(
    ("command", "printed"),
    [("echo `id`", "`id`"), ("echo 'a\nid'", "a\nid"), ("echo $HOME", "$HOME")],
    ids=["backticks", "newline", "variable"],
)
def test_allowlist_mode_never_lets_a_shell_interpret_the_command(policy, command, printed):
    """CWE-78. Servers that pass a command string to a shell run whatever substitution or
    second line it contains. In allowlist mode no shell runs: backticks, a newline and a
    variable reach the program as literal text."""
    assert run_command(policy, command)["stdout"] == printed + "\n"


def test_commands_get_an_empty_stdin_instead_of_hanging(policy):
    """Resource exhaustion. A command that reads its input blocks forever when the server
    leaves stdin open with nothing behind it. run_command must give it an empty input."""
    started = time.monotonic()
    result = run_command(policy, python_cmd("import sys; print(len(sys.stdin.read()))"), timeout_seconds=30)
    assert result["stdout"].strip() == "0" and result["timed_out"] is False
    assert time.monotonic() - started < 15


def test_binary_output_is_returned_without_failing(policy):
    """Robustness. A server that decodes output strictly fails, or crashes, on output that
    isn't valid text. Every byte value must come back, decoded leniently, from both
    run_command and a session."""
    code = "import sys; sys.stdout.buffer.write(bytes(range(256))); sys.stdout.flush()"
    assert run_command(policy, python_cmd(code))["exit_code"] == 0
    sessions = SessionManager(policy)
    started = sessions.start(python_cmd(code), wait_seconds=10)
    try:
        output = started["output"]
        deadline = time.monotonic() + 10
        while len(output) < 200 and time.monotonic() < deadline:
            output += sessions.read(started["session_id"], wait_seconds=1)["output"]
        assert len(output) >= 200
    finally:
        sessions.terminate(started["session_id"])


def test_session_output_without_newlines_stays_bounded(policy):
    """CWE-400. A server that keeps a session's output, or its last unfinished line, whole
    runs out of memory when a program writes megabytes without a newline. The session must
    keep a bounded buffer and keep answering."""
    code = "import sys, time\nfor _ in range(400): sys.stdout.write('x' * 65536)\nsys.stdout.flush()\ntime.sleep(30)"
    sessions = SessionManager(policy)
    started = sessions.start(python_cmd(code), wait_seconds=10)
    sid = started["session_id"]
    try:
        session = sessions._sessions[sid]
        deadline = time.monotonic() + 30
        while session.end < 400 * 65536 and time.monotonic() < deadline:
            time.sleep(0.1)
        assert session.end >= 400 * 65536, "the program did not finish writing"
        assert len(session.buffer) <= session.cap
        before = time.monotonic()
        result = sessions.read(sid)
        assert time.monotonic() - before < 5 and result["waiting_for_input"] is False
    finally:
        sessions.terminate(sid)


def test_force_terminate_ends_the_programs_children(policy, workspace):
    """CWE-404. Killing only the process a server started leaves whatever it launched
    running: the commonest source of orphaned processes. force_terminate must end the
    whole tree."""
    pid_file = workspace / "work" / "child.pid"
    sessions = SessionManager(policy)
    started = sessions.start(python_cmd(_spawner(pid_file, then="time.sleep(60)")), wait_seconds=10)
    child = _wait_for_pid(pid_file)
    try:
        assert _alive(child)
        sessions.terminate(started["session_id"])
        deadline = time.monotonic() + 10
        while _alive(child) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not _alive(child)
    finally:
        _kill(child)


@pytest.mark.xfail(
    not IS_WINDOWS,
    strict=True,
    reason="Finding F-2: on POSIX a finished command's background children keep running, "
    "and run_command waits its 5 s drain timeout for the pipe they hold.",
)
def test_a_finished_command_leaves_nothing_running(policy, workspace):
    """CWE-404. A command that starts a background program and exits leaves an orphan that
    holds the output pipe: servers either hang on the pipe or return and leak the process.
    Windows ends everything a command started when it finishes (its job is closed); the
    same must hold everywhere, and run_command must return promptly."""
    pid_file = workspace / "work" / "child.pid"
    started = time.monotonic()
    result = run_command(policy, python_cmd(_spawner(pid_file, then="")), timeout_seconds=30)
    elapsed = time.monotonic() - started
    child = _wait_for_pid(pid_file)
    try:
        assert result["exit_code"] == 0 and "started" in result["stdout"]
        assert elapsed < 4, f"run_command took {elapsed:.1f} s"
        assert not _alive(child), "the command's child outlived it"
    finally:
        _kill(child)


# ------------------------------------------------------------------ Windows names


@pytest.mark.xfail(
    strict=True,
    reason="Finding F-1: COM¹-COM³ and LPT¹-LPT³ (superscript digits) are not refused.",
)
@pytest.mark.parametrize("name", ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³", "com¹.txt"])
def test_superscript_device_names_are_refused(workspace, name):
    """CWE-67. Windows treats COM and LPT followed by the superscript digits ¹ ² ³ as
    device names, like COM1. Sandboxes that refused only the ASCII forms let a path such as
    docs/COM¹ open a device. These names must be refused like COM1."""
    assert windows_path_problem(rf"docs\{name}") is not None
    policy = replace(load_policy({"filesystem": {"roots": [str(workspace)]}}), windows=True)
    with pytest.raises(PolicyViolation):
        policy.resolve(f"docs/{name}")


@windows_only
@pytest.mark.parametrize("mode", ["rewrite", "append"])
def test_filesystem_route_never_opens_a_device_as_a_file(tmp_path, mode):
    """CWE-67. On Windows a path ending in NUL names the null device in every folder, so a
    server that opens it reads nothing and silently discards writes, reporting success.
    The filesystem route must refuse it as not a regular file."""
    root = Path(os.path.realpath(tmp_path))
    fs = Filesystem([FsRoot(root, writable=True)])
    with pytest.raises(FsError):
        fs.read_file(str(root / "NUL"))
    with pytest.raises(FsError):
        fs.write_file(str(root / "NUL"), "x\n", mode=mode)
