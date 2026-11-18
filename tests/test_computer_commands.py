from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

import psutil
import pytest
from helpers import PY, UNLISTED_PY, python_cmd

from contextbridge.computer import commands
from contextbridge.computer.commands import BoundedCapture, CommandError, SessionManager
from contextbridge.computer.policy import PolicyViolation

posix_only = pytest.mark.skipif(os.name == "nt", reason="uses POSIX shell utilities")


@posix_only
def test_run_command_success(policy, workspace):
    result = commands.run_command(policy, "ls docs", cwd=str(workspace))
    assert result["exit_code"] == 0
    assert "notes.md" in result["stdout"]
    assert result["timed_out"] is False


@posix_only
def test_run_command_defaults_to_first_root(policy, workspace):
    result = commands.run_command(policy, "ls")
    assert result["cwd"] == str(workspace)


@posix_only
def test_run_command_reports_nonzero_exit(policy):
    result = commands.run_command(policy, "ls does-not-exist")
    assert result["exit_code"] != 0
    assert result["stderr"]


@posix_only
def test_run_command_cwd_must_be_inside_roots(policy, workspace):
    with pytest.raises(PolicyViolation):
        commands.run_command(policy, "ls", cwd=str(workspace.parent))


@posix_only
def test_run_command_timeout_kills_process_tree(make_policy):
    policy = make_policy(commands={"mode": "unrestricted"})
    started = time.monotonic()
    result = commands.run_command(policy, "sleep 30 & sleep 30; wait", timeout_seconds=1)
    assert result["timed_out"] is True
    assert time.monotonic() - started < 10
    leftovers = [p for p in psutil.process_iter(["cmdline"]) if p.info["cmdline"] == ["sleep", "30"]]
    assert leftovers == []


@posix_only
def test_run_command_truncates_output(make_policy):
    policy = make_policy(commands={"mode": "unrestricted", "max_output_bytes": 1000})
    result = commands.run_command(policy, f"{sys.executable} -c \"print('x' * 100000)\"")
    assert result["stdout_truncated"] is True
    assert "bytes omitted" in result["stdout"]
    assert len(result["stdout"]) < 1200


@posix_only
def test_run_command_does_not_leak_gateway_tokens(policy, monkeypatch):
    monkeypatch.setenv("MCP_AUTH_TOKEN", "super-secret-value")
    result = commands.run_command(policy, "env")
    assert "super-secret-value" not in result["stdout"]


def test_bounded_capture_keeps_head_and_tail():
    capture = BoundedCapture(8)
    capture.feed(b"ab")
    capture.feed(b"cdefghijkl")
    assert capture.total == 12
    assert capture.truncated
    text = capture.text()
    assert text.startswith("ab")
    assert text.endswith("ghijkl")


@posix_only
def test_session_lifecycle(make_policy, workspace):
    policy = make_policy(commands={"mode": "unrestricted"})
    sessions = SessionManager(policy)
    started = sessions.start("cat", cwd=str(workspace), wait_seconds=0.1)
    sid = started["session_id"]
    assert started["running"] is True
    reply = sessions.send(sid, "ping", wait_seconds=2)
    assert "ping" in reply["output"]
    assert sessions.read(sid)["output"] == ""
    assert [s["session_id"] for s in sessions.list()] == [sid]
    final = sessions.terminate(sid)
    assert final["running"] is False
    with pytest.raises(CommandError, match="no longer running"):
        sessions.send(sid, "again")
    with pytest.raises(CommandError, match="Unknown session"):
        sessions.read("nope")


@posix_only
def test_session_limit_and_lifetime(make_policy):
    policy = make_policy(commands={"mode": "unrestricted", "max_sessions": 1})
    sessions = SessionManager(policy)
    first = sessions.start("sleep 30", timeout_seconds=1, wait_seconds=0)
    with pytest.raises(PolicyViolation, match="limit 1"):
        sessions.start("sleep 30", wait_seconds=0)
    result = sessions.read(first["session_id"], wait_seconds=5)
    assert result["running"] is False
    assert result["timed_out"] is True
    sessions.shutdown()


def _watchdogs() -> list[threading.Timer]:
    return [t for t in threading.enumerate() if isinstance(t, threading.Timer)]


def test_finished_session_leaves_no_watchdog_thread(make_policy):
    # Each session gets a lifetime timer. One that outlives its process holds a thread and the
    # session's output buffer for up to max_session_seconds, so many short sessions pile up.
    policy = make_policy(commands={"mode": "allowlist", "allow": [PY]})
    sessions = SessionManager(policy)
    before = set(_watchdogs())
    for _ in range(5):
        sid = sessions.start(python_cmd("print('done')"), wait_seconds=0)["session_id"]
        deadline = time.monotonic() + 10
        while sessions.read(sid)["running"] and time.monotonic() < deadline:
            time.sleep(0.05)
        final = sessions.read(sid)
        assert final["running"] is False and final["timed_out"] is False
    deadline = time.monotonic() + 5
    while set(_watchdogs()) - before and time.monotonic() < deadline:
        time.sleep(0.05)
    assert set(_watchdogs()) - before == set()


@posix_only
def test_session_rejects_unlisted_program(policy):
    with pytest.raises(PolicyViolation, match="allowlist"):
        SessionManager(policy).start(UNLISTED_PY)


def test_list_processes_includes_self():
    result = commands.list_processes(name_filter="python")
    assert any(row["pid"] == os.getpid() for row in result["processes"])


def test_kill_process_refuses_protected_pids():
    for pid in (1, os.getpid(), os.getppid()):
        with pytest.raises(PolicyViolation, match="protected"):
            commands.kill_process(pid)


@pytest.mark.parametrize("pid", [-1, -4242])
def test_kill_process_refuses_negative_pids(pid):
    # On POSIX a negative pid addresses a whole process group (-1: every process the user may signal).
    with pytest.raises(CommandError, match="No such process"):
        commands.kill_process(pid)


@posix_only
def test_kill_process_terminates_child():
    import subprocess

    proc = subprocess.Popen(["sleep", "30"])
    try:
        result = commands.kill_process(proc.pid)
        assert result["exited"] is True
    finally:
        proc.kill()
        proc.wait()


# ------------------------------------------------- cross-platform (Linux + Windows)
# These use this Python interpreter as the command, so they run identically on Thanatos.

_SPAWN_GRANDCHILD = (
    "import subprocess, sys, time; "
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
    "print(p.pid, flush=True); time.sleep(120)"
)


def _wait_gone(pid: int, timeout: float = 10.0) -> bool:
    try:
        psutil.Process(pid).wait(timeout=timeout)
    except psutil.NoSuchProcess:
        return True
    except psutil.TimeoutExpired:
        return False
    return True


def test_python_command_runs_with_exit_code(policy):
    ok = commands.run_command(policy, python_cmd("print('hi')"))
    assert ok["exit_code"] == 0 and ok["stdout"].strip() == "hi" and ok["pid"] > 0
    failed = commands.run_command(policy, python_cmd("import sys; sys.exit(3)"))
    assert failed["exit_code"] == 3 and failed["timed_out"] is False


def test_timeout_kills_grandchildren_on_every_platform(make_policy):
    policy = make_policy(commands={"max_timeout_seconds": 3})
    started = time.monotonic()
    result = commands.run_command(policy, python_cmd(_SPAWN_GRANDCHILD), timeout_seconds=3)
    assert result["timed_out"] is True
    assert time.monotonic() - started < 15
    grandchild = int(result["stdout"].split()[0])
    assert _wait_gone(grandchild), "the grandchild survived the timeout"


def test_output_is_bounded_on_every_platform(make_policy):
    policy = make_policy(commands={"max_output_bytes": 1000})
    result = commands.run_command(policy, python_cmd("import sys; sys.stdout.write('x' * 200000)"))
    assert result["stdout_truncated"] is True and "bytes omitted" in result["stdout"]
    assert len(result["stdout"]) < 1200


def test_gateway_tokens_never_reach_commands(policy, monkeypatch):
    monkeypatch.setenv("MCP_AUTH_TOKEN", "super-secret-value")
    monkeypatch.setenv("CONTEXTBRIDGE_COMPUTER_TOKEN", "other-secret-value")
    result = commands.run_command(policy, python_cmd("import os; print(sorted(os.environ))"))
    assert "MCP_AUTH_TOKEN" not in result["stdout"] and "CONTEXTBRIDGE_COMPUTER_TOKEN" not in result["stdout"]


def test_interactive_session_on_every_platform(policy):
    sessions = SessionManager(policy)
    echo_loop = "import sys\nfor line in sys.stdin:\n    print('got ' + line.strip(), flush=True)"
    started = sessions.start(python_cmd(echo_loop), wait_seconds=0.2)
    sid = started["session_id"]
    try:
        reply = sessions.send(sid, "ping", wait_seconds=5)
        for _ in range(20):
            if "got ping" in reply["output"]:
                break
            reply = sessions.read(sid, wait_seconds=0.5)
        assert "got ping" in reply["output"]
    finally:
        final = sessions.terminate(sid)
    assert final["running"] is False


def _python_repl(sessions: SessionManager) -> dict:
    return sessions.start(f"{PY} -i -q -u", wait_seconds=20)


def _read_until(sessions: SessionManager, sid: str, done, first: dict) -> dict:
    """Keep reading a slow machine's output until ``done`` holds for all of it, for up to 20 s."""
    result, output = first, first["output"]
    deadline = time.monotonic() + 20
    while not done({**result, "output": output}) and time.monotonic() < deadline:
        result = sessions.read(sid, wait_seconds=1)
        output += result["output"]
    return {**result, "output": output}


def test_a_waiting_repl_answers_at_its_prompt(policy):
    sessions = SessionManager(policy)
    started = _python_repl(sessions)
    sid = started["session_id"]
    try:
        assert started["waiting_for_input"] is True and started["prompt"] == ">>> "
        before = time.monotonic()
        reply = sessions.send(sid, "6 * 7", wait_seconds=20)
        # Back as soon as the prompt shows, far inside the 20 seconds allowed.
        assert time.monotonic() - before < 10
        reply = _read_until(sessions, sid, lambda r: r["waiting_for_input"], reply)
        assert "42" in reply["output"] and reply["prompt"] == ">>> "
        assert [s["waiting_for_input"] for s in sessions.list()] == [True]
    finally:
        sessions.terminate(sid)


def test_the_prompt_input_answered_does_not_count(policy):
    sessions = SessionManager(policy)
    sid = _python_repl(sessions)["session_id"]
    try:
        busy = sessions.send(sid, "import time; time.sleep(3); print('late')", wait_seconds=0.5)
        assert busy["waiting_for_input"] is False and busy["prompt"] is None
        done = _read_until(sessions, sid, lambda r: "late" in r["output"] and r["waiting_for_input"], busy)
        assert done["waiting_for_input"] is True
    finally:
        sessions.terminate(sid)


def test_several_input_lines_return_after_the_last(policy):
    sessions = SessionManager(policy)
    sid = _python_repl(sessions)["session_id"]
    try:
        reply = sessions.send(sid, "for i in range(3):\n    print('row', i)\n", wait_seconds=20)
        reply = _read_until(sessions, sid, lambda r: "row 2" in r["output"] and r["waiting_for_input"], reply)
        assert "row 0" in reply["output"] and reply["prompt"] == ">>> "
    finally:
        sessions.terminate(sid)


def test_a_question_counts_once_output_settles(policy):
    sessions = SessionManager(policy)
    sid = _python_repl(sessions)["session_id"]
    try:
        reply = sessions.send(sid, "answer = input('Your name: ')", wait_seconds=20)
        reply = _read_until(sessions, sid, lambda r: r["waiting_for_input"], reply)
        assert reply["prompt"] == ">>> Your name: "
        answered = sessions.send(sid, "Ada", wait_seconds=20)
        answered = _read_until(sessions, sid, lambda r: r["prompt"] == ">>> ", answered)
        assert answered["waiting_for_input"] is True
    finally:
        sessions.terminate(sid)


def test_unfinished_output_from_a_busy_program_is_not_a_prompt(policy):
    sessions = SessionManager(policy)
    code = "import sys, time\nsys.stdout.write('collecting ... ')\nsys.stdout.flush()\ntime.sleep(30)"
    before = time.monotonic()
    started = sessions.start(python_cmd(code), wait_seconds=20)
    try:
        started = _read_until(sessions, started["session_id"], lambda r: "collecting" in r["output"], started)
        assert started["waiting_for_input"] is False and started["prompt"] is None
        # It came back once the output settled, not after the 20 seconds allowed.
        assert time.monotonic() - before < 15
    finally:
        sessions.terminate(started["session_id"])


def test_a_finished_program_is_never_waiting(policy):
    sessions = SessionManager(policy)
    sid = sessions.start(python_cmd("print('>>> ', end='')"), wait_seconds=5)["session_id"]
    deadline = time.monotonic() + 10
    while sessions.read(sid)["running"] and time.monotonic() < deadline:
        time.sleep(0.05)
    final = sessions.read(sid)
    assert final["running"] is False and final["waiting_for_input"] is False


def test_session_lifetime_kills_grandchildren(policy):
    sessions = SessionManager(policy)
    started = sessions.start(python_cmd(_SPAWN_GRANDCHILD), timeout_seconds=2, wait_seconds=5)
    output = started["output"] or sessions.read(started["session_id"], wait_seconds=5)["output"]
    grandchild = int(output.split()[0])
    result = sessions.read(started["session_id"], wait_seconds=10)
    assert result["running"] is False and result["timed_out"] is True
    assert _wait_gone(grandchild), "the grandchild survived the session lifetime"


_LEAVE_GRANDCHILD = (
    "import subprocess, sys; "
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
    "print(p.pid, flush=True)"
)


def test_a_finished_command_leaves_no_background_program(policy):
    """A program started in the background ends with the command, and can't hold up its result."""
    started = time.monotonic()
    result = commands.run_command(policy, python_cmd(_LEAVE_GRANDCHILD), timeout_seconds=30)
    elapsed = time.monotonic() - started
    grandchild = int(result["stdout"].split()[0])
    try:
        assert result["exit_code"] == 0 and result["timed_out"] is False
        # Its open output pipe used to make run_command wait out the 5 s drain timeout.
        assert elapsed < 4, f"run_command took {elapsed:.1f} s"
        assert _wait_gone(grandchild), "the background program outlived the command"
    finally:
        try:
            psutil.Process(grandchild).kill()
        except psutil.NoSuchProcess:
            pass


def test_a_finished_session_leaves_no_background_program(policy):
    sessions = SessionManager(policy)
    started = sessions.start(python_cmd(_LEAVE_GRANDCHILD), wait_seconds=10)
    output = started["output"] or sessions.read(started["session_id"], wait_seconds=10)["output"]
    grandchild = int(output.split()[0])
    try:
        deadline = time.monotonic() + 10
        while sessions.read(started["session_id"])["running"] and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _wait_gone(grandchild), "the background program outlived the session"
    finally:
        try:
            psutil.Process(grandchild).kill()
        except psutil.NoSuchProcess:
            pass


def test_allowlist_names_this_interpreter(policy):
    assert PY in policy.command_allow


def test_list_processes_hides_arguments_unless_the_policy_allows_them():
    # A secret passed as an argument (an enrollment code, a token) must not be readable, or probeable through
    # the name filter, by a client that only has read access.
    secret = "cb-secret-" + os.urandom(6).hex()
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", secret])
    try:
        hidden = commands.list_processes(limit=1000)
        mine = next(p for p in hidden["processes"] if p["pid"] == child.pid)
        assert secret not in mine["cmdline"] and mine["cmdline"]  # the program is still shown
        assert "note" in hidden
        assert commands.list_processes(name_filter=secret)["matched"] == 0
        shown = commands.list_processes(name_filter=secret, command_lines=True)
        assert [p["pid"] for p in shown["processes"]] == [child.pid]
        assert secret in shown["processes"][0]["cmdline"]
    finally:
        child.kill()
        child.wait()


def test_process_command_lines_are_off_by_default_and_opt_in(make_policy):
    assert make_policy().process_command_lines is False
    assert make_policy(processes={"list": True, "command_lines": True}).process_command_lines is True


def test_input_to_a_program_that_never_reads_it_times_out_instead_of_blocking(policy, monkeypatch):
    # More input than a pipe holds, to a program that never reads stdin: the write would otherwise hold
    # this worker thread until the session's lifetime ran out.
    monkeypatch.setattr(commands, "_INPUT_WRITE_SECONDS", 1.0)
    sessions = SessionManager(policy)
    sid = sessions.start(python_cmd("import time; time.sleep(30)"), wait_seconds=0)["session_id"]
    try:
        started = time.monotonic()
        with pytest.raises(CommandError, match="not reading its input"):
            sessions.send(sid, "x" * (512 * 1024), newline=False)
        assert time.monotonic() - started < 10
        with pytest.raises(CommandError, match="has not read the input sent earlier"):
            sessions.send(sid, "more")
    finally:
        sessions.shutdown()


def test_input_larger_than_the_write_limit_is_refused(make_policy):
    policy = make_policy(filesystem={"max_write_bytes": 1024})
    sessions = SessionManager(policy)
    sid = sessions.start(python_cmd("import sys; sys.stdin.read()"), wait_seconds=0)["session_id"]
    try:
        with pytest.raises(CommandError, match="at most 1024"):
            sessions.send(sid, "y" * 2048)
    finally:
        sessions.shutdown()


def test_a_finished_session_closes_its_input_pipe(policy):
    sessions = SessionManager(policy)
    sid = sessions.start(python_cmd("print('bye')"), wait_seconds=0)["session_id"]
    try:
        session = sessions._get(sid)
        session.proc.wait(timeout=10)
        deadline = time.monotonic() + 5
        while not session.proc.stdin.closed and time.monotonic() < deadline:
            time.sleep(0.05)
        assert session.proc.stdin.closed
    finally:
        sessions.shutdown()
