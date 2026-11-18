"""Command execution, background sessions, and process inspection.

Commands run without an intermediate shell in allowlist mode, with credentials
stripped from the environment, inside a readable root, under a hard timeout,
and with bounded output capture. Timed-out commands are killed with their whole
process tree (see :mod:`.proctree`). When a command or session ends, so does
whatever it left running in the background: on Windows everything it started, on
POSIX everything that stayed in its process group.
"""

from __future__ import annotations

import contextlib
import itertools
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

import psutil

from .audit import mark_started
from .oscompat import decode_output
from .policy import ComputerPolicy, PolicyViolation
from .proctree import IS_WINDOWS, ProcessTree
from .waiting import TAIL_CHARS, Prompt, find_prompt

_READ_CHUNK = 65536
_MAX_WAIT_SECONDS = 30.0
_JOIN_SECONDS = 5.0
_SESSION_DRAIN_SECONDS = 0.5
# How long send_input waits for a program to take its input. A program that does not read stdin
# fills the pipe, and the write would otherwise hold a worker thread until the session expires.
_INPUT_WRITE_SECONDS = 10.0
# Output that has stopped arriving for this long is settled: start_process and
# interact_with_process return it, and a question at its end counts as a prompt.
_SETTLE_SECONDS = 0.3
# Bytes holding at least TAIL_CHARS characters, whatever their UTF-8 width.
_TAIL_BYTES = TAIL_CHARS * 4


class CommandError(ValueError):
    """Raised when a command or session request cannot be fulfilled."""


# Processes that must never be signalled; killing them crashes or locks Windows.
_WINDOWS_CRITICAL = frozenset(
    {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe"}
)


def _resolve_cwd(policy: ComputerPolicy, cwd: str | None) -> Path:
    directory = policy.resolve(cwd) if cwd else policy.roots[0]
    if not directory.is_dir():
        raise CommandError(f"Working directory does not exist: {cwd}")
    return directory


class BoundedCapture:
    """Keeps the head and tail of a stream within ``limit`` bytes."""

    def __init__(self, limit: int) -> None:
        self._head_limit = limit // 4
        self._tail_limit = limit - self._head_limit
        self._head = bytearray()
        self._tail = bytearray()
        self.total = 0

    def feed(self, chunk: bytes) -> None:
        self.total += len(chunk)
        room = self._head_limit - len(self._head)
        if room > 0:
            self._head += chunk[:room]
            chunk = chunk[room:]
        if chunk:
            self._tail += chunk
            if len(self._tail) > self._tail_limit:
                del self._tail[: len(self._tail) - self._tail_limit]

    @property
    def truncated(self) -> bool:
        return self.total > len(self._head) + len(self._tail)

    def text(self) -> str:
        head = decode_output(bytes(self._head))
        tail = decode_output(bytes(self._tail))
        if not self.truncated:
            return head + tail
        dropped = self.total - len(self._head) - len(self._tail)
        return f"{head}\n… [{dropped} bytes omitted] …\n{tail}"


def _pump(stream: IO[bytes], sink: Any) -> None:
    try:
        while True:
            chunk = stream.read1(_READ_CHUNK) if hasattr(stream, "read1") else stream.read(_READ_CHUNK)
            if not chunk:
                break
            sink(chunk)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def run_command(
    policy: ComputerPolicy, command: str, *, cwd: str | None = None, timeout_seconds: float | None = None
) -> dict[str, Any]:
    argv = policy.command_argv(command)
    directory = _resolve_cwd(policy, cwd)
    timeout = policy.clamp_timeout(timeout_seconds)
    stdout = BoundedCapture(policy.max_output_bytes)
    stderr = BoundedCapture(policy.max_output_bytes)
    env = policy.child_env()
    mark_started(argv=argv, cwd=str(directory), timeout_seconds=timeout)
    started = time.monotonic()
    try:
        tree = ProcessTree(
            argv,
            cwd=directory,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise CommandError(f"Could not start command: {exc}") from None
    proc = tree.proc
    readers = [
        threading.Thread(target=_pump, args=(proc.stdout, stdout.feed), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, stderr.feed), daemon=True),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        tree.kill()
        proc.wait()
    finally:
        if proc.poll() is None:
            tree.kill()
            proc.wait()
        tree.release()
    drain_deadline = time.monotonic() + _JOIN_SECONDS
    for reader in readers:
        reader.join(max(0.0, drain_deadline - time.monotonic()))
    return {
        "command": command,
        "cwd": str(directory),
        "pid": proc.pid,
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        "timeout_seconds": timeout,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "stdout": stdout.text(),
        "stderr": stderr.text(),
        "stdout_truncated": stdout.truncated,
        "stderr_truncated": stderr.truncated,
    }


# ----------------------------------------------------------------- sessions


ExitCallback = Callable[[dict[str, Any]], None]


class _Session:
    def __init__(
        self,
        session_id: str,
        command: str,
        cwd: Path,
        tree: ProcessTree,
        cap: int,
        on_exit: ExitCallback | None = None,
    ) -> None:
        self.id = session_id
        self.command = command
        self.cwd = cwd
        self.tree = tree
        self.proc = proc = tree.proc
        self.started = time.time()
        self.cap = cap
        self.buffer = bytearray()
        self.base = 0  # absolute offset of buffer[0]
        self.cursor = 0  # absolute offset of the next unread byte
        # Absolute offset of the output's end when input was last sent: a prompt before it
        # was answered by that input, so it no longer means the program is waiting.
        self.answered_to = 0
        self.last_output = time.monotonic()
        self.timed_out = False
        # The lifetime timer, set by SessionManager.start; cancelled once the process exits.
        self.watchdog: threading.Timer | None = None
        self.changed = threading.Condition()
        self.writer: threading.Thread | None = None  # an input write still waiting for the program to read
        self.input_lock = threading.Lock()
        self.reader = threading.Thread(target=_pump, args=(proc.stdout, self._append), daemon=True)
        self.reader.start()
        self._on_exit = on_exit
        threading.Thread(target=self._wait_for_exit, daemon=True).start()

    def _wait_for_exit(self) -> None:
        self.proc.wait()
        if self.proc.stdin is not None:  # the program is gone; keep no pipe open for a finished session
            with contextlib.suppress(OSError, ValueError):
                self.proc.stdin.close()
        if self.watchdog is not None:
            self.watchdog.cancel()
        # Before draining: a background child left running would hold the output pipe open.
        self.tree.release()
        self.reader.join(_SESSION_DRAIN_SECONDS)
        if self._on_exit is None:
            return
        try:
            self._on_exit(self.status())
        except Exception as exc:  # an exit report must never crash the waiter thread
            print(f"[computer] could not report exit of session {self.id}: {exc}", file=sys.stderr, flush=True)

    def _append(self, chunk: bytes) -> None:
        with self.changed:
            self.buffer += chunk
            overflow = len(self.buffer) - self.cap
            if overflow > 0:
                del self.buffer[:overflow]
                self.base += overflow
            self.last_output = time.monotonic()
            self.changed.notify_all()

    @property
    def end(self) -> int:
        return self.base + len(self.buffer)

    def running(self) -> bool:
        return self.proc.poll() is None

    def prompt(self) -> Prompt | None:
        """The prompt the program waits at now, if any. Call with ``changed`` held."""
        if self.end <= self.answered_to or not self.running():
            return None
        settled = time.monotonic() - self.last_output >= _SETTLE_SECONDS
        return find_prompt(decode_output(bytes(self.buffer[-_TAIL_BYTES:])), settled=settled)

    def before_input(self) -> int:
        """Note that input is about to be sent; return where the output answering it will start."""
        with self.changed:
            self.answered_to = self.end
            return self.answered_to

    def read(self, wait_seconds: float, *, answer_from: int | None = None, lines_sent: int = 1) -> dict[str, Any]:
        """The output not read yet, waiting up to ``wait_seconds`` for some.

        Plain reads return at the first new output. With ``answer_from``, the wait is for the
        program's answer to what was started or sent: output past that offset, complete. It
        ends when the program waits at a prompt or its output settles. After several input
        lines (``lines_sent``) a prompt may be for the next line, so only settling ends it.
        """
        deadline = time.monotonic() + max(0.0, min(wait_seconds, _MAX_WAIT_SECONDS))
        with self.changed:
            while self.running():
                now = time.monotonic()
                if now >= deadline:
                    break
                if answer_from is None:
                    if self.cursor < self.end:
                        break
                elif self.end > answer_from:
                    if now - self.last_output >= _SETTLE_SECONDS:
                        break
                    if lines_sent <= 1 and self.prompt() is not None:
                        break
                self.changed.wait(min(deadline - now, 0.05))
        if not self.running():
            self.reader.join(_SESSION_DRAIN_SECONDS)
        with self.changed:
            dropped = max(0, self.base - self.cursor)
            start = max(self.cursor, self.base) - self.base
            data = bytes(self.buffer[start:])
            self.cursor = self.end
        return {
            **self.status(),
            "output": decode_output(data),
            "dropped_bytes": dropped,
        }

    def status(self) -> dict[str, Any]:
        code = self.proc.poll()
        with self.changed:
            prompt = self.prompt()
        return {
            "session_id": self.id,
            "command": self.command,
            "cwd": str(self.cwd),
            "pid": self.proc.pid,
            "running": code is None,
            "exit_code": code,
            "timed_out": self.timed_out,
            "runtime_seconds": round(time.time() - self.started, 1),
            "unread_bytes": max(0, self.end - max(self.cursor, self.base)),
            "waiting_for_input": prompt is not None,
            "prompt": prompt.text if prompt else None,
        }


class SessionManager:
    """Long-running commands whose output is read incrementally."""

    def __init__(self, policy: ComputerPolicy, *, on_exit: ExitCallback | None = None) -> None:
        self._policy = policy
        self._on_exit = on_exit
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()
        self._ids = itertools.count(1)

    def _get(self, session_id: str) -> _Session:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise CommandError(f"Unknown session: {session_id}")
        return session

    def _evict_finished(self) -> None:
        finished = [s for s in self._sessions.values() if not s.running()]
        finished.sort(key=lambda s: s.started)
        while len(self._sessions) >= self._policy.max_sessions * 2 and finished:
            self._sessions.pop(finished.pop(0).id, None)

    def start(
        self, command: str, *, cwd: str | None = None, timeout_seconds: float | None = None, wait_seconds: float = 1.0
    ) -> dict[str, Any]:
        argv = self._policy.command_argv(command)
        directory = _resolve_cwd(self._policy, cwd)
        limit = self._policy.max_session_seconds
        lifetime = limit if not timeout_seconds or timeout_seconds <= 0 else min(float(timeout_seconds), limit)
        with self._lock:
            running = sum(1 for s in self._sessions.values() if s.running())
            if running >= self._policy.max_sessions:
                raise PolicyViolation(
                    f"{running} sessions are already running (limit {self._policy.max_sessions}); "
                    "terminate one first."
                )
            self._evict_finished()
            env = self._policy.child_env()
            mark_started(argv=argv, cwd=str(directory), lifetime_seconds=lifetime)
            try:
                tree = ProcessTree(
                    argv,
                    cwd=directory,
                    env=env,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
            except OSError as exc:
                raise CommandError(f"Could not start command: {exc}") from None
            session = _Session(
                f"s{next(self._ids)}",
                command,
                directory,
                tree,
                self._policy.max_output_bytes * 4,
                on_exit=self._on_exit,
            )
            self._sessions[session.id] = session
        watchdog = threading.Timer(lifetime, self._expire, args=(session,))
        watchdog.daemon = True
        session.watchdog = watchdog
        watchdog.start()
        if not session.running():
            # It exited before the exit waiter could see the timer; nothing is left to expire.
            watchdog.cancel()
        result = session.read(wait_seconds, answer_from=0)
        result["lifetime_seconds"] = lifetime
        return result

    def _expire(self, session: _Session) -> None:
        if session.running():
            session.timed_out = True
            session.tree.kill()

    def read(self, session_id: str, *, wait_seconds: float = 0.0) -> dict[str, Any]:
        session = self._get(session_id)
        mark_started(session_id=session_id, pid=session.proc.pid)
        return session.read(wait_seconds)

    def send(self, session_id: str, text: str, *, newline: bool = True, wait_seconds: float = 1.0) -> dict[str, Any]:
        session = self._get(session_id)
        if not session.running() or session.proc.stdin is None:
            raise CommandError(f"Session {session_id} is no longer running.")
        line_end = "\r\n" if IS_WINDOWS else "\n"
        payload = (text + (line_end if newline else "")).encode("utf-8")
        if len(payload) > self._policy.max_write_bytes:
            raise CommandError(
                f"Input is {len(payload)} bytes; at most {self._policy.max_write_bytes} can be sent at once."
            )
        stdin = session.proc.stdin
        failed: list[BaseException] = []

        def deliver() -> None:
            try:
                stdin.write(payload)
                stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                failed.append(exc)

        with session.input_lock:  # one write in flight per session, so input never interleaves
            if session.writer is not None and session.writer.is_alive():
                raise CommandError(
                    f"Session {session_id} has not read the input sent earlier; send more once it does."
                )
            mark_started(session_id=session_id, pid=session.proc.pid, input_bytes=len(payload))
            answer_from = session.before_input()
            writer = session.writer = threading.Thread(target=deliver, daemon=True, name=f"session-{session_id}-input")
            writer.start()
        writer.join(_INPUT_WRITE_SECONDS)
        if writer.is_alive():
            raise CommandError(
                f"Session {session_id} is not reading its input: it was not taken within "
                f"{_INPUT_WRITE_SECONDS:.0f} seconds. It is delivered if the program reads it later."
            )
        if failed:
            raise CommandError(f"Session {session_id} is not accepting input.")
        return session.read(wait_seconds, answer_from=answer_from, lines_sent=payload.count(b"\n"))

    def terminate(self, session_id: str) -> dict[str, Any]:
        session = self._get(session_id)
        mark_started(session_id=session_id, pid=session.proc.pid)
        if session.running():
            session.tree.kill()
            try:
                session.proc.wait(timeout=_JOIN_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        return session.read(0.0)

    def list(self) -> list[dict[str, Any]]:
        mark_started()
        with self._lock:
            sessions = list(self._sessions.values())
        return [s.status() for s in sessions]

    def shutdown(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
        for session in sessions:
            if session.running():
                session.tree.kill()


# ---------------------------------------------------------------- processes


def list_processes(*, name_filter: str | None = None, limit: int = 200, command_lines: bool = False) -> dict[str, Any]:
    """List processes. Without ``command_lines`` only each program is shown, never its arguments.

    The filter then matches the name and program only, so arguments cannot be probed by filtering on guesses.
    """
    needle = (name_filter or "").casefold()
    mark_started(name_filter=name_filter)
    rows: list[dict[str, Any]] = []
    attrs = ["pid", "ppid", "name", "username", "status", "create_time", "memory_info", "cmdline"]
    total = 0
    for proc in psutil.process_iter(attrs):
        info = proc.info
        argv = info.get("cmdline") or []
        cmdline = " ".join(argv) if command_lines else (argv[0] if argv else "")
        name = info.get("name") or ""
        if needle and needle not in name.casefold() and needle not in cmdline.casefold():
            continue
        total += 1
        if len(rows) >= limit:
            continue
        memory = info.get("memory_info")
        rows.append(
            {
                "pid": info["pid"],
                "ppid": info.get("ppid"),
                "name": name,
                "user": info.get("username"),
                "status": info.get("status"),
                "rss_bytes": memory.rss if memory else None,
                "started": round(info["create_time"]) if info.get("create_time") else None,
                "cmdline": cmdline[:300],
            }
        )
    result: dict[str, Any] = {"processes": rows, "matched": total, "truncated": total > len(rows)}
    if not command_lines:
        result["note"] = "Arguments are hidden; cmdline shows each program only (processes.command_lines enables them)."
    return result


def kill_process(pid: int, *, force: bool = False) -> dict[str, Any]:
    if pid < 0:  # never a process: on POSIX a negative pid names a process group
        raise CommandError(f"No such process: {pid}")
    protected = {0, 1, 4, os.getpid(), os.getppid()}
    if pid in protected:
        raise PolicyViolation(f"Process {pid} is protected and cannot be signalled.")
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        if IS_WINDOWS and name.lower() in _WINDOWS_CRITICAL:
            raise PolicyViolation(f"Process {pid} ({name}) is critical to Windows and cannot be signalled.")
        mark_started(pid=pid, name=name, signal="kill" if force else "terminate")
        if force:
            proc.kill()
        else:
            proc.terminate()
        try:
            proc.wait(timeout=_JOIN_SECONDS)
            exited = True
        except psutil.TimeoutExpired:
            exited = False
    except psutil.NoSuchProcess:
        raise CommandError(f"No such process: {pid}") from None
    except psutil.AccessDenied:
        raise CommandError(f"Not permitted to signal process {pid}.") from None
    return {"pid": pid, "name": name, "signal": "kill" if force else "terminate", "exited": exited}
