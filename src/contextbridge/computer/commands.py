"""Command execution, background sessions, and process inspection.

Commands run without an intermediate shell in allowlist mode, with credentials
stripped from the environment, inside a readable root, under a hard timeout,
and with bounded output capture. Timed-out commands are killed with their whole
process tree.
"""

from __future__ import annotations

import itertools
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import IO, Any

import psutil

from .policy import ComputerPolicy, PolicyViolation

_READ_CHUNK = 65536
_MAX_WAIT_SECONDS = 30.0
_JOIN_SECONDS = 5.0
_SESSION_DRAIN_SECONDS = 0.5


class CommandError(ValueError):
    """Raised when a command or session request cannot be fulfilled."""


def _popen_kwargs() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Kill ``proc`` and every descendant it started."""
    try:
        children = psutil.Process(proc.pid).children(recursive=True)
    except psutil.Error:
        children = []
    if os.name != "nt":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
    for child in children:
        try:
            child.kill()
        except psutil.Error:
            pass
    try:
        proc.kill()
    except OSError:
        pass


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
        head = self._head.decode("utf-8", errors="replace")
        tail = self._tail.decode("utf-8", errors="replace")
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
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            cwd=directory,
            env=policy.child_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **_popen_kwargs(),
        )
    except OSError as exc:
        raise CommandError(f"Could not start command: {exc}") from None
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
        kill_tree(proc)
        proc.wait()
    finally:
        if proc.poll() is None:
            kill_tree(proc)
            proc.wait()
    drain_deadline = time.monotonic() + _JOIN_SECONDS
    for reader in readers:
        reader.join(max(0.0, drain_deadline - time.monotonic()))
    return {
        "command": command,
        "cwd": str(directory),
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


class _Session:
    def __init__(self, session_id: str, command: str, cwd: Path, proc: subprocess.Popen[bytes], cap: int) -> None:
        self.id = session_id
        self.command = command
        self.cwd = cwd
        self.proc = proc
        self.started = time.time()
        self.cap = cap
        self.buffer = bytearray()
        self.base = 0  # absolute offset of buffer[0]
        self.cursor = 0  # absolute offset of the next unread byte
        self.timed_out = False
        self.changed = threading.Condition()
        self.reader = threading.Thread(target=_pump, args=(proc.stdout, self._append), daemon=True)
        self.reader.start()

    def _append(self, chunk: bytes) -> None:
        with self.changed:
            self.buffer += chunk
            overflow = len(self.buffer) - self.cap
            if overflow > 0:
                del self.buffer[:overflow]
                self.base += overflow
            self.changed.notify_all()

    @property
    def end(self) -> int:
        return self.base + len(self.buffer)

    def running(self) -> bool:
        return self.proc.poll() is None

    def read(self, wait_seconds: float) -> dict[str, Any]:
        deadline = time.monotonic() + max(0.0, min(wait_seconds, _MAX_WAIT_SECONDS))
        with self.changed:
            while self.cursor >= self.end and self.running():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.changed.wait(min(remaining, 0.1))
        if not self.running():
            self.reader.join(_SESSION_DRAIN_SECONDS)
        with self.changed:
            dropped = max(0, self.base - self.cursor)
            start = max(self.cursor, self.base) - self.base
            data = bytes(self.buffer[start:])
            self.cursor = self.end
        return {
            **self.status(),
            "output": data.decode("utf-8", errors="replace"),
            "dropped_bytes": dropped,
        }

    def status(self) -> dict[str, Any]:
        code = self.proc.poll()
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
        }


class SessionManager:
    """Long-running commands whose output is read incrementally."""

    def __init__(self, policy: ComputerPolicy) -> None:
        self._policy = policy
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
            try:
                proc = subprocess.Popen(
                    argv,
                    cwd=directory,
                    env=self._policy.child_env(),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    **_popen_kwargs(),
                )
            except OSError as exc:
                raise CommandError(f"Could not start command: {exc}") from None
            session = _Session(f"s{next(self._ids)}", command, directory, proc, self._policy.max_output_bytes * 4)
            self._sessions[session.id] = session
        watchdog = threading.Timer(lifetime, self._expire, args=(session,))
        watchdog.daemon = True
        watchdog.start()
        result = session.read(wait_seconds)
        result["lifetime_seconds"] = lifetime
        return result

    def _expire(self, session: _Session) -> None:
        if session.running():
            session.timed_out = True
            kill_tree(session.proc)

    def read(self, session_id: str, *, wait_seconds: float = 0.0) -> dict[str, Any]:
        return self._get(session_id).read(wait_seconds)

    def send(self, session_id: str, text: str, *, newline: bool = True, wait_seconds: float = 1.0) -> dict[str, Any]:
        session = self._get(session_id)
        if not session.running() or session.proc.stdin is None:
            raise CommandError(f"Session {session_id} is no longer running.")
        payload = (text + ("\n" if newline else "")).encode("utf-8")
        try:
            session.proc.stdin.write(payload)
            session.proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            raise CommandError(f"Session {session_id} is not accepting input.") from None
        return session.read(wait_seconds)

    def terminate(self, session_id: str) -> dict[str, Any]:
        session = self._get(session_id)
        if session.running():
            kill_tree(session.proc)
            try:
                session.proc.wait(timeout=_JOIN_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        return session.read(0.0)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            sessions = list(self._sessions.values())
        return [s.status() for s in sessions]

    def shutdown(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
        for session in sessions:
            if session.running():
                kill_tree(session.proc)


# ---------------------------------------------------------------- processes


def list_processes(*, name_filter: str | None = None, limit: int = 200) -> dict[str, Any]:
    needle = (name_filter or "").casefold()
    rows: list[dict[str, Any]] = []
    attrs = ["pid", "ppid", "name", "username", "status", "create_time", "memory_info", "cmdline"]
    total = 0
    for proc in psutil.process_iter(attrs):
        info = proc.info
        cmdline = " ".join(info.get("cmdline") or [])
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
    return {"processes": rows, "matched": total, "truncated": total > len(rows)}


def kill_process(pid: int, *, force: bool = False) -> dict[str, Any]:
    protected = {0, 1, 4, os.getpid(), os.getppid()}
    if pid in protected:
        raise PolicyViolation(f"Process {pid} is protected and cannot be signalled.")
    try:
        proc = psutil.Process(pid)
        name = proc.name()
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
