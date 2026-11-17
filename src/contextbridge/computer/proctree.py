"""Start a child process so that it and everything it starts can be killed together.

POSIX: the child leads a new session (process group); killing sends SIGKILL to
the group and to any descendants psutil can still see. When the child has exited,
releasing the tree kills the group too, so background programs it started that
stayed in the group do not outlive it. A program that left the group (``setsid``,
a daemon that detaches into a session of its own) is out of reach on POSIX.

Windows: the child starts suspended, is placed in a Job Object, and only then
resumed, so it cannot start anything outside the job. Killing terminates the
job. The job is created with KILL_ON_JOB_CLOSE, so when the tree is released (or
the agent itself dies, even by TerminateProcess) nothing it started survives.
Child processes also get no console window.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from typing import IO, Any

import psutil

IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _BasicAccounting(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_int64),
            ("TotalKernelTime", ctypes.c_int64),
            ("ThisPeriodTotalUserTime", ctypes.c_int64),
            ("ThisPeriodTotalKernelTime", ctypes.c_int64),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p
    ]
    _kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    _ntdll.NtResumeProcess.restype = ctypes.c_long

    _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _CREATE_SUSPENDED = 0x00000004
    _CREATE_NEW_PROCESS_GROUP = 0x00000200
    _CREATE_NO_WINDOW = 0x08000000

    def _win_error(what: str) -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, f"{what} failed: {ctypes.FormatError(code).strip()}")

    def _create_job() -> int:
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            raise _win_error("CreateJobObject")
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not _kernel32.SetInformationJobObject(
            job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            error = _win_error("SetInformationJobObject")
            _kernel32.CloseHandle(job)
            raise error
        return job

    def _active_processes(job: int) -> int | None:
        info = _BasicAccounting()
        if not _kernel32.QueryInformationJobObject(
            job, _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, ctypes.byref(info), ctypes.sizeof(info), None
        ):
            return None
        return int(info.ActiveProcesses)


# How long release() waits on Windows for a terminated job's processes to be gone.
_JOB_EXIT_SECONDS = 5.0


class ProcessTree:
    """A child process plus everything it starts."""

    def __init__(
        self,
        argv: list[str] | str,
        *,
        cwd: Any,
        env: dict[str, str],
        stdin: int | IO[Any] | None,
        stdout: int | IO[Any] | None,
        stderr: int | IO[Any] | None,
    ) -> None:
        self._job: int | None = None
        self._group_ended = False
        self.contained = True
        common = {"cwd": cwd, "env": env, "stdin": stdin, "stdout": stdout, "stderr": stderr}
        if not IS_WINDOWS:
            self.proc = subprocess.Popen(argv, start_new_session=True, **common)
            return
        flags = _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW  # pragma: no cover - Windows
        try:  # pragma: no cover - Windows
            job = _create_job()
        except OSError as exc:
            # No job object (e.g. a restricted parent job): fall back to psutil tree kills.
            print(f"[computer] process containment unavailable: {exc}", file=sys.stderr, flush=True)
            self.contained = False
            self.proc = subprocess.Popen(argv, creationflags=flags, **common)
            return
        self.proc = subprocess.Popen(argv, creationflags=flags | _CREATE_SUSPENDED, **common)  # pragma: no cover
        handle = int(self.proc._handle)  # type: ignore[attr-defined]  # pragma: no cover
        try:  # pragma: no cover - Windows
            if not _kernel32.AssignProcessToJobObject(job, handle):
                raise _win_error("AssignProcessToJobObject")
            self._job = job
        except OSError as exc:
            _kernel32.CloseHandle(job)
            print(f"[computer] process containment unavailable: {exc}", file=sys.stderr, flush=True)
            self.contained = False
        status = _ntdll.NtResumeProcess(handle)  # pragma: no cover - Windows
        if status != 0:  # pragma: no cover - Windows
            self.proc.kill()
            self.release()
            raise OSError(f"could not resume the new process (NTSTATUS {status & 0xFFFFFFFF:#x})")

    @property
    def pid(self) -> int:
        return self.proc.pid

    def kill(self) -> None:
        """Kill the process and every descendant."""
        if self._job is not None:  # pragma: no cover - Windows
            _kernel32.TerminateJobObject(self._job, 1)
        try:
            children = psutil.Process(self.proc.pid).children(recursive=True)
        except psutil.Error:
            children = []
        if not IS_WINDOWS:
            # The session leader can exit before its background children do.
            # Its process group remains live until every member exits, so
            # kill the group even if the leader has already terminated.
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for child in children:
            try:
                child.kill()
            except psutil.Error:
                pass
        try:
            self.proc.kill()
        except OSError:
            pass

    def release(self) -> None:
        """The command is done: end anything it left running, and drop the containment handle.

        Windows: closing the job ends everything in it. POSIX: once the process has exited,
        its process group is killed, once. Called while the process still runs, it only
        drops the handle; the caller kills the tree first when it means to end it.
        """
        self._end_job()
        if IS_WINDOWS or self._group_ended or self.proc.poll() is None:
            return
        self._group_ended = True
        try:
            # The group outlives its leader while members remain, and POSIX never reuses a
            # number still in use as a group ID. Callers release right after the exit, so
            # a number an empty group has freed has had no time to be given out again.
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def _end_job(self) -> None:
        """Windows: end everything in the job and wait until it has actually exited, then close it.

        Closing a kill-on-close job, like TerminateJobObject, only starts the termination: a
        process can still be running for a moment after the call returns. Callers release a
        tree to promise that nothing the command started is left, so wait for that to be true.
        """
        job = self._job
        if job is not None:  # pragma: no cover - Windows
            _kernel32.TerminateJobObject(job, 1)
            deadline = time.monotonic() + _JOB_EXIT_SECONDS
            while time.monotonic() < deadline:
                active = _active_processes(job)
                if not active:  # 0, or None if the job cannot be queried
                    break
                time.sleep(0.01)
        self._close_job()

    def _close_job(self) -> None:
        job, self._job = self._job, None
        if job is not None:  # pragma: no cover - Windows
            _kernel32.CloseHandle(job)

    def __del__(self) -> None:
        # Only the handle: killing a group here, at some later collection, could reach a
        # group that has since been given the same number.
        try:
            self._close_job()
        except Exception:  # interpreter shutdown; the OS closes the handle with the process
            pass
