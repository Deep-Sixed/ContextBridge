"""Operating-system differences the engine has to get right.

Every function takes an explicit ``windows`` flag (defaulting to the running
OS) so the Windows rules can be tested on any platform.
"""

from __future__ import annotations

import base64
import os
import shlex
from pathlib import PureWindowsPath

IS_WINDOWS = os.name == "nt"

# Only real executables: .bat/.cmd run through cmd.exe, which re-parses the
# arguments and allows command injection (the "BatBadBut" class of bugs).
WINDOWS_EXECUTABLE_EXTENSIONS = (".com", ".exe")

_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(10)}
    | {f"LPT{i}" for i in range(10)}
)
_WINDOWS_INVALID_CHARS = frozenset('<>"|?*') | {chr(c) for c in range(32)}

# UTF-8 console output for PowerShell, so the agent can decode it reliably.
_POWERSHELL_PRELUDE = (
    "$ProgressPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$OutputEncoding=[System.Text.Encoding]::UTF8;"
)

SHELL_PRESETS = ("bash", "sh", "powershell", "pwsh", "cmd")


# ------------------------------------------------------------- command lines


def split_command(command: str, *, windows: bool = IS_WINDOWS) -> list[str]:
    """Split a command line into argv the way the target platform's programs will see it."""
    if not windows:
        return shlex.split(command, posix=True)
    return split_windows_command(command)


def split_windows_command(command: str) -> list[str]:
    """CommandLineToArgvW rules: quotes group, backslashes are literal unless they precede a quote.

    The inverse of :func:`subprocess.list2cmdline`.
    """
    args: list[str] = []
    current: list[str] = []
    in_quotes = False
    pending = False  # an argument has started (even an empty quoted one)
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\":
            j = i
            while j < n and command[j] == "\\":
                j += 1
            count = j - i
            if j < n and command[j] == '"':
                current.append("\\" * (count // 2))
                if count % 2:
                    current.append('"')
                    j += 1
            else:
                current.append("\\" * count)
            i = j
            pending = True
            continue
        if c == '"':
            if in_quotes and i + 1 < n and command[i + 1] == '"':
                current.append('"')
                i += 2
            else:
                in_quotes = not in_quotes
                i += 1
            pending = True
            continue
        if c in " \t" and not in_quotes:
            if pending:
                args.append("".join(current))
                current = []
                pending = False
            i += 1
            continue
        current.append(c)
        pending = True
        i += 1
    if in_quotes:
        raise ValueError("No closing quotation")
    if pending:
        args.append("".join(current))
    return args


def is_shell_operator(token: str) -> bool:
    """A token that only means something to a shell (pipes, redirects, separators)."""
    return bool(token) and set(token) <= set("();<>|&^")


def program_name(program: str, *, windows: bool = IS_WINDOWS) -> str:
    """The allowlist name for a program: lower-cased without .exe/.com on Windows."""
    if not windows:
        return program
    lowered = program.lower()
    for ext in WINDOWS_EXECUTABLE_EXTENSIONS:
        if lowered.endswith(ext):
            return lowered[: -len(ext)]
    return lowered


def has_path_part(program: str, *, windows: bool = IS_WINDOWS) -> bool:
    if "/" in program:
        return True
    return windows and ("\\" in program or ":" in program)


def resolve_program(
    name: str,
    *,
    path: str | None = None,
    windows: bool = IS_WINDOWS,
) -> str | None:
    """Find ``name`` on PATH, never in the current directory or a relative PATH entry.

    On Windows only .exe and .com files are accepted.
    """
    search = os.environ.get("PATH", "") if path is None else path
    if windows:
        stem, ext = os.path.splitext(name)
        if ext:
            if ext.lower() not in WINDOWS_EXECUTABLE_EXTENSIONS:
                return None
            candidates = [name]
        else:
            candidates = [name + e for e in WINDOWS_EXECUTABLE_EXTENSIONS]
        separator = ";"
        is_absolute = lambda d: PureWindowsPath(d).is_absolute() or os.path.isabs(d)  # noqa: E731
    else:
        candidates = [name]
        separator = os.pathsep
        is_absolute = os.path.isabs
    for entry in search.split(separator):
        directory = entry.strip().strip('"')
        if not directory or not is_absolute(directory):
            continue
        for candidate in candidates:
            full = os.path.join(directory, candidate)
            if os.path.isfile(full) and (windows or os.access(full, os.X_OK)):
                return full
    return None


def shell_invocation(shell: str | list[str] | tuple[str, ...] | None, command: str, *, windows: bool = IS_WINDOWS):
    """argv (or, for cmd.exe, a raw command line) that runs ``command`` in ``shell``.

    ``shell`` is a preset name, an explicit argv prefix (the command is appended
    as the last argument), or None for the platform default.
    """
    if shell is None or shell == "" or shell == ():
        shell = "powershell" if windows else "bash"
    if not isinstance(shell, str):
        return [*shell, command]
    if shell in ("powershell", "pwsh"):
        script = (_POWERSHELL_PRELUDE + command).encode("utf-16-le")
        exe = "powershell.exe" if shell == "powershell" else "pwsh.exe" if windows else "pwsh"
        return [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.b64encode(script).decode()]
    if shell == "cmd":
        # cmd.exe parses its own command line; pass it verbatim instead of re-quoting.
        return f'cmd.exe /d /s /c "{command}"'
    if shell == "bash":
        return ["/bin/bash" if os.path.exists("/bin/bash") else "bash", "-c", command]
    if shell == "sh":
        return ["/bin/sh", "-c", command]
    raise ValueError(f"unknown shell {shell!r}; use one of {', '.join(SHELL_PRESETS)} or an argv list")


# ------------------------------------------------------------------ file names


def windows_path_problem(raw: str) -> str | None:
    """Why ``raw`` is unsafe as a Windows path, or None.

    Blocks names Windows silently reinterprets, which could slip past deny
    patterns: alternate data streams (``.env::$DATA``), device names (``CON``),
    trailing dots or spaces (``.env.`` opens ``.env``), and device namespaces.
    """
    if raw.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")):
        return "device-namespace paths are not allowed"
    path = PureWindowsPath(raw)
    if path.drive and not path.root and not path.drive.startswith("\\\\"):
        return "drive-relative paths (like C:file) are not allowed"
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        if part in (".", ".."):
            continue
        if ":" in part:
            return "alternate data streams are not allowed"
        if part != part.rstrip(". "):
            return "names ending in a dot or space are not allowed"
        if any(ch in _WINDOWS_INVALID_CHARS for ch in part):
            return "name contains characters Windows does not allow"
        if part.split(".")[0].upper().rstrip() in _WINDOWS_RESERVED_NAMES:
            return f"{part!r} is a reserved Windows device name"
    return None


# ---------------------------------------------------------------------- output


def decode_output(data: bytes, *, windows: bool = IS_WINDOWS) -> str:
    """Decode program output: UTF-8, falling back to the OEM code page on Windows."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    text = data.decode("utf-8", errors="replace")
    if windows and text.count("�") > 3:
        try:
            return data.decode("oem")
        except LookupError:
            pass
    return text
