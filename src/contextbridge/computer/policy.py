"""Local policy for the computer route — default-deny, enforced on the machine itself.

The policy decides which paths may be read or written, whether and how commands
may run, and whether processes may be signalled. The gateway only exposes tools
the policy enables, and every tool re-checks the policy before acting.
"""

from __future__ import annotations

import fnmatch
import os
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oscompat import (
    IS_WINDOWS,
    SHELL_PRESETS,
    WINDOWS_EXECUTABLE_EXTENSIONS,
    has_path_part,
    is_shell_operator,
    program_name,
    resolve_program,
    shell_invocation,
    split_command,
    windows_path_problem,
)

COMMAND_MODES = ("disabled", "allowlist", "unrestricted")
DELETE_MODES = ("trash", "permanent", "disabled")
# Deleted items move here, inside the writable root that held them. No file tool may
# read, list, write, or delete anything under it, so a client cannot purge the trash.
TRASH_DIRNAME = ".contextbridge-trash"

DEFAULT_DENY: tuple[str, ...] = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".docker",
    ".password-store",
    ".netrc",
    ".pgpass",
    ".git-credentials",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "id_rsa*",
    "id_ecdsa*",
    "id_ed25519*",
)

# Added on Windows: registry hives, DPAPI keys and credential stores, browser
# secrets, PuTTY keys, cloud CLI credentials.
WINDOWS_DEFAULT_DENY: tuple[str, ...] = (
    "NTUSER.DAT*",
    "UsrClass.dat*",
    "Credentials",
    "Protect",
    "Vault",
    "Login Data",
    "Cookies",
    "Local State",
    "*.ppk",
    ".azure",
)

DEFAULT_ENV_STRIP: tuple[str, ...] = (
    "*TOKEN*",
    "*SECRET*",
    "*PASSWORD*",
    "*PASSWD*",
    "*API_KEY*",
    "*ACCESS_KEY*",
    "*PRIVATE_KEY*",
    "*CREDENTIAL*",
)

# Gateway credentials are never passed to child processes, whatever env_strip says.
ALWAYS_STRIPPED_ENV: frozenset[str] = frozenset({"MCP_AUTH_TOKEN", "CONTEXTBRIDGE_COMPUTER_TOKEN"})

_UNQUOTED_OPERATORS = frozenset("|&<>")

# A junction's reparse tag. stat.IO_REPARSE_TAG_MOUNT_POINT exists only on Windows builds.
_IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003


class PolicyError(ValueError):
    """Raised when a policy configuration is invalid."""


class PolicyViolation(PermissionError):
    """Raised when a request falls outside the configured policy."""


def _real(path: str | Path) -> Path:
    return Path(os.path.realpath(Path(path).expanduser()))


def _is_plain_entry(path: Path) -> bool:
    """True when ``path`` exists and is neither a symlink nor a Windows junction."""
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    if stat.S_ISLNK(st.st_mode):
        return False
    # os.path.islink misses junctions; lstat reports them by reparse tag.
    return getattr(st, "st_reparse_tag", 0) != _IO_REPARSE_TAG_MOUNT_POINT


def _within(path: Path, roots: tuple[Path, ...]) -> Path | None:
    for root in roots:
        if path == root or path.is_relative_to(root):
            return root
    return None


def _has_unquoted_operator(command: str) -> bool:
    """Windows: a pipe, redirect, or & outside double quotes."""
    in_quotes = False
    backslashes = 0
    for ch in command:
        if ch == '"' and backslashes % 2 == 0:
            in_quotes = not in_quotes
        elif not in_quotes and ch in _UNQUOTED_OPERATORS:
            return True
        backslashes = backslashes + 1 if ch == "\\" else 0
    return False


@dataclass(frozen=True)
class ComputerPolicy:
    roots: tuple[Path, ...]
    writable_roots: tuple[Path, ...] = ()
    deny: tuple[str, ...] = DEFAULT_DENY
    protected: frozenset[Path] = frozenset()
    hidden: frozenset[Path] = frozenset()
    max_read_bytes: int = 1024 * 1024
    max_write_bytes: int = 1024 * 1024
    max_results: int = 500
    max_search_seconds: float = 10.0
    command_mode: str = "disabled"
    command_allow: frozenset[str] = frozenset()
    shell: str | tuple[str, ...] = ""
    default_timeout_seconds: float = 30.0
    max_timeout_seconds: float = 600.0
    max_output_bytes: int = 64 * 1024
    max_sessions: int = 4
    max_session_seconds: float = 3600.0
    env_strip: tuple[str, ...] = DEFAULT_ENV_STRIP
    list_processes: bool = True
    allow_kill: bool = False
    delete_mode: str = "trash"
    max_delete_entries: int = 10_000
    max_document_bytes: int = 20 * 1024 * 1024
    windows: bool = IS_WINDOWS

    # ------------------------------------------------------------------ paths

    @property
    def can_write(self) -> bool:
        return bool(self.writable_roots)

    @property
    def can_delete(self) -> bool:
        return self.can_write and self.delete_mode != "disabled"

    def writable_root_for(self, path: Path) -> Path | None:
        """The innermost writable root containing ``path`` (already resolved)."""
        containing = [r for r in self.writable_roots if path == r or path.is_relative_to(r)]
        return max(containing, key=lambda r: len(r.parts)) if containing else None

    def _is_denied(self, path: Path) -> bool:
        for part in path.parts[1:]:
            if (part.casefold() if self.windows else part) == TRASH_DIRNAME:
                return True
            for pattern in self.deny:
                if fnmatch.fnmatch(part, pattern):
                    return True
        return False

    def is_untouchable(self, path: Path) -> bool:
        """True for a path no file tool may read, write, or delete (denied, hidden, or protected)."""
        return self._is_denied(path) or path in self.protected

    def resolve(self, raw: str, *, write: bool = False, follow_symlinks: bool = True) -> Path:
        """Resolve ``raw`` and verify it is inside the readable (or writable) roots.

        Relative paths are taken relative to the first readable root. Symlinks are
        followed before the check, so a link cannot escape the roots. With
        ``follow_symlinks=False`` a final component that is a symlink or junction is
        kept as named, so the link itself can be moved; any other existing final
        component is resolved to its real name, and ``..`` is refused.
        """
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            raise PolicyViolation("A non-empty path is required.")
        if self.windows:
            problem = windows_path_problem(raw.strip())
            if problem:
                raise PolicyViolation(f"{raw}: {problem}.")
        candidate = Path(raw.strip()).expanduser()
        if not candidate.is_absolute():
            candidate = self.roots[0] / candidate
        if follow_symlinks:
            resolved = _real(candidate)
        else:
            # An unresolved trailing ".." passes the lexical root, hidden, and
            # protected checks while naming the directory above. (pathlib drops
            # "." components; an empty name is a filesystem root.)
            if candidate.name in ("", ".."):
                raise PolicyViolation(f"{raw} must end in a file or directory name.")
            resolved = _real(candidate.parent) / candidate.name
            if _is_plain_entry(resolved):
                # Nothing to keep unresolved. On Windows the name may be an 8.3
                # alias (DEVICE~1.JSO for devices.json) that the checks would miss.
                resolved = _real(resolved)
        roots = self.writable_roots if write else self.roots
        if _within(resolved, roots) is None:
            kind = "writable" if write else "readable"
            raise PolicyViolation(f"{raw} is outside the {kind} roots of this computer.")
        if self._is_denied(resolved) or resolved in self.hidden:
            raise PolicyViolation(f"{raw} matches a denied path pattern.")
        if write and resolved in self.protected:
            raise PolicyViolation(f"{raw} is protected and cannot be modified through ContextBridge.")
        return resolved

    def guard_move(self, source: Path) -> None:
        """Refuse to move a root, or a directory holding a protected path, out from under the policy."""
        if source in self.roots or source in self.writable_roots:
            raise PolicyViolation(f"{source} is a configured root and cannot be moved.")
        if any(p.is_relative_to(source) for p in self.protected | self.hidden):
            raise PolicyViolation(f"{source} contains a protected path and cannot be moved.")

    def is_visible(self, path: Path) -> bool:
        """True when ``path`` (already absolute) may be shown in listings and searches."""
        try:
            self.resolve(str(path))
        except PolicyViolation:
            return False
        return True

    # --------------------------------------------------------------- commands

    @property
    def commands_enabled(self) -> bool:
        return self.command_mode != "disabled"

    def command_argv(self, command: str) -> list[str] | str:
        """Translate ``command`` into what to execute: an argv list, or for cmd.exe a raw command line."""
        if not isinstance(command, str) or not command.strip() or "\x00" in command:
            raise PolicyViolation("A non-empty command is required.")
        if self.command_mode == "disabled":
            raise PolicyViolation("Command execution is disabled on this computer.")
        if self.command_mode == "unrestricted":
            return shell_invocation(self.shell or None, command, windows=self.windows)
        return self._allowlisted_argv(command)

    def _allowlisted_argv(self, command: str) -> list[str]:
        operators = "Shell operators (pipes, redirects, ;, &&) are not available in allowlist mode. "
        try:
            argv = split_command(command, windows=self.windows)
            if self.windows:
                has_operator = _has_unquoted_operator(command) or any(is_shell_operator(t) for t in argv)
            else:
                lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
                lexer.whitespace_split = True
                has_operator = any(is_shell_operator(t) for t in lexer)
        except ValueError as exc:
            raise PolicyViolation(f"Could not parse command: {exc}") from None
        if has_operator:
            raise PolicyViolation(operators + "Run one program per call.")
        if not argv:
            raise PolicyViolation("A non-empty command is required.")
        program = argv[0]
        if has_path_part(program, windows=self.windows):
            # A path names one exact file, which must itself be on the allowlist.
            if program not in self.command_allow:
                raise PolicyViolation(f"Program {program!r} is not on this computer's command allowlist.")
            if self.windows and not program.lower().endswith(WINDOWS_EXECUTABLE_EXTENSIONS):
                raise PolicyViolation(f"Program {program!r} must be an .exe or .com file.")
            return argv
        name = program_name(program, windows=self.windows)
        allowed = {program_name(p, windows=self.windows) for p in self.command_allow}
        if name not in allowed:
            raise PolicyViolation(f"Program {name!r} is not on this computer's command allowlist.")
        executable = resolve_program(program, windows=self.windows)
        if executable is None:
            kind = " as an .exe or .com file" if self.windows else ""
            raise PolicyViolation(f"Program {program!r} was not found on PATH{kind}.")
        return [executable, *argv[1:]]

    def child_env(self) -> dict[str, str]:
        """Environment for child processes with credentials removed."""
        env: dict[str, str] = {}
        for key, value in os.environ.items():
            upper = key.upper()
            if upper in ALWAYS_STRIPPED_ENV:
                continue
            if any(fnmatch.fnmatchcase(upper, pattern.upper()) for pattern in self.env_strip):
                continue
            env[key] = value
        return env

    def clamp_timeout(self, requested: float | None) -> float:
        if requested is None or requested <= 0:
            return min(self.default_timeout_seconds, self.max_timeout_seconds)
        return min(float(requested), self.max_timeout_seconds)

    # ---------------------------------------------------------------- summary

    def summary(self) -> dict[str, Any]:
        return {
            "readable_roots": [str(p) for p in self.roots],
            "writable_roots": [str(p) for p in self.writable_roots],
            "denied_patterns": list(self.deny),
            "max_read_bytes": self.max_read_bytes,
            "max_write_bytes": self.max_write_bytes,
            "command_mode": self.command_mode,
            "command_allowlist": sorted(self.command_allow) if self.command_mode == "allowlist" else None,
            "max_timeout_seconds": self.max_timeout_seconds,
            "max_sessions": self.max_sessions,
            "list_processes": self.list_processes,
            "allow_kill": self.allow_kill,
            "delete": self.delete_mode if self.can_write else "disabled",
            "max_document_bytes": self.max_document_bytes,
        }


# ------------------------------------------------------------------- loading


def _positive(section: dict[str, Any], key: str, default: float, *, kind: type = int) -> Any:
    value = section.get(key, default)
    try:
        value = kind(value)
    except (TypeError, ValueError):
        raise PolicyError(f"{key} must be a positive number") from None
    if value <= 0:
        raise PolicyError(f"{key} must be a positive number")
    return value


def _str_list(section: dict[str, Any], key: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    value = section.get(key, list(default))
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        hint = ' (a bare ~ is null in YAML; write "~")' if isinstance(value, list) and None in value else ""
        raise PolicyError(f"{key} must be a list of strings{hint}")
    return tuple(value)


def load_policy(
    cfg: dict[str, Any],
    *,
    protected: tuple[str | Path, ...] = (),
    hidden: tuple[str | Path, ...] = (),
    windows: bool = IS_WINDOWS,
) -> ComputerPolicy:
    """Build a :class:`ComputerPolicy` from the ``filesystem``/``commands``/``processes`` sections.

    ``protected`` paths can be read but never written or moved (config, audit log).
    ``hidden`` paths can never be read, listed, written, or moved (private keys, device registry).
    """
    fs = cfg.get("filesystem") or {}
    cmds = cfg.get("commands") or {}
    procs = cfg.get("processes") or {}
    if not all(isinstance(s, dict) for s in (fs, cmds, procs)):
        raise PolicyError("filesystem, commands, and processes must be mappings")

    roots: list[Path] = []
    for raw in _str_list(fs, "roots"):
        root = _real(raw)
        if not root.is_dir():
            raise PolicyError(f"filesystem.roots: {raw} is not an existing directory")
        roots.append(root)
    if not roots:
        raise PolicyError("filesystem.roots must list at least one directory")

    writable: list[Path] = []
    for raw in _str_list(fs, "writable_roots"):
        root = _real(raw)
        if not root.is_dir():
            raise PolicyError(f"filesystem.writable_roots: {raw} is not an existing directory")
        if _within(root, tuple(roots)) is None:
            raise PolicyError(f"filesystem.writable_roots: {raw} must be inside a readable root")
        writable.append(root)

    delete_mode = fs.get("delete", "trash")
    if delete_mode not in DELETE_MODES:
        raise PolicyError(f"filesystem.delete must be one of {', '.join(DELETE_MODES)}")

    mode = cmds.get("mode", "disabled")
    if mode not in COMMAND_MODES:
        raise PolicyError(f"commands.mode must be one of {', '.join(COMMAND_MODES)}")
    allow = _str_list(cmds, "allow")
    if mode == "allowlist" and not allow:
        raise PolicyError("commands.allow must list at least one program in allowlist mode")
    shell_cfg = cmds.get("shell", "")
    if isinstance(shell_cfg, str):
        if shell_cfg and shell_cfg not in SHELL_PRESETS:
            raise PolicyError(f"commands.shell must be one of {', '.join(SHELL_PRESETS)} or an argv list")
        shell: str | tuple[str, ...] = shell_cfg
    else:
        shell = _str_list(cmds, "shell")
    max_timeout = _positive(cmds, "max_timeout_seconds", 600.0, kind=float)
    if "default_timeout_seconds" in cmds:
        default_timeout = _positive(cmds, "default_timeout_seconds", 30.0, kind=float)
        if default_timeout > max_timeout:
            raise PolicyError("commands.default_timeout_seconds cannot exceed max_timeout_seconds")
    else:
        default_timeout = min(30.0, max_timeout)

    policy = ComputerPolicy(
        roots=tuple(roots),
        writable_roots=tuple(writable),
        deny=_str_list(fs, "deny", DEFAULT_DENY + (WINDOWS_DEFAULT_DENY if windows else ())),
        protected=frozenset(_real(p) for p in (*protected, *hidden) if p),
        hidden=frozenset(_real(p) for p in hidden if p),
        max_read_bytes=_positive(fs, "max_read_bytes", 1024 * 1024),
        max_write_bytes=_positive(fs, "max_write_bytes", 1024 * 1024),
        max_results=_positive(fs, "max_results", 500),
        max_search_seconds=_positive(fs, "max_search_seconds", 10.0, kind=float),
        command_mode=mode,
        command_allow=frozenset(allow),
        shell=shell,
        default_timeout_seconds=default_timeout,
        max_timeout_seconds=max_timeout,
        max_output_bytes=_positive(cmds, "max_output_bytes", 64 * 1024),
        max_sessions=_positive(cmds, "max_sessions", 4),
        max_session_seconds=_positive(cmds, "max_session_seconds", 3600.0, kind=float),
        env_strip=_str_list(cmds, "env_strip", DEFAULT_ENV_STRIP),
        list_processes=bool(procs.get("list", True)),
        allow_kill=bool(procs.get("allow_kill", False)),
        delete_mode=delete_mode,
        max_delete_entries=_positive(fs, "max_delete_entries", 10_000),
        max_document_bytes=_positive(fs, "max_document_bytes", 20 * 1024 * 1024),
        windows=windows,
    )
    return policy
