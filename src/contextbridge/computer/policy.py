"""Local policy for the computer route — default-deny, enforced on the machine itself.

The policy decides which paths may be read or written, whether and how commands
may run, and whether processes may be signalled. The gateway only exposes tools
the policy enables, and every tool re-checks the policy before acting.
"""

from __future__ import annotations

import fnmatch
import os
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

COMMAND_MODES = ("disabled", "allowlist", "unrestricted")

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

# Tokens that only make sense to a shell; allowlist mode runs without one.
_SHELL_OPERATOR_CHARS = frozenset("();<>|&")


class PolicyError(ValueError):
    """Raised when a policy configuration is invalid."""


class PolicyViolation(PermissionError):
    """Raised when a request falls outside the configured policy."""


def _real(path: str | Path) -> Path:
    return Path(os.path.realpath(Path(path).expanduser()))


def _within(path: Path, roots: tuple[Path, ...]) -> Path | None:
    for root in roots:
        if path == root or path.is_relative_to(root):
            return root
    return None


def _default_shell() -> list[str]:
    if os.name == "nt":
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]
    for candidate in ("/bin/bash", "/bin/sh"):
        if os.path.exists(candidate):
            return [candidate, "-c"]
    return ["sh", "-c"]


@dataclass(frozen=True)
class ComputerPolicy:
    roots: tuple[Path, ...]
    writable_roots: tuple[Path, ...] = ()
    deny: tuple[str, ...] = DEFAULT_DENY
    protected: frozenset[Path] = frozenset()
    max_read_bytes: int = 1024 * 1024
    max_write_bytes: int = 1024 * 1024
    max_results: int = 500
    max_search_seconds: float = 10.0
    command_mode: str = "disabled"
    command_allow: frozenset[str] = frozenset()
    shell: tuple[str, ...] = ()
    default_timeout_seconds: float = 30.0
    max_timeout_seconds: float = 600.0
    max_output_bytes: int = 64 * 1024
    max_sessions: int = 4
    max_session_seconds: float = 3600.0
    env_strip: tuple[str, ...] = DEFAULT_ENV_STRIP
    list_processes: bool = True
    allow_kill: bool = False

    # ------------------------------------------------------------------ paths

    @property
    def can_write(self) -> bool:
        return bool(self.writable_roots)

    def _is_denied(self, path: Path) -> bool:
        for part in path.parts[1:]:
            for pattern in self.deny:
                if fnmatch.fnmatch(part, pattern):
                    return True
        return False

    def resolve(self, raw: str, *, write: bool = False, follow_symlinks: bool = True) -> Path:
        """Resolve ``raw`` and verify it is inside the readable (or writable) roots.

        Relative paths are taken relative to the first readable root. Symlinks are
        followed before the check, so a link cannot escape the roots.
        """
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            raise PolicyViolation("A non-empty path is required.")
        candidate = Path(raw.strip()).expanduser()
        if not candidate.is_absolute():
            candidate = self.roots[0] / candidate
        if follow_symlinks:
            resolved = _real(candidate)
        else:
            resolved = _real(candidate.parent) / candidate.name
        roots = self.writable_roots if write else self.roots
        if _within(resolved, roots) is None:
            kind = "writable" if write else "readable"
            raise PolicyViolation(f"{raw} is outside the {kind} roots of this computer.")
        if self._is_denied(resolved):
            raise PolicyViolation(f"{raw} matches a denied path pattern.")
        if write and resolved in self.protected:
            raise PolicyViolation(f"{raw} is protected and cannot be modified through ContextBridge.")
        return resolved

    def guard_move(self, source: Path) -> None:
        """Refuse to move a root, or a directory holding a protected path, out from under the policy."""
        if source in self.roots or source in self.writable_roots:
            raise PolicyViolation(f"{source} is a configured root and cannot be moved.")
        if any(p.is_relative_to(source) for p in self.protected):
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

    def command_argv(self, command: str) -> list[str]:
        """Translate ``command`` into an argv list permitted by the command policy."""
        if not isinstance(command, str) or not command.strip() or "\x00" in command:
            raise PolicyViolation("A non-empty command is required.")
        if self.command_mode == "disabled":
            raise PolicyViolation("Command execution is disabled on this computer.")
        if self.command_mode == "unrestricted":
            return [*(self.shell or _default_shell()), command]
        return self._allowlisted_argv(command)

    def _allowlisted_argv(self, command: str) -> list[str]:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        try:
            tokens = list(lexer)
            argv = shlex.split(command, posix=os.name != "nt")
        except ValueError as exc:
            raise PolicyViolation(f"Could not parse command: {exc}") from None
        if any(tok and set(tok) <= _SHELL_OPERATOR_CHARS for tok in tokens):
            raise PolicyViolation(
                "Shell operators (pipes, redirects, ;, &&) are not available in allowlist mode. "
                "Run one program per call."
            )
        if not argv:
            raise PolicyViolation("A non-empty command is required.")
        program = argv[0]
        if os.sep in program or (os.altsep and os.altsep in program):
            if program not in self.command_allow:
                raise PolicyViolation(f"Program {program!r} is not on this computer's command allowlist.")
            return argv
        name = program[:-4] if os.name == "nt" and program.lower().endswith(".exe") else program
        if name not in self.command_allow:
            raise PolicyViolation(f"Program {name!r} is not on this computer's command allowlist.")
        executable = shutil.which(program)
        if executable is None:
            raise PolicyViolation(f"Program {program!r} was not found on PATH.")
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


def load_policy(cfg: dict[str, Any], *, protected: tuple[str | Path, ...] = ()) -> ComputerPolicy:
    """Build a :class:`ComputerPolicy` from the ``filesystem``/``commands``/``processes`` sections."""
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

    mode = cmds.get("mode", "disabled")
    if mode not in COMMAND_MODES:
        raise PolicyError(f"commands.mode must be one of {', '.join(COMMAND_MODES)}")
    allow = _str_list(cmds, "allow")
    if mode == "allowlist" and not allow:
        raise PolicyError("commands.allow must list at least one program in allowlist mode")
    shell = _str_list(cmds, "shell")

    policy = ComputerPolicy(
        roots=tuple(roots),
        writable_roots=tuple(writable),
        deny=_str_list(fs, "deny", DEFAULT_DENY),
        protected=frozenset(_real(p) for p in protected if p),
        max_read_bytes=_positive(fs, "max_read_bytes", 1024 * 1024),
        max_write_bytes=_positive(fs, "max_write_bytes", 1024 * 1024),
        max_results=_positive(fs, "max_results", 500),
        max_search_seconds=_positive(fs, "max_search_seconds", 10.0, kind=float),
        command_mode=mode,
        command_allow=frozenset(allow),
        shell=shell,
        default_timeout_seconds=_positive(cmds, "default_timeout_seconds", 30.0, kind=float),
        max_timeout_seconds=_positive(cmds, "max_timeout_seconds", 600.0, kind=float),
        max_output_bytes=_positive(cmds, "max_output_bytes", 64 * 1024),
        max_sessions=_positive(cmds, "max_sessions", 4),
        max_session_seconds=_positive(cmds, "max_session_seconds", 3600.0, kind=float),
        env_strip=_str_list(cmds, "env_strip", DEFAULT_ENV_STRIP),
        list_processes=bool(procs.get("list", True)),
        allow_kill=bool(procs.get("allow_kill", False)),
    )
    if policy.default_timeout_seconds > policy.max_timeout_seconds:
        raise PolicyError("commands.default_timeout_seconds cannot exceed max_timeout_seconds")
    return policy
