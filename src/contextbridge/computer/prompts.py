"""Detects from its output whether an interactive process is waiting for input.

A prompt is the last thing a process writes before it waits, so only the end of
its output is examined. Output never shows that a process has finished: that is
known from its exit alone.

The prompt tables and the matching rules are ported from Desktop Commander's
``src/utils/process-detection.ts`` (MIT License, Copyright (c) 2024-2025 Eduard
Ruzga and Desktop Commander Contributors; see ``THIRD_PARTY_NOTICES.md``).
"""

from __future__ import annotations

import re

# How much of the end of the output is examined, so the cost stays the same
# however much a process has written.
TAIL_CHARS = 4096

# Common REPL prompts. Most are generic ("... ", "> ", "+ ", "| "): inside or at
# the end of a longer line they are ordinary text (pytest -v's "collecting ... ",
# a markdown table's "| a | b |"), so they count only in a last line made of
# prompts alone: the prompt itself, or the prompts a REPL that doesn't echo its
# input printed one after another (">>> ... " from python -i, "> | " from node -i).
_REPL_PROMPTS = {
    "python": [">>> ", "... "],
    "nodejs": ["> ", "... ", "| "],  # "| " is Node 24's continuation, "... " before it
    "r": ["> ", "+ "],
    "julia": ["julia> ", "       "],  # julia's continuation is spaces
    "shell": ["$ ", "# ", "% "],
    "mysql": ["mysql> ", "    -> "],
    "postgres": ["=# ", "-# "],
    "redis": ["redis> "],
    "mongo": ["> ", "... "],
    "powershell": [">> "],  # continuation
}
_PROMPTS = list(dict.fromkeys(prompt for prompts in _REPL_PROMPTS.values() for prompt in prompts))
_PROMPTS_ONLY = re.compile("(?:" + "|".join(re.escape(prompt) for prompt in _PROMPTS) + ")+")

# Prompts that also count at the end of a longer line: named ones, after output
# that didn't end in a newline ("done>>> "), and the end of a shell or psql
# prompt ("bash-5.2$ ", "user@host dir % ", "postgres=# ").
_LINE_END_PROMPTS = (">>> ", "julia> ", "mysql> ", "redis> ", "$ ", "# ", "% ")

# PowerShell's prompt at the end of a line: "PS ", a location (a drive, provider
# or path: "C:\Users\me", "/Users/me", "HKLM:\"), then "> " (">> " in a nested
# or debugger prompt, "[DBG]: PS C:\>> ").
_POWERSHELL_PROMPT = re.compile(r"PS [^<>|\n]*[\\/:][^<>|\n]*>>? \Z")

# cmd.exe's prompt: the whole last line is a path and ">", with nothing after it
# ("C:\Users\me>"). Output lines end in a newline; a prompt doesn't.
_CMD_PROMPT = re.compile(r'[A-Za-z]:\\[^<>|"*?\n]*>')


def find_prompt(last_line: str) -> str | None:
    """The prompt ``last_line`` is, or ends in, if any."""
    if _PROMPTS_ONLY.fullmatch(last_line):
        # The longest that fits names it best: "julia> " rather than "> ".
        return max((prompt for prompt in _PROMPTS if last_line.endswith(prompt)), key=len)
    for prompt in _LINE_END_PROMPTS:
        if last_line.endswith(prompt):
            return prompt
    if _POWERSHELL_PROMPT.search(last_line) or _CMD_PROMPT.fullmatch(last_line):
        return "> "
    return None


def detect_prompt(output: str) -> str | None:
    """The prompt the output ends at, or None when its end doesn't show one.

    Only the unfinished last line counts: a prompt is not followed by a newline.
    """
    tail = output[-TAIL_CHARS:]
    if not tail.strip():
        return None
    return find_prompt(tail.rsplit("\n", 1)[-1])
