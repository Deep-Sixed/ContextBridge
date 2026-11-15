"""Prompt detection: which output ends at a process waiting for input.

The cases follow Desktop Commander's prompt-detection tests (MIT License; see
THIRD_PARTY_NOTICES.md), including the regressions they record: generic prompts
such as "... " inside a longer line (pytest -v's "collecting ... ") are text, and
Node 24's "| " continuation is a prompt only on a line of prompts alone.
"""

from __future__ import annotations

import pytest

from contextbridge.computer.prompts import TAIL_CHARS, detect_prompt

PROMPTS = [
    ("python", "x = 1\n>>> ", ">>> "),
    ("python continuation", "def f():\n... ", "... "),
    ("python, after output without a newline", "done>>> ", ">>> "),
    ("python -i prompts written one after another", ">>> >>> ... ", "... "),
    ("node", "1\n> ", "> "),
    ("node 24 continuation", "> function f() {\n> | ", "| "),
    ("R continuation", "+ ", "+ "),
    ("julia", "julia> ", "julia> "),
    ("shell", "$ ", "$ "),
    ("bash default", "bash-5.2$ ", "$ "),
    ("bash -i prompts written one after another", "bash-5.2$ bash-5.2$ ", "$ "),
    ("bash with user@host", "user@host:~/project$ ", "$ "),
    ("root shell", "root@box:/# ", "# "),
    ("zsh on macOS", "user@Mac project % ", "% "),
    ("mysql", "mysql> ", "mysql> "),
    ("psql", "postgres=# ", "# "),
    ("redis", "redis> ", "redis> "),
    ("powershell.exe at start", "Windows PowerShell\r\n\r\nPS C:\\Users\\me\\project> ", "> "),
    ("powershell after output", "PS C:\\Users\\me\\project> echo hi\nhi\r\nPS C:\\Users\\me\\project> ", "> "),
    ("powershell continuation", "PS C:\\Users\\me\\project> if ($true) {\n>> ", ">> "),
    ("powershell nested prompt", "[DBG]: PS C:\\>> ", "> "),
    ("pwsh on a POSIX path", "PS /Users/me/project> ", "> "),
    ("cmd.exe at start", "Microsoft Windows\r\n\r\nC:\\Users\\me\\project>", "> "),
    ("cmd.exe after output", "C:\\Users\\me\\project>echo hi\nhi\r\n\r\nC:\\Users\\me\\project>", "> "),
]

NOT_PROMPTS = [
    ("pytest -v while it collects", "=== test session starts ===\nplatform linux\ncollecting ... "),
    ("a pytest progress line before its newline", "tests/test_a.py F.F..                    [100%]"),
    ("a markdown table's line", "| a | b |"),
    ("a piece of a line ending in '>'", "<div>"),
    ("a piece of a line ending in '$'", "costs 5$"),
    ("a piece of a line ending in '#'", "see issue #"),
    ("a prompt followed by a newline", ">>> \n"),
    ("output ending in a finished line", "build done\n"),
    ("a diff line", "+ added line"),
    ("nothing", ""),
    ("only whitespace", "  \n "),
]


@pytest.mark.parametrize(("output", "prompt"), [case[1:] for case in PROMPTS], ids=[case[0] for case in PROMPTS])
def test_prompts_are_detected(output, prompt):
    assert detect_prompt(output) == prompt


@pytest.mark.parametrize("output", [case[1] for case in NOT_PROMPTS], ids=[case[0] for case in NOT_PROMPTS])
def test_ordinary_output_is_not_a_prompt(output):
    assert detect_prompt(output) is None


def test_only_the_end_of_long_output_is_examined():
    assert detect_prompt("x" * (TAIL_CHARS * 10) + "\n>>> ") == ">>> "
    assert detect_prompt(">>> " + "\n" + "y" * TAIL_CHARS) is None
