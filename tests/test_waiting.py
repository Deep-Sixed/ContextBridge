"""Judging from the end of a program's output whether it waits for input.

The output below was captured from the programs named, run on pipes with stderr merged
into stdout as sessions run them (Python 3, Node.js 22, bash 5 with --norc). The
PowerShell, cmd.exe, MySQL and Julia prompts are their documented default forms.
"""

from __future__ import annotations

import pytest

from contextbridge.computer.waiting import MAX_PROMPT_CHARS, TAIL_CHARS, find_prompt

WAITING = [
    # (case, output, prompt text, kind)
    ("python at start", ">>> ", ">>> ", "marks"),
    ("python after an answer", "2\n>>> ", ">>> ", "marks"),
    ("python mid-statement", ">>> ... ", "... ", "marks"),
    ("python reading two lines at once", "... ... ", "... ", "marks"),
    ("python after output without a newline", "done>>> ", ">>> ", "named"),
    ("python after an answered input()", ">>> Your name: >>> ", ">>> ", "named"),
    ("node at start", 'Welcome to Node.js v22.23.4.\nType ".help" for more information.\n> ', "> ", "marks"),
    ("node after an answer", "2\n> ", "> ", "marks"),
    ("node mid-statement", "> ... ", "... ", "marks"),
    ("bash continuation", "if true; then\n> ", "> ", "marks"),
    ("bash with a user@host PS1", "user@host:~/proj$ echo hi\nhi\nuser@host:~/proj$ ", "user@host:~/proj$ ", "shell"),
    ("bash as root", "root@box:/# true\nroot@box:/# ", "root@box:/# ", "shell"),
    ("zsh default", "me@laptop project % ", "me@laptop project % ", "shell"),
    ("psql", "postgres=# ", "postgres=# ", "shell"),
    ("bash default", "bash-5.2$ ", "bash-5.2$ ", "shell"),
    ("bash as root, default", "bash-5.2# ", "bash-5.2# ", "shell"),
    ("a bare shell sign", "$ ", "$ ", "shell"),
    ("bracketed bash PS1", "[me@box src]$ ", "[me@box src]$ ", "shell"),
    ("csh-style host prompt", "box% ", "box% ", "shell"),
    ("mysql", "mysql> ", "mysql> ", "named"),
    ("mysql continuation", "    -> ", "-> ", "marks"),
    ("julia", "julia> ", "julia> ", "named"),
    ("elixir", "iex(1)> ", "iex(1)> ", "named"),
    ("ruby irb with a prompt", "irb(main):001:0> ", "irb(main):001:0> ", "named"),
    ("powershell", "Windows PowerShell\r\n\r\nPS C:\\Users\\me> ", "PS C:\\Users\\me> ", "named"),
    ("powershell at a drive root", "PS C:\\> ", "PS C:\\> ", "named"),
    ("powershell continuation", "PS C:\\> if ($true) {\n>> ", ">> ", "marks"),
    ("cmd.exe", "Microsoft Windows\r\n\r\nC:\\Users\\me>", "C:\\Users\\me>", "cmd"),
]

QUESTIONS = [
    ("python input()", ">>> name? ", ">>> name? "),
    ("a password prompt", "Password: ", "Password: "),
    ("a confirmation", "Overwrite 3 files? [y/N] ", "Overwrite 3 files? [y/N] "),
]

NOT_WAITING = [
    ("a test runner still collecting", "=== test session starts ===\ncollecting ... "),
    ("a progress bar redrawing its line", "Downloading  45%\r"),
    ("a finished line", "build done\n"),
    ("a prompt followed by a newline", ">>> \n"),
    ("a comparison", "x > y"),
    ("an html tag", "<div>"),
    ("a price", "total: 5$"),
    ("a percentage with a space", "Downloading 45 % "),
    ("a percentage", "progress: 100% "),
    ("an amount", "Total cost: 30$ "),
    ("a heading-like sign", "Building target # "),
    ("a sign after a word and a space", "Copying files $ "),
    ("a step counter", "Step 3/5 # "),
    ("a version-like number", "release 2.1$ "),
    ("a markdown table row", "| a | b |"),
    ("a tag followed by a space", "see <div> "),
    ("nothing", ""),
    ("only whitespace", "   "),
    ("a long unfinished line", "x" * MAX_PROMPT_CHARS + "$ "),
]


@pytest.mark.parametrize(("output", "text", "kind"), [c[1:] for c in WAITING], ids=[c[0] for c in WAITING])
def test_prompts_are_found_without_waiting_for_quiet(output, text, kind):
    found = find_prompt(output)
    assert found is not None and (found.text, found.kind) == (text, kind)


@pytest.mark.parametrize(("output", "text"), [c[1:] for c in QUESTIONS], ids=[c[0] for c in QUESTIONS])
def test_questions_count_only_once_output_has_settled(output, text):
    assert find_prompt(output) is None
    found = find_prompt(output, settled=True)
    assert found is not None and (found.text, found.kind) == (text, "question")


@pytest.mark.parametrize("output", [c[1] for c in NOT_WAITING], ids=[c[0] for c in NOT_WAITING])
def test_ordinary_output_is_not_a_prompt(output):
    assert find_prompt(output, settled=True) is None


def test_only_the_end_of_long_output_is_examined():
    assert find_prompt("x" * (TAIL_CHARS * 10) + "\n>>> ").text == ">>> "
    assert find_prompt(">>> \n" + "y" * (TAIL_CHARS * 2), settled=True) is None
