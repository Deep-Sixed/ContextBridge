"""Whether an interactive program is waiting for input, judged from the end of its output.

A program asking for input leaves its last line unfinished: the prompt has no newline,
because the answer is typed after it. So only that unfinished line is examined, and it
counts as a prompt when its shape is one programs use:

- **marks**: a line of nothing but prompt marks, each followed by a space, such as an
  interpreter's ``>>> `` or ``> `` and its continuation ``... `` or ``>> ``. Several marks
  in a row are normal: a program that reads more than one line before answering prints
  one mark per line on the same unfinished line (``>>> ... ``).
- **named**: a name, closed by ``> `` (``julia> ``, ``sqlite> ``, ``iex(1)> ``), or
  PowerShell's ``PS <location>> ``.
- **shell**: a POSIX shell prompt, which ends in ``$ ``, ``# `` or ``% ``.
- **cmd**: cmd.exe's prompt, a drive path followed by ``>`` with no space.
- **question**: anything else ending in ``? ``, ``: `` or ``] `` (``Password: ``,
  ``Continue? [y/N] ``). Programs also print such text while working (``Loading: ``), so
  it counts only once the output has settled: nothing more arrived for a moment.

Output that ends in a newline or a carriage return (a progress bar redrawing its line)
is never a prompt, and neither is a long line: a prompt is short.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The most of the output's end that is examined: the unfinished line must fit in it.
TAIL_CHARS = 2048
MAX_PROMPT_CHARS = 300

_MARK = r"(?:>>>|\.\.\.|>>|>|\+|->)"
_MARKS_ONLY = re.compile(rf"[ \t]*(?:{_MARK} )+")
_NAMED = re.compile(r"(?:^|.*\s)([\w.\-]+(?:\([^()\s]*\))?(?::\d+)*>) \Z")
_POWERSHELL = re.compile(r"(?:\[\w+\]: )?PS \S.*> \Z")
# An interpreter prompt after other text on its line: output with no newline, or an
# answered question ("Your name: >>> ")
_AFTER_OUTPUT = re.compile(r".*(>>> )\Z")
_SHELL = re.compile(r".*[$#%] \Z")
_CMD = re.compile(r"[A-Za-z]:\\[^\r\n<>|\"*?]*>\Z")
_QUESTION = re.compile(r".*\S[?:\]] \Z")


@dataclass(frozen=True)
class Prompt:
    text: str  # the prompt: its last mark, its name, or its whole line for the other kinds
    kind: str  # "marks", "named", "shell", "cmd" or "question"


def find_prompt(output: str, *, settled: bool = False) -> Prompt | None:
    """The prompt ``output`` ends at, or None when its end doesn't show one.

    ``settled``: the output has stopped arriving, so a question counts too.
    """
    tail = output[-TAIL_CHARS:]
    cut = tail.rfind("\n")
    line = tail[cut + 1 :]
    if cut == -1 and len(output) > len(tail):
        return None  # the unfinished line is longer than the tail, so too long for a prompt
    if not line.strip() or len(line) > MAX_PROMPT_CHARS or line.endswith("\r"):
        return None
    if _MARKS_ONLY.fullmatch(line):
        return Prompt(line.split()[-1] + " ", "marks")
    if _POWERSHELL.fullmatch(line):
        return Prompt(line, "named")
    found = _AFTER_OUTPUT.fullmatch(line) or _NAMED.fullmatch(line)
    if found:
        return Prompt(found.group(1) + ("" if found.group(1).endswith(" ") else " "), "named")
    if _CMD.fullmatch(line):
        return Prompt(line, "cmd")
    if _SHELL.fullmatch(line):
        return Prompt(line, "shell")
    if settled and _QUESTION.fullmatch(line):
        return Prompt(line.strip() + " ", "question")
    return None
