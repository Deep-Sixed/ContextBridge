"""Near-miss feedback for edit_block: when old_string is not in a file, the text closest to it.

Most failed edits are near misses: different indentation, tabs for spaces, ``\\r\\n``
line endings, a changed word. Showing where the closest text is and how it differs
lets the caller copy the exact text instead of guessing again.

The search compares the query with runs of lines of about its length using
:mod:`difflib`, needing no dependency, under a time limit. The diff marks every
difference as ``{-removed-}{+added+}`` and shows invisible characters such as tabs
and ``\\r``.
"""

from __future__ import annotations

import heapq
import re
import time
import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher

THRESHOLD = 0.7
SEARCH_SECONDS = 1.0
# Longer queries are not searched: one comparison could outlast the time limit.
MAX_QUERY_CHARS = 4000
MAX_DIFF_CHARS = 2000
# Runs of lines compared character by character, per run length, picked by the words they share.
CANDIDATES = 200
_WORD = re.compile(r"\w+")
_EQUAL_LINE_WEIGHT = 10.0


@dataclass(frozen=True)
class NearMiss:
    line: int  # the 1-based line the closest text starts on
    text: str
    similarity: float  # 0..1: twice the matching characters over both lengths


def closest_match(text: str, query: str, *, seconds: float = SEARCH_SECONDS) -> NearMiss | None:
    """The text in ``text`` closest to ``query``, or None if nothing shares a character with it.

    Compares ``query`` with runs of lines one shorter, as long as, and one longer than it,
    each trimmed to the part that lines up with it. When the query has words, only the
    runs sharing the most lines and rare words with it are compared, which keeps a large file fast.
    Stops at ``seconds`` with the best so far.
    """
    if not query or not text or len(query) > MAX_QUERY_CHARS:
        return None
    lines = text.splitlines(keepends=True)
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))
    query_lines = max(1, len(query.splitlines()))
    max_window = 4 * len(query) + 1000
    matcher = SequenceMatcher(None, autojunk=False)
    matcher.set_seq2(query)  # SequenceMatcher caches what it learns about the second sequence
    best_score, best_span = 0.0, (0, 0)
    deadline = time.monotonic() + seconds
    # How much each line looks like part of the query: a line equal to one of its lines (ignoring
    # indentation) counts most, then the query's words it has, rarer words more. shared[i] sums
    # this over the lines before line i, so a run's total is one subtraction.
    query_words = set(_WORD.findall(query))
    query_lines_stripped = {line.strip() for line in query.splitlines() if line.strip()}
    line_words = [set(_WORD.findall(line)) & query_words for line in lines]
    lines_with: dict[str, int] = {}
    for words in line_words:
        for word in words:
            lines_with[word] = lines_with.get(word, 0) + 1
    shared = [0.0]
    for line, words in zip(lines, line_words):
        equal = _EQUAL_LINE_WEIGHT if line.strip() in query_lines_stripped else 0.0
        shared.append(shared[-1] + equal + sum(1 / lines_with[word] for word in words))
    for size in dict.fromkeys((query_lines, query_lines - 1, query_lines + 1)):
        if size < 1:
            continue
        firsts = range(max(1, len(lines) - size + 1))
        if (query_words or query_lines_stripped) and len(firsts) > CANDIDATES:
            end = len(lines)
            firsts = heapq.nlargest(CANDIDATES, firsts, key=lambda i: shared[min(i + size, end)] - shared[i])
        for first in firsts:
            if time.monotonic() > deadline:
                break
            window = "".join(lines[first : first + size])
            if not window or len(window) > max_window:
                continue
            matcher.set_seq1(window)
            # quick_ratio bounds the matching characters, which bounds the trimmed score.
            bound = matcher.quick_ratio() * (len(window) + len(query)) / 2
            if bound == 0 or 2 * bound / (bound + len(query)) <= best_score:
                continue
            blocks = [block for block in matcher.get_matching_blocks() if block.size]
            span = _widen(window, query, blocks[0].a, blocks[-1].a + blocks[-1].size)
            matched = sum(block.size for block in blocks)
            score = 2 * matched / (span[1] - span[0] + len(query))
            if score > best_score:
                offset = starts[first]
                best_score, best_span = score, (offset + span[0], offset + span[1])
    if best_score == 0:
        return None
    start, end = best_span
    return NearMiss(line=text.count("\n", 0, start) + 1, text=text[start:end], similarity=best_score)


def _widen(window: str, query: str, start: int, end: int) -> tuple[int, int]:
    """Widen the part of ``window`` that lines up with ``query`` over what alignment leaves out.

    Indentation before it on its line when ``query`` starts with some, and the rest of its last line when ``query`` ends
    one, are part of the near miss: a tab for spaces, a missing ``\\r``.
    """
    line_start = window.rfind("\n", 0, start) + 1
    if query[:1] in (" ", "\t") and not window[line_start:start].strip():
        start = line_start
    if query.endswith(("\n", "\r")):
        line_end = window.find("\n", end)
        if line_end != -1 and not window[end:line_end].strip():
            end = line_end + 1
    return start, end


def describe(expected: str, miss: NearMiss | None) -> str:
    """What to tell the caller about the closest text, as sentences to add to the error."""
    if miss is None:
        return "No text like old_string was found in the file."
    percent = round(miss.similarity * 100)
    if miss.similarity < THRESHOLD:
        return (
            f"The closest text, at line {miss.line}, is only {percent}% similar, so old_string "
            "may be from another file or an older version of this one. Read the file again."
        )
    hint = _hint(expected, miss.text)
    diff = render_diff(expected, miss.text)
    if len(diff) > MAX_DIFF_CHARS:
        diff = diff[:MAX_DIFF_CHARS] + f"\n… [{len(diff) - MAX_DIFF_CHARS} more characters]"
    return (
        f"The closest text, at line {miss.line}, is {percent}% similar.{hint} "
        "Differences, as {-in old_string-}{+in the file+}:\n"
        f"{diff}\n"
        "Retry with old_string copied exactly as the file has it."
    )


def _hint(expected: str, found: str) -> str:
    if expected.replace("\r\n", "\n") == found.replace("\r\n", "\n"):
        ending = "\\r\\n" if "\r\n" in found else "\\n"
        return f" They differ only in line endings: the file uses {ending}."
    if expected.split() == found.split():
        return " They differ only in whitespace (indentation, spaces, tabs or line endings)."
    return ""


def render_diff(expected: str, found: str) -> str:
    """``expected`` with each difference from ``found`` marked ``{-removed-}{+added+}``."""
    matcher = SequenceMatcher(None, expected, found, autojunk=False)
    parts: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            parts.append(expected[i1:i2])
            continue
        if i2 > i1:
            parts.append("{-" + _visible(expected[i1:i2]) + "-}")
        if j2 > j1:
            parts.append("{+" + _visible(found[j1:j2]) + "+}")
    return "".join(parts)


def _visible(segment: str) -> str:
    """Show the characters a reader can't see. Newlines stay unless the segment is only whitespace."""
    only_space = not segment.strip()
    out = []
    for char in segment:
        if char == "\n":
            out.append("\\n" if only_space else char)
        elif char == "\t":
            out.append("\\t")
        elif char == "\r":
            out.append("\\r")
        elif char != " " and (unicodedata.category(char)[0] == "C" or unicodedata.category(char) == "Zs"):
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    return "".join(out)
