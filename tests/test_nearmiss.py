"""Near-miss feedback for edit_block: finding the closest text, and how it is described."""

from __future__ import annotations

import random
import time

import pytest

from contextbridge.nearmiss import MAX_QUERY_CHARS, THRESHOLD, closest_match, describe, render_diff

CODE = (
    "def handler(event):\n"
    "    value = event.get('x')\n"
    "    if value is None:\n"
    "        return 0\n"
    "    return value * 2\n"
)


def test_tabs_for_spaces_is_found_and_called_whitespace():
    query = "def handler(event):\n\tvalue = event.get('x')\n"
    miss = closest_match(CODE, query)
    assert miss.line == 1 and miss.text == "def handler(event):\n    value = event.get('x')\n"
    message = describe(query, miss)
    assert "line 1" in message and "only in whitespace" in message
    assert "{-\\t-}{+    +}" in message


def test_crlf_line_endings_are_named():
    query = "    if value is None:\n        return 0\n"
    miss = closest_match(CODE.replace("\n", "\r\n"), query)
    assert miss.line == 3 and miss.text == "    if value is None:\r\n        return 0\r\n"
    message = describe(query, miss)
    assert "only in line endings: the file uses \\r\\n" in message
    assert "{+\\r+}" in message


def test_a_changed_word_is_marked():
    query = "    value = event.get('y')\n"
    miss = closest_match(CODE, query)
    assert miss.line == 2 and miss.similarity >= THRESHOLD
    assert "event.get('{-y-}{+x+}')" in describe(query, miss)


def test_a_partial_line_is_trimmed_to_what_lines_up():
    # The query starts mid-line, so the indentation before it is not part of the near miss.
    miss = closest_match(CODE, "if value is Nne:")
    assert miss.line == 3 and miss.text == "if value is None:"
    assert render_diff("if value is Nne:", miss.text) == "if value is N{+o+}ne:"


def test_unrelated_text_gets_no_diff():
    query = "SELECT * FROM users WHERE id = 1"
    miss = closest_match(CODE, query)
    assert miss is None or miss.similarity < THRESHOLD
    message = describe(query, miss)
    assert "{-" not in message and ("only" in message or "No text" in message)


@pytest.mark.parametrize(
    ("text", "query"),
    [("", "x"), (CODE, ""), (CODE, "x" * (MAX_QUERY_CHARS + 1))],
    ids=["empty file", "empty query", "query too long to search"],
)
def test_nothing_to_search(text, query):
    assert closest_match(text, query) is None
    assert describe(query, None) == "No text like old_string was found in the file."


def test_invisible_characters_are_shown():
    assert render_diff("a b", "a b") == "a{- -}{+\\u00a0+}b"
    assert render_diff("x\n", "x\n\n") == "x\n{+\\n+}"


def test_a_long_diff_is_cut_short():
    query = "line\n" * 900
    miss = closest_match("LINE\n" * 900, query)
    assert miss is None or len(describe(query, miss)) < 3000


@pytest.mark.parametrize("mutate", ["word", "tabs", "crlf"])
def test_large_file_finds_the_right_lines_quickly(mutate):
    # 25,000 lines from a 12-word vocabulary: words alone can't tell the runs apart.
    rng = random.Random(1)
    words = ["alpha", "beta", "gamma", "delta", "value", "return", "event", "handler", "if", "else", "for", "in"]
    lines = ["    " + " ".join(rng.choice(words) for _ in range(8)) + "\n" for _ in range(25000)]
    query = "".join(lines[18000:18006])
    query = {
        "word": query.replace("gamma", "gamme", 1),
        "tabs": query.replace("    ", "\t"),
        "crlf": query.replace("\n", "\r\n"),
    }[mutate]
    started = time.monotonic()
    miss = closest_match("".join(lines), query)
    assert time.monotonic() - started < 5
    assert miss.line == 18001 and miss.similarity >= 0.9
