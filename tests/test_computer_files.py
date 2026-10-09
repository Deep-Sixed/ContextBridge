from __future__ import annotations

import io
import os
import stat
import threading
import time
import tracemalloc

import psutil
import pytest
from helpers import symlink_or_skip

from contextbridge.computer import files
from contextbridge.computer.files import FileOperationError
from contextbridge.computer.matcher import WORKER_TAG
from contextbridge.computer.policy import PolicyViolation, load_policy


def _names(result):
    return {entry["path"] for entry in result["entries"]}


def test_list_directory_hides_denied_entries(policy, workspace):
    result = files.list_directory(policy, str(workspace))
    assert {"docs", "src", "work"} <= _names(result)
    assert ".ssh" not in _names(result)
    assert ".env" not in _names(result)


def test_list_directory_depth(policy, workspace):
    shallow = files.list_directory(policy, str(workspace), depth=1)
    deep = files.list_directory(policy, str(workspace), depth=2)
    assert os.path.join("docs", "notes.md") not in _names(shallow)
    assert os.path.join("docs", "notes.md") in _names(deep)
    assert not any(".ssh" in name for name in _names(deep))


def test_list_directory_respects_result_limit(make_policy, workspace):
    for i in range(10):
        (workspace / "work" / f"f{i}.txt").write_text("x", encoding="utf-8")
    policy = make_policy(filesystem={"max_results": 3})
    result = files.list_directory(policy, str(workspace / "work"))
    assert len(result["entries"]) == 3
    assert result["truncated"]


def test_read_file_offsets(policy):
    full = files.read_file(policy, "docs/notes.md")
    assert full["content"] == "alpha\nbeta\ngamma\n"
    assert full["total_lines"] == 3
    middle = files.read_file(policy, "docs/notes.md", offset=1, length=1)
    assert middle["content"] == "beta\n"
    assert middle["start_line"] == 1
    tail = files.read_file(policy, "docs/notes.md", offset=-2)
    assert tail["content"] == "beta\ngamma\n"
    assert tail["start_line"] == 1


def test_read_file_truncates_at_limit(make_policy, workspace):
    (workspace / "docs" / "big.txt").write_text("0123456789\n" * 100, encoding="utf-8")
    policy = make_policy(filesystem={"max_read_bytes": 50})
    result = files.read_file(policy, "docs/big.txt")
    assert result["truncated"]
    assert len(result["content"].encode()) <= 50
    assert result["total_lines"] == 100


def _peak_bytes(fn):
    tracemalloc.start()
    try:
        result = fn()
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_read_file_never_holds_a_newline_free_file_in_memory(make_policy, workspace):
    (workspace / "docs" / "one-line.txt").write_bytes(b"a" * (16 * 1024 * 1024))
    policy = make_policy(filesystem={"max_read_bytes": 4096})
    result, peak = _peak_bytes(lambda: files.read_file(policy, "docs/one-line.txt"))
    assert peak < 1024 * 1024
    assert result["truncated"] and result["line_clipped"]
    assert result["lines_returned"] == 1 and result["total_lines"] == 1
    assert len(result["content"].encode()) <= 4096
    assert result["content"].startswith("aaaa")
    assert result["content"].endswith("clipped at the 4096-byte read limit]\n")


def test_read_file_huge_negative_offset_is_bounded(make_policy, workspace):
    (workspace / "docs" / "log.txt").write_bytes(b"".join(b"line %06d\n" % i for i in range(200_000)))
    policy = make_policy(filesystem={"max_read_bytes": 4096})
    result, peak = _peak_bytes(lambda: files.read_file(policy, "docs/log.txt", offset=-(10**9)))
    assert peak < 1024 * 1024
    assert result["start_line"] == 0
    assert result["content"].startswith("line 000000\n")
    assert result["truncated"] and not result["line_clipped"]
    assert len(result["content"].encode()) <= 4096
    assert result["total_lines"] == 200_000
    tail = files.read_file(policy, "docs/log.txt", offset=-2)
    assert tail["content"] == "line 199998\nline 199999\n"
    assert tail["start_line"] == 199_998


def test_read_file_pages_past_an_overlong_line(make_policy, workspace):
    (workspace / "docs" / "mixed.txt").write_bytes(b"short\r\n" + b"x" * 1000 + b"\r\nafter\r\n")
    policy = make_policy(filesystem={"max_read_bytes": 100})
    first = files.read_file(policy, "docs/mixed.txt")
    assert first["content"] == "short\r\n"
    assert first["truncated"] and not first["line_clipped"]
    clipped = files.read_file(policy, "docs/mixed.txt", offset=1)
    assert clipped["line_clipped"] and clipped["lines_returned"] == 1
    assert clipped["content"].startswith("xxx") and "more characters on this line" in clipped["content"]
    assert len(clipped["content"].encode()) <= 100
    after = files.read_file(policy, "docs/mixed.txt", offset=2)
    assert after["content"] == "after\r\n"
    assert not after["truncated"]
    assert {r["total_lines"] for r in (first, clipped, after)} == {3}


def test_read_file_clips_multibyte_lines_on_a_character_boundary(make_policy, workspace):
    (workspace / "docs" / "accents.txt").write_text("é" * 300 + "\n", encoding="utf-8")
    policy = make_policy(filesystem={"max_read_bytes": 120})
    result = files.read_file(policy, "docs/accents.txt")
    assert result["line_clipped"]
    head = result["content"].split(" … [")[0]
    assert head and set(head) == {"é"}
    assert len(result["content"].encode()) <= 120


def test_bounded_lines_counts_crlf_split_at_the_limit_once():
    def lines(text, limit=4):
        return list(files._bounded_lines(io.StringIO(text, newline=""), limit))

    assert lines("abc\r\ndef\n") == [("abc\r", 0), ("def\n", 0)]
    assert lines("a\rb\rc") == [("a\r", 0), ("b\r", 0), ("c", 0)]
    assert lines("abc\rdefgh\n") == [("abc\r", 0), ("defg", 1)]
    assert lines("abcdefghij") == [("abcd", 6)]
    assert lines("abcdefg\r\nz") == [("abcd", 3), ("z", 0)]


def test_read_file_rejects_binary_and_denied(policy, workspace):
    (workspace / "docs" / "blob.bin").write_bytes(b"\x00\x01\x02")
    with pytest.raises(FileOperationError, match="binary"):
        files.read_file(policy, "docs/blob.bin")
    with pytest.raises(PolicyViolation):
        files.read_file(policy, ".ssh/id_ed25519")
    with pytest.raises(FileNotFoundError):
        files.read_file(policy, "docs/missing.md")


def test_get_file_info(policy, workspace):
    info = files.get_file_info(policy, "docs/notes.md")
    assert info["type"] == "file"
    assert info["line_count"] == 3
    assert info["writable_by_policy"] is False
    (workspace / "work" / "w.txt").write_text("x", encoding="utf-8")
    assert files.get_file_info(policy, "work/w.txt")["writable_by_policy"] is True


def test_search_files_glob_and_substring(policy, workspace):
    by_glob = files.search_files(policy, str(workspace), "*.py")
    assert [m["path"] for m in by_glob["matches"]] == [str(workspace / "src" / "app.py")]
    by_substring = files.search_files(policy, str(workspace), "NOTE")
    assert [m["path"] for m in by_substring["matches"]] == [str(workspace / "docs" / "notes.md")]
    hidden = files.search_files(policy, str(workspace), "id_ed25519")
    assert hidden["matches"] == []


def test_search_code_literal_regex_and_context(policy, workspace):
    literal = files.search_code(policy, str(workspace), "HELLO")
    assert [(m["path"], m["line"]) for m in literal["matches"]] == [(str(workspace / "src" / "app.py"), 2)]
    assert files.search_code(policy, str(workspace), "HELLO", case_sensitive=True)["matches"] == []
    regex = files.search_code(policy, str(workspace), r"^(alpha|gamma)$", regex=True, context_lines=1)
    assert [m["line"] for m in regex["matches"]] == [1, 3]
    assert regex["matches"][0]["after"] == ["beta"]
    filtered = files.search_code(policy, str(workspace), "a", file_pattern="*.py")
    assert {m["path"] for m in filtered["matches"]} == {str(workspace / "src" / "app.py")}
    assert files.search_code(policy, str(workspace), "PRIVATE")["matches"] == []
    with pytest.raises(FileOperationError, match="regular expression"):
        files.search_code(policy, str(workspace), "(", regex=True)


def _worker_processes():
    rows = []
    for proc in psutil.Process().children(recursive=True):
        try:
            if WORKER_TAG in " ".join(proc.cmdline()):
                rows.append(proc)
        except psutil.Error:
            continue
    return rows


def test_search_code_catastrophic_regex_neither_hangs_nor_stalls_other_threads(make_policy, workspace):
    (workspace / "docs" / "a_quick.txt").write_text("aaa\n", encoding="utf-8")
    (workspace / "docs" / "b_slow.txt").write_text("a" * 26 + "b\n", encoding="utf-8")  # ~10 s in-process
    policy = make_policy(filesystem={"max_search_seconds": 1})
    ticks: list[float] = []
    done = threading.Event()

    def tick():
        while not done.is_set():
            ticks.append(time.monotonic())
            time.sleep(0.01)

    ticker = threading.Thread(target=tick)
    ticker.start()
    try:
        started = time.monotonic()
        result = files.search_code(policy, str(workspace / "docs"), r"^(a+)+$", regex=True)
        elapsed = time.monotonic() - started
    finally:
        done.set()
        ticker.join()
    assert result["timed_out"] and result["truncated"]
    assert [(os.path.basename(m["path"]), m["line"]) for m in result["matches"]] == [("a_quick.txt", 1)]
    assert elapsed < 4
    assert max(b - a for a, b in zip(ticks, ticks[1:])) < 1.0  # the GIL was never held for the match
    assert _worker_processes() == []  # killed at the deadline, not left running


def test_search_code_regex_worker_exits_after_a_normal_search(policy, workspace):
    result = files.search_code(policy, str(workspace), r"^def \w+\(", regex=True)
    assert [m["line"] for m in result["matches"]] == [1]
    assert not result["timed_out"]
    assert _worker_processes() == []


def test_search_code_skips_symlinks_out_of_roots(policy, workspace):
    symlink_or_skip(workspace / "docs" / "leak.txt", workspace.parent / "outside.txt")
    assert files.search_code(policy, str(workspace), "outside")["matches"] == []


def test_write_file_rewrite_and_append(policy, workspace):
    target = workspace / "work" / "out.txt"
    first = files.write_file(policy, "work/out.txt", "one\n")
    assert first["created"] and target.read_text() == "one\n"
    os.chmod(target, 0o640)
    files.write_file(policy, "work/out.txt", "two\n")
    assert target.read_text() == "two\n"
    if os.name != "nt":  # POSIX mode bits survive the atomic rewrite
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
    files.write_file(policy, "work/out.txt", "three\n", mode="append")
    assert target.read_text() == "two\nthree\n"
    assert not [p for p in (workspace / "work").iterdir() if p.name.endswith(".cbtmp")]


def test_write_file_limits(make_policy, workspace):
    policy = make_policy(filesystem={"max_write_bytes": 4})
    with pytest.raises(FileOperationError, match="limit"):
        files.write_file(policy, "work/out.txt", "too long")
    with pytest.raises(PolicyViolation, match="writable"):
        files.write_file(policy, "docs/notes.md", "x")
    with pytest.raises(FileOperationError, match="Parent directory"):
        files.write_file(policy, "work/missing/out.txt", "x")
    with pytest.raises(FileOperationError, match="mode"):
        files.write_file(policy, "work/out.txt", "x", mode="truncate")


def test_write_through_symlink_out_of_writable_root_is_denied(policy, workspace):
    symlink_or_skip(workspace / "work" / "notes-link.md", workspace / "docs" / "notes.md")
    with pytest.raises(PolicyViolation, match="writable"):
        files.write_file(policy, "work/notes-link.md", "x")
    assert (workspace / "docs" / "notes.md").read_text() == "alpha\nbeta\ngamma\n"


def test_edit_block(policy, workspace):
    target = workspace / "work" / "code.py"
    target.write_text("x = 1\ny = 1\n", encoding="utf-8")
    with pytest.raises(FileOperationError, match="found 2"):
        files.edit_block(policy, str(target), "= 1", "= 2")
    with pytest.raises(FileOperationError, match="found 0"):
        files.edit_block(policy, str(target), "z = 1", "z = 2")
    assert files.edit_block(policy, str(target), "= 1", "= 2", expected_replacements=2)["replacements"] == 2
    assert target.read_text() == "x = 2\ny = 2\n"
    files.edit_block(policy, str(target), "x = 2", "x = 3")
    assert target.read_text() == "x = 3\ny = 2\n"


def test_edit_block_preserves_crlf(policy, workspace):
    target = workspace / "work" / "win.txt"
    target.write_bytes(b"a\r\nb\r\n")
    files.edit_block(policy, str(target), "b", "c")
    assert target.read_bytes() == b"a\r\nc\r\n"


def test_create_directory_and_move(policy, workspace):
    made = files.create_directory(policy, "work/a/b")
    assert made["created"] and (workspace / "work" / "a" / "b").is_dir()
    assert files.create_directory(policy, "work/a/b")["created"] is False
    (workspace / "work" / "f.txt").write_text("x", encoding="utf-8")
    files.move_file(policy, "work/f.txt", "work/a/g.txt")
    assert (workspace / "work" / "a" / "g.txt").read_text() == "x"
    (workspace / "work" / "h.txt").write_text("y", encoding="utf-8")
    with pytest.raises(FileOperationError, match="already exists"):
        files.move_file(policy, "work/h.txt", "work/a/g.txt")
    with pytest.raises(FileOperationError, match="into itself"):
        files.move_file(policy, "work/a", "work/a/b/c")
    with pytest.raises(PolicyViolation):
        files.move_file(policy, "work/h.txt", "docs/h.txt")
    with pytest.raises(PolicyViolation):
        files.move_file(policy, "docs/notes.md", "work/notes.md")


def test_new_files_get_normal_permissions(policy, workspace):
    # Host services may run with a restrictive umask (for example 077).
    # Verify ordinary file creation honors the selected umask instead of
    # assuming group/other read access on every host.
    previous_umask = os.umask(0o022)
    try:
        files.write_file(policy, "work/fresh.txt", "x")
    finally:
        os.umask(previous_umask)
    mode = stat.S_IMODE((workspace / "work" / "fresh.txt").stat().st_mode)
    if os.name == "nt":
        # Windows stat mode is a synthesized DOS read/write view, not POSIX
        # group/other permission bits; NTFS authorization is enforced by ACLs.
        assert mode & 0o666 == 0o666
    else:
        assert mode == 0o644


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_search_code_skips_fifos(policy, workspace):
    os.mkfifo(workspace / "docs" / "pipe")
    assert files.search_code(policy, str(workspace), "alpha")["files_scanned"] >= 1


def test_move_refuses_roots_and_protected_ancestors(workspace):
    (workspace / "work" / "cfg").mkdir()
    config = workspace / "work" / "cfg" / "computer.yaml"
    config.write_text("x", encoding="utf-8")
    (workspace / "work" / "inner").mkdir()
    policy = load_policy(
        {
            "filesystem": {
                "roots": [str(workspace)],
                "writable_roots": [str(workspace / "work"), str(workspace / "work" / "inner")],
            }
        },
        protected=(config,),
    )
    with pytest.raises(PolicyViolation, match="protected"):
        files.move_file(policy, "work/cfg", "work/cfg-old")
    with pytest.raises(PolicyViolation, match="protected"):
        files.move_file(policy, str(config), "work/moved.yaml")
    with pytest.raises(PolicyViolation, match="configured root"):
        files.move_file(policy, "work/inner", "work/elsewhere")
    assert config.exists()


def test_utf16_files_from_powershell_are_text(policy, workspace):
    """Windows PowerShell's `>` writes UTF-16 with a BOM; it must read, search, and edit as text."""
    target = workspace / "work" / "ps.log"
    target.write_bytes("first line\r\nzweite Zeile ü\r\n".encode("utf-16"))
    read = files.read_file(policy, "work/ps.log")
    assert read["content"] == "first line\r\nzweite Zeile ü\r\n" and read["encoding"] == "utf-16"
    hits = files.search_code(policy, str(workspace / "work"), "zweite")["matches"]
    assert [(h["line"], h["text"]) for h in hits] == [(2, "zweite Zeile ü")]
    info = files.get_file_info(policy, "work/ps.log")
    assert info["binary"] is False and info["line_count"] == 2
    files.edit_block(policy, "work/ps.log", "zweite", "second")
    raw = target.read_bytes()
    assert raw[:2] in (b"\xff\xfe", b"\xfe\xff")  # still UTF-16 with its BOM
    assert raw.decode("utf-16") == "first line\r\nsecond Zeile ü\r\n"


def test_utf8_bom_is_preserved_on_edit(policy, workspace):
    target = workspace / "work" / "bom.txt"
    target.write_bytes(b"\xef\xbb\xbfhello\r\n")
    assert files.read_file(policy, "work/bom.txt")["content"] == "hello\r\n"
    files.edit_block(policy, "work/bom.txt", "hello", "bye")
    assert target.read_bytes() == b"\xef\xbb\xbfbye\r\n"
