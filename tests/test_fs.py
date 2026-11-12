from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from contextbridge.filesystem.fs import (
    MAX_LIST_DEPTH,
    MAX_MULTI_READ_FILES,
    TRASH_DIR_NAME,
    Filesystem,
    FsError,
    FsLimits,
    FsPathDenied,
    FsRoot,
    filesystem_from_config,
)

# Windows reports a synthesized DOS read/write view in st_mode, not POSIX
# permission bits; NTFS authorization is enforced by ACLs.
WINDOWS = os.name == "nt"


@pytest.fixture
def dirs(tmp_path: Path) -> dict[str, Path]:
    paths = {name: tmp_path / name for name in ("rw", "ro", "outside")}
    for path in paths.values():
        path.mkdir()
    (paths["ro"] / "notes.txt").write_bytes(b"one\ntwo\nthree\n")  # LF on every OS
    (paths["outside"] / "secret.txt").write_text("secret\n", encoding="utf-8")
    return {name: Path(os.path.realpath(path)) for name, path in paths.items()}


def _fs(dirs: dict[str, Path], limits: FsLimits | None = None) -> Filesystem:
    return Filesystem([FsRoot(dirs["rw"], writable=True), FsRoot(dirs["ro"])], limits)


# -- path enforcement -------------------------------------------------------------


def test_relative_and_outside_paths_are_denied(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    for path in [
        "notes.txt",
        str(dirs["outside"] / "secret.txt"),
        str(dirs["ro"] / ".." / "outside" / "secret.txt"),
        str(dirs["ro"] / "missing" / ".." / ".." / "outside" / "secret.txt"),
        str(dirs["ro"]) + "\0x",
    ]:
        with pytest.raises(FsPathDenied):
            fs.read_file(path)


def test_symlink_out_of_a_root_is_denied(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    (dirs["ro"] / "escape").symlink_to(dirs["outside"] / "secret.txt")
    (dirs["rw"] / "escape_dir").symlink_to(dirs["outside"])

    with pytest.raises(FsPathDenied, match="outside the allowed directories"):
        fs.read_file(str(dirs["ro"] / "escape"))
    with pytest.raises(FsPathDenied):
        fs.write_file(str(dirs["rw"] / "escape_dir" / "new.txt"), "x")
    assert not (dirs["outside"] / "new.txt").exists()


def test_symlink_within_roots_is_followed(dirs: dict[str, Path]) -> None:
    (dirs["rw"] / "link.txt").symlink_to(dirs["ro"] / "notes.txt")

    result = _fs(dirs).read_file(str(dirs["rw"] / "link.txt"))

    assert result["path"] == str(dirs["ro"] / "notes.txt")
    assert result["content"] == "one\ntwo\nthree\n"


def test_read_only_root_refuses_every_write(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    notes = str(dirs["ro"] / "notes.txt")
    attempts = [
        lambda: fs.write_file(notes, "x"),
        lambda: fs.write_file(notes, "x", mode="append"),
        lambda: fs.edit_block(notes, "one", "1"),
        lambda: fs.create_directory(str(dirs["ro"] / "sub")),
        lambda: fs.move_file(notes, str(dirs["ro"] / "moved.txt")),
        lambda: fs.move_file(notes, str(dirs["rw"] / "moved.txt")),
        lambda: fs.move_file(str(dirs["rw"]), str(dirs["ro"] / "in")),
        lambda: fs.delete_file(notes),
    ]
    for attempt in attempts:
        with pytest.raises(FsPathDenied):
            attempt()
    assert (dirs["ro"] / "notes.txt").read_text(encoding="utf-8") == "one\ntwo\nthree\n"
    assert sorted(p.name for p in dirs["ro"].iterdir()) == ["notes.txt"]


def test_trash_is_unreachable(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    target = dirs["rw"] / "gone.txt"
    target.write_text("bye\n", encoding="utf-8")
    trash_path = fs.delete_file(str(target))["trash_path"]
    trash = dirs["rw"] / TRASH_DIR_NAME

    for attempt in [
        lambda: fs.read_file(trash_path),
        lambda: fs.list_directory(str(trash)),
        lambda: fs.write_file(str(trash / "x.txt"), "x"),
        lambda: fs.delete_file(str(trash), recursive=True),
        lambda: fs.move_file(trash_path, str(dirs["rw"] / "back.txt")),
        lambda: fs.create_directory(str(trash)),
    ]:
        with pytest.raises(FsPathDenied, match="reserved"):
            attempt()


# -- reading ----------------------------------------------------------------------


def test_read_file_by_lines(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    notes = str(dirs["ro"] / "notes.txt")

    whole = fs.read_file(notes)
    middle = fs.read_file(notes, offset=1, length=1)
    tail = fs.read_file(notes, offset=-2)

    assert (whole["content"], whole["line_count"], whole["has_more"]) == ("one\ntwo\nthree\n", 3, False)
    assert (middle["content"], middle["start_line"], middle["has_more"]) == ("two\n", 1, True)
    assert (tail["content"], tail["start_line"], tail["has_more"]) == ("two\nthree\n", 1, False)
    assert fs.read_file(notes, offset=10)["content"] == ""


def test_read_file_keeps_line_endings(dirs: dict[str, Path]) -> None:
    (dirs["ro"] / "crlf.txt").write_bytes(b"a\r\nb\r\n")

    assert _fs(dirs).read_file(str(dirs["ro"] / "crlf.txt"))["content"] == "a\r\nb\r\n"


def test_read_file_caps_bytes(dirs: dict[str, Path]) -> None:
    (dirs["ro"] / "big.txt").write_bytes(b"x" * 9 + b"\n" + b"y" * 9 + b"\n")
    fs = _fs(dirs, FsLimits(max_read_bytes=15))

    result = fs.read_file(str(dirs["ro"] / "big.txt"))

    assert (result["content"], result["has_more"], result["bytes"]) == ("x" * 9 + "\n", True, 10)
    (dirs["ro"] / "long.txt").write_text("z" * 40, encoding="utf-8")
    with pytest.raises(FsError, match="longer than the 15-byte read limit") as excinfo:
        fs.read_file(str(dirs["ro"] / "long.txt"))
    assert excinfo.value.code == "too_large"


def test_read_file_rejects_non_text_and_non_files(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    (dirs["ro"] / "blob.bin").write_bytes(b"\x89PNG\r\n\x00\x00")
    (dirs["ro"] / "latin1.txt").write_bytes("caf\xe9\n".encode("latin-1"))
    has_fifo = hasattr(os, "mkfifo")  # not on Windows
    if has_fifo:
        os.mkfifo(dirs["ro"] / "pipe")

    for name, code in [
        ("blob.bin", "binary"),
        ("latin1.txt", "binary"),
        *([("pipe", "not_a_file")] if has_fifo else []),
        ("missing.txt", "not_found"),
        ("", "is_a_directory"),
    ]:
        with pytest.raises(FsError) as excinfo:
            fs.read_file(str(dirs["ro"] / name))
        assert excinfo.value.code == code, name


def test_read_multiple_files_reports_errors_per_file(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)

    result = fs.read_multiple_files(
        [str(dirs["ro"] / "notes.txt"), str(dirs["outside"] / "secret.txt"), "relative"]
    )

    good, outside, relative = result["files"]
    assert good["content"] == "one\ntwo\nthree\n"
    assert "outside the allowed directories" in outside["error"]
    assert "must be absolute" in relative["error"]
    with pytest.raises(FsError, match=f"at most {MAX_MULTI_READ_FILES}"):
        fs.read_multiple_files(["/x"] * (MAX_MULTI_READ_FILES + 1))


def test_read_multiple_files_shares_one_byte_budget(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs, FsLimits(max_read_bytes=20))
    notes = str(dirs["ro"] / "notes.txt")

    result = fs.read_multiple_files([notes, notes, notes])

    assert [f.get("line_count") for f in result["files"]] == [3, 1, None]
    assert result["bytes"] == 18
    assert "response size limit" in result["files"][2]["error"]


def test_list_directory_depth_symlinks_and_trash(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    (dirs["rw"] / "a" / "b" / "c").mkdir(parents=True)
    (dirs["rw"] / "a" / "file.txt").write_text("x", encoding="utf-8")
    (dirs["rw"] / "link").symlink_to(dirs["rw"] / "a")
    (dirs["rw"] / TRASH_DIR_NAME).mkdir()

    shallow = fs.list_directory(str(dirs["rw"]), depth=1)
    deep = fs.list_directory(str(dirs["rw"]), depth=3)

    assert shallow["entries"] == [
        {"path": "a", "type": "directory"},
        {"path": "link", "type": "symlink"},
    ]
    assert [e["path"] for e in deep["entries"]] == ["a", "a/b", "a/b/c", "a/file.txt", "link"]
    for depth in (0, MAX_LIST_DEPTH + 1):
        with pytest.raises(FsError, match="depth must be between"):
            fs.list_directory(str(dirs["rw"]), depth=depth)


def test_list_directory_caps_entries(dirs: dict[str, Path]) -> None:
    for i in range(5):
        (dirs["rw"] / f"f{i}").write_text("x", encoding="utf-8")

    result = _fs(dirs, FsLimits(max_list_entries=3)).list_directory(str(dirs["rw"]))

    assert [e["path"] for e in result["entries"]] == ["f0", "f1", "f2"]
    assert result["truncated"] is True


def test_get_file_info(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    (dirs["ro"] / "notes.txt").chmod(0o640)
    (dirs["rw"] / "link").symlink_to(dirs["ro"] / "notes.txt")

    info = fs.get_file_info(str(dirs["ro"] / "notes.txt"))
    via_link = fs.get_file_info(str(dirs["rw"] / "link"))

    assert {k: info[k] for k in ("type", "size", "permissions", "is_symlink", "writable")} == {
        "type": "file",
        "size": 14,
        "permissions": "666" if WINDOWS else "640",
        "is_symlink": False,
        "writable": False,
    }
    assert info["modified"].endswith("Z")
    assert via_link["is_symlink"] is True and via_link["path"] == str(dirs["ro"] / "notes.txt")


# -- writing ----------------------------------------------------------------------


def test_write_file_creates_with_umask_and_appends(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    target = dirs["rw"] / "new.txt"
    umask = os.umask(0o022)
    try:
        assert fs.write_file(str(target), "a\n")["bytes"] == 2
        fs.write_file(str(target), "b\n", mode="append")
    finally:
        os.umask(umask)

    assert target.read_text(encoding="utf-8") == "a\nb\n"
    assert stat.S_IMODE(target.stat().st_mode) == (0o666 if WINDOWS else 0o644)


def test_write_file_rewrite_keeps_permissions_and_leaves_no_temp(dirs: dict[str, Path]) -> None:
    target = dirs["rw"] / "keep.txt"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o600)

    _fs(dirs).write_file(str(target), "new\n")

    assert target.read_text(encoding="utf-8") == "new\n"
    assert stat.S_IMODE(target.stat().st_mode) == (0o666 if WINDOWS else 0o600)
    assert [p.name for p in dirs["rw"].iterdir()] == ["keep.txt"]


def test_write_file_errors(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs, FsLimits(max_write_bytes=4))
    (dirs["rw"] / "sub").mkdir()

    for path, content, code in [
        (dirs["rw"] / "missing" / "x.txt", "x", "not_found"),
        (dirs["rw"] / "sub", "x", "not_a_file"),
        (dirs["rw"] / "big.txt", "12345", "too_large"),
    ]:
        with pytest.raises(FsError) as excinfo:
            fs.write_file(str(path), content)
        assert excinfo.value.code == code
    with pytest.raises(FsError, match="mode must be"):
        fs.write_file(str(dirs["rw"] / "x.txt"), "x", mode="truncate")


def test_edit_block_replaces_exact_text(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    target = dirs["rw"] / "code.py"
    target.write_text("a = 1\nb = 1\n", encoding="utf-8")

    with pytest.raises(FsError, match="expected 1 occurrence.*found 2") as excinfo:
        fs.edit_block(str(target), "= 1", "= 2")
    assert excinfo.value.code == "ambiguous"
    with pytest.raises(FsError, match="not found") as excinfo:
        fs.edit_block(str(target), "c = 1", "c = 2")
    assert excinfo.value.code == "no_match"
    assert target.read_text(encoding="utf-8") == "a = 1\nb = 1\n"

    assert fs.edit_block(str(target), "b = 1", "b = 2")["replacements"] == 1
    assert fs.edit_block(str(target), " = ", "=", expected_replacements=2)["replacements"] == 2
    assert target.read_text(encoding="utf-8") == "a=1\nb=2\n"
    with pytest.raises(FsError, match="must not be empty"):
        fs.edit_block(str(target), "", "x")


def test_create_directory(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    nested = dirs["rw"] / "a" / "b"

    assert fs.create_directory(str(nested))["created"] is True
    assert fs.create_directory(str(nested))["created"] is False
    (dirs["rw"] / "file").write_text("x", encoding="utf-8")
    with pytest.raises(FsError, match="not a directory"):
        fs.create_directory(str(dirs["rw"] / "file"))
    assert nested.is_dir()


def test_move_file(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    (dirs["rw"] / "a.txt").write_text("a", encoding="utf-8")
    (dirs["rw"] / "b.txt").write_text("b", encoding="utf-8")
    (dirs["rw"] / "dir").mkdir()

    fs.move_file(str(dirs["rw"] / "a.txt"), str(dirs["rw"] / "dir" / "c.txt"))

    assert (dirs["rw"] / "dir" / "c.txt").read_text(encoding="utf-8") == "a"
    with pytest.raises(FsError, match="already exists"):
        fs.move_file(str(dirs["rw"] / "b.txt"), str(dirs["rw"] / "dir" / "c.txt"))
    assert (dirs["rw"] / "dir" / "c.txt").read_text(encoding="utf-8") == "a"
    with pytest.raises(FsError, match="into itself"):
        fs.move_file(str(dirs["rw"] / "dir"), str(dirs["rw"] / "dir" / "inner"))
    with pytest.raises(FsError, match="cannot be moved"):
        fs.move_file(str(dirs["rw"]), str(dirs["rw"] / "elsewhere"))
    with pytest.raises(FsError, match="not found"):
        fs.move_file(str(dirs["rw"] / "nope"), str(dirs["rw"] / "x"))


def test_move_file_moves_a_symlink_not_its_target(dirs: dict[str, Path]) -> None:
    (dirs["rw"] / "target.txt").write_text("t", encoding="utf-8")
    (dirs["rw"] / "link").symlink_to(dirs["rw"] / "target.txt")

    _fs(dirs).move_file(str(dirs["rw"] / "link"), str(dirs["rw"] / "renamed"))

    assert (dirs["rw"] / "renamed").is_symlink()
    assert (dirs["rw"] / "target.txt").read_text(encoding="utf-8") == "t"


def test_delete_file_moves_to_trash(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    target = dirs["rw"] / "doc.txt"
    target.write_text("keep me\n", encoding="utf-8")

    result = fs.delete_file(str(target))

    assert not target.exists()
    trash = dirs["rw"] / TRASH_DIR_NAME
    assert Path(result["trash_path"]).read_text(encoding="utf-8") == "keep me\n"
    manifest = json.loads((trash / f"{result['trash_id']}.json").read_text(encoding="utf-8"))
    assert manifest["original_path"] == str(target) and manifest["type"] == "file"
    assert stat.S_IMODE(trash.stat().st_mode) == (0o777 if WINDOWS else 0o700)


def test_delete_directory_needs_recursive(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    (dirs["rw"] / "empty").mkdir()
    (dirs["rw"] / "full").mkdir()
    (dirs["rw"] / "full" / "x.txt").write_text("x", encoding="utf-8")

    fs.delete_file(str(dirs["rw"] / "empty"))
    with pytest.raises(FsError, match="set recursive") as excinfo:
        fs.delete_file(str(dirs["rw"] / "full"))
    assert excinfo.value.code == "not_empty"
    assert (dirs["rw"] / "full" / "x.txt").exists()
    result = fs.delete_file(str(dirs["rw"] / "full"), recursive=True)

    assert result["type"] == "directory"
    assert (Path(result["trash_path"]) / "x.txt").exists()
    assert [p.name for p in dirs["rw"].iterdir()] == [TRASH_DIR_NAME]


def test_delete_symlink_keeps_target_and_root_is_protected(dirs: dict[str, Path]) -> None:
    fs = _fs(dirs)
    (dirs["rw"] / "dir").mkdir()
    (dirs["rw"] / "dir" / "x.txt").write_text("x", encoding="utf-8")
    (dirs["rw"] / "link").symlink_to(dirs["rw"] / "dir")

    assert fs.delete_file(str(dirs["rw"] / "link"), recursive=True)["type"] == "symlink"
    assert (dirs["rw"] / "dir" / "x.txt").exists()
    with pytest.raises(FsError, match="cannot be deleted"):
        fs.delete_file(str(dirs["rw"]), recursive=True)
    with pytest.raises(FsError, match="not found"):
        fs.delete_file(str(dirs["rw"] / "missing"))


# -- configuration ----------------------------------------------------------------


def _config(tmp_path: Path, section: object) -> Filesystem:
    return filesystem_from_config(section, config_path=tmp_path / "configs" / "fs.yaml")


def test_config_builds_roots(tmp_path: Path) -> None:
    (tmp_path / "configs" / "data").mkdir(parents=True)
    (tmp_path / "rw").mkdir()

    fs = _config(
        tmp_path,
        {
            "roots": [{"path": "data"}, {"path": str(tmp_path / "rw"), "writable": True}],
            "max_read_bytes": 10,
        },
    )

    real = Path(os.path.realpath(tmp_path))
    assert fs.roots == (
        FsRoot(real / "configs" / "data", writable=False),
        FsRoot(real / "rw", writable=True),
    )
    assert fs.limits == FsLimits(max_read_bytes=10)
    assert fs.writable is True


@pytest.mark.parametrize(
    ("section", "message"),
    [
        (None, "section is required"),
        ({"roots": []}, "at least one directory"),
        ({"roots": [{"path": "missing"}]}, "directory not found"),
        ({"roots": ["a"]}, "must be a mapping"),
        ({"roots": [{"path": "a", "writeable": True}]}, "unknown key"),
        ({"roots": [{"path": "a", "writable": "yes"}]}, "must be true or false"),
        ({"roots": [{"path": "a"}, {"path": "a/b"}]}, "overlap"),
        ({"roots": [{"path": "a"}], "max_read_bytes": 0}, "positive integer"),
        ({"roots": [{"path": "a"}], "allow_all": True}, "unknown key"),
    ],
)
def test_config_rejects_bad_sections(tmp_path: Path, section: object, message: str) -> None:
    (tmp_path / "configs" / "a" / "b").mkdir(parents=True)

    with pytest.raises(ValueError, match=message):
        _config(tmp_path, section)


def test_read_file_tail_memory_is_bounded(dirs: dict[str, Path]) -> None:
    import tracemalloc

    (dirs["ro"] / "log.txt").write_bytes(b"".join(b"line %07d\n" % i for i in range(400_000)))
    fs = _fs(dirs)
    tracemalloc.start()
    try:
        result = fs.read_file(str(dirs["ro"] / "log.txt"), offset=-1_000_000_000, length=1)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert (result["content"], result["start_line"], result["has_more"]) == ("line 0000000\n", 0, True)
    assert peak < 1_000_000
    last = fs.read_file(str(dirs["ro"] / "log.txt"), offset=-2)
    assert (last["content"], last["start_line"], last["has_more"]) == ("line 0399998\nline 0399999\n", 399_998, False)
