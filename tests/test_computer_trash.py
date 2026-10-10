"""Native deletion: trash by default, permanent or disabled by policy, with safeguards."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from helpers import symlink_or_skip

from contextbridge.computer.dispatch import Engine, available_tools
from contextbridge.computer.files import FileOperationError, read_file
from contextbridge.computer.policy import TRASH_DIRNAME, PolicyViolation
from contextbridge.computer.trash import delete_file, list_deleted, restore_deleted


@pytest.fixture
def work(workspace: Path) -> Path:
    (workspace / "work" / "notes.txt").write_bytes(b"keep me\n")
    folder = workspace / "work" / "project"
    (folder / "src").mkdir(parents=True)
    (folder / "src" / "main.py").write_bytes(b"print('hi')\n")
    (folder / "README.md").write_bytes(b"# project\n")
    return workspace / "work"


def test_delete_moves_to_trash_and_restores(make_policy, work):
    policy = make_policy()
    result = delete_file(policy, "work/notes.txt")
    assert result["mode"] == "trash" and result["restorable"] and result["type"] == "file"
    assert not (work / "notes.txt").exists()
    trash = work / TRASH_DIRNAME
    assert (trash / result["trash_id"] / "notes.txt").read_bytes() == b"keep me\n"

    listed = list_deleted(policy)
    assert [i["trash_id"] for i in listed["items"]] == [result["trash_id"]]
    assert listed["items"][0]["original_path"] == str(work.resolve() / "notes.txt")
    assert listed["items"][0]["original_exists"] is False

    restored = restore_deleted(policy, result["trash_id"])
    assert restored["restored"] and (work / "notes.txt").read_bytes() == b"keep me\n"
    assert list_deleted(policy)["items"] == []
    assert not (trash / result["trash_id"]).exists()


def test_folders_need_recursive_and_restore_whole(make_policy, work):
    policy = make_policy()
    with pytest.raises(FileOperationError, match="recursive=true"):
        delete_file(policy, "work/project")
    assert (work / "project" / "src" / "main.py").exists()

    result = delete_file(policy, "work/project", recursive=True)
    assert result["type"] == "directory" and result["entries"] == 3
    assert not (work / "project").exists()
    restore_deleted(policy, result["trash_id"])
    assert (work / "project" / "src" / "main.py").read_bytes() == b"print('hi')\n"

    (work / "empty").mkdir()
    assert delete_file(policy, "work/empty")["entries"] == 0  # an empty folder needs no flag


@pytest.mark.parametrize(
    ("target", "error"),
    [
        ("work", "configured root"),  # a writable root itself
        ("docs/notes.md", "outside the writable roots"),  # readable but not writable
        ("../outside.txt", "outside the writable roots"),
        ("work/missing.txt", "No such file"),
    ],
)
def test_delete_refuses_roots_and_paths_outside_writable(make_policy, work, target, error):
    with pytest.raises((PolicyViolation, FileNotFoundError), match=error):
        delete_file(make_policy(), target)


def test_delete_refuses_folders_holding_what_tools_cannot_see(make_policy, work):
    (work / "project" / ".env").write_bytes(b"SECRET=1\n")
    with pytest.raises(PolicyViolation, match=r"contains \.env"):
        delete_file(make_policy(), "work/project", recursive=True)
    assert (work / "project" / ".env").exists() and (work / "project" / "README.md").exists()


def test_trash_is_out_of_reach_of_every_file_tool(make_policy, work):
    policy = make_policy()
    trash_id = delete_file(policy, "work/notes.txt")["trash_id"]
    inside = f"work/{TRASH_DIRNAME}/{trash_id}/notes.txt"
    with pytest.raises(PolicyViolation, match="denied"):
        read_file(policy, inside)
    with pytest.raises(PolicyViolation, match="denied"):
        delete_file(policy, inside)
    with pytest.raises(PolicyViolation, match="denied"):
        delete_file(policy, f"work/{TRASH_DIRNAME}", recursive=True)
    engine = Engine(policy)
    listing = engine.execute("list_directory", {"path": "work"})
    assert TRASH_DIRNAME not in {e["path"] for e in listing["entries"]}


def test_entry_cap_refuses_huge_deletes(make_policy, work):
    policy = make_policy(filesystem={"max_delete_entries": 2})
    with pytest.raises(FileOperationError, match="max_delete_entries"):
        delete_file(policy, "work/project", recursive=True)
    assert (work / "project" / "src" / "main.py").exists()


def test_restore_checks(make_policy, work):
    policy = make_policy()
    trash_id = delete_file(policy, "work/notes.txt")["trash_id"]
    (work / "notes.txt").write_bytes(b"new\n")
    with pytest.raises(FileOperationError, match="exists again"):
        restore_deleted(policy, trash_id)
    with pytest.raises(FileOperationError, match="not a trash id"):
        restore_deleted(policy, "../../etc/passwd")
    with pytest.raises(FileNotFoundError):
        restore_deleted(policy, "20000101T000000Z-00000000")


def test_symlink_is_deleted_not_its_target(make_policy, work):
    link = symlink_or_skip(work / "link.txt", work / "notes.txt")
    result = delete_file(make_policy(), "work/link.txt")
    assert result["type"] == "symlink"
    assert not os.path.lexists(link) and (work / "notes.txt").read_bytes() == b"keep me\n"


def test_nested_writable_roots_use_the_innermost_trash(make_policy, workspace, work):
    inner = work / "project"
    policy = make_policy(filesystem={"writable_roots": [str(work), str(inner)]})
    result = delete_file(policy, "work/project/README.md")
    assert (inner / TRASH_DIRNAME / result["trash_id"] / "README.md").exists()
    assert not (work / TRASH_DIRNAME).exists()


def test_permanent_mode_removes_outright_even_read_only_files(make_policy, work):
    policy = make_policy(filesystem={"delete": "permanent"})
    locked = work / "project" / "src" / "main.py"
    locked.chmod(stat.S_IREAD)
    result = delete_file(policy, "work/project", recursive=True)
    assert result["mode"] == "permanent" and not result["restorable"]
    assert not (work / "project").exists() and not (work / TRASH_DIRNAME).exists()
    tools = available_tools(policy)
    assert "delete_file" in tools and not {"list_deleted", "restore_deleted"} & tools
    with pytest.raises(PolicyViolation, match="no trash"):
        list_deleted(policy)


def test_disabled_mode_and_read_only_policies_have_no_delete(make_policy, workspace, work):
    disabled = make_policy(filesystem={"delete": "disabled"})
    assert not {"delete_file", "list_deleted", "restore_deleted"} & available_tools(disabled)
    with pytest.raises(PolicyViolation, match="disabled"):
        delete_file(disabled, "work/notes.txt")
    with pytest.raises(PolicyViolation, match="not enabled"):
        Engine(disabled).execute("delete_file", {"path": "work/notes.txt"})
    read_only = make_policy(filesystem={"writable_roots": []})
    assert "delete_file" not in available_tools(read_only)
    assert (work / "notes.txt").exists()


def test_restores_what_the_filesystem_route_deleted(make_policy, work):
    """Both routes share one trash layout, so a folder they both serve has one undo history."""
    trash_id = "20261010T010203Z-abcdef12"
    holder = work / TRASH_DIRNAME / trash_id
    holder.mkdir(parents=True)
    (work / "notes.txt").rename(holder / "notes.txt")
    manifest = {"original_path": str(work.resolve() / "notes.txt"), "type": "file", "deleted_at": "2026-10-10T01:02:03Z"}
    (work / TRASH_DIRNAME / f"{trash_id}.json").write_text(json.dumps(manifest), encoding="utf-8")
    policy = make_policy()
    assert [i["trash_id"] for i in list_deleted(policy)["items"]] == [trash_id]
    restore_deleted(policy, trash_id)
    assert (work / "notes.txt").read_bytes() == b"keep me\n"


def test_bad_delete_mode_is_a_config_error():
    from contextbridge.computer.policy import PolicyError, load_policy

    with pytest.raises(PolicyError, match="filesystem.delete"):
        load_policy({"filesystem": {"roots": ["."], "delete": "shred"}})
