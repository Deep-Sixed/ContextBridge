from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from contextbridge.filesystem import search as fs_search
from contextbridge.filesystem.fs import TRASH_DIR_NAME, Filesystem, FsError, FsLimits, FsPathDenied, FsRoot
from contextbridge.filesystem.search import SearchManager, expand_file_pattern
from contextbridge.filesystem.search_worker import run as run_worker

# Exponential backtracking on a line of a's ending in b: the worker cannot finish
# or check its deadline while matching it, so only killing the process stops it.
HANGING_REGEX = "(a+)+$"
HANGING_LINE = "a" * 40 + "b\n"


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "pkg" / "app.py").write_text(
        "import os\ndef main():\n    return os.getcwd()\n", encoding="utf-8"
    )
    (root / "src" / "pkg" / "util.PY").write_text("def Main_helper():\n    pass\n", encoding="utf-8")
    (root / "README.md").write_bytes(b"# Notes\r\nmain entry point\r\n")
    (root / ".hidden").mkdir()
    (root / ".hidden" / "secret.txt").write_text("main secret\n", encoding="utf-8")
    (root / TRASH_DIR_NAME / "t1").mkdir(parents=True)
    (root / TRASH_DIR_NAME / "t1" / "gone.txt").write_text("main trashed\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "o.txt").write_text("main outside\n", encoding="utf-8")
    (root / "link_dir").symlink_to(outside)
    (root / "link_file.txt").symlink_to(outside / "o.txt")
    return Path(os.path.realpath(root))


def _job(root: Path, **overrides: Any) -> dict[str, Any]:
    job: dict[str, Any] = {
        "start": str(root),
        "skip": [str(root / TRASH_DIR_NAME)],
        "search_type": "content",
        "pattern": "main",
        "literal": False,
        "ignore_case": True,
        "file_globs": [],
        "include_hidden": False,
        "context_lines": 0,
        "max_results": 100,
        "max_file_bytes": 1024 * 1024,
        "max_line_chars": 500,
        "deadline_seconds": 30,
    }
    job.update(overrides)
    return job


def _search(root: Path, **overrides: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    results: list[dict[str, Any]] = []
    summary = run_worker(_job(root, **overrides), lambda m: results.append(m["result"]))
    return results, summary


def _rel(root: Path, results: list[dict[str, Any]]) -> list[str]:
    return [Path(r["path"]).relative_to(root).as_posix() for r in results]


# -- worker: file name search -----------------------------------------------------


def test_files_search_matches_names_substring_or_glob(tree: Path) -> None:
    substring, _ = _search(tree, search_type="files", pattern="APP")
    glob, _ = _search(tree, search_type="files", pattern="*.py")
    case_sensitive, _ = _search(tree, search_type="files", pattern="*.py", ignore_case=False)
    dirs, _ = _search(tree, search_type="files", pattern="pkg")

    assert _rel(tree, substring) == ["src/pkg/app.py"]
    assert _rel(tree, glob) == ["src/pkg/app.py", "src/pkg/util.PY"]
    assert _rel(tree, case_sensitive) == ["src/pkg/app.py"]
    assert dirs == [{"path": str(tree / "src" / "pkg"), "type": "directory"}]


def test_files_search_reports_symlinks_without_following_them(tree: Path) -> None:
    links, _ = _search(tree, search_type="files", pattern="link")
    everything, _ = _search(tree, search_type="files", pattern="*")

    assert links == [
        {"path": str(tree / "link_dir"), "type": "symlink"},
        {"path": str(tree / "link_file.txt"), "type": "symlink"},
    ]
    # link_dir points outside the root; its contents are never listed.
    assert not any("o.txt" in r["path"] for r in everything)


def test_hidden_entries_and_trash(tree: Path) -> None:
    default, _ = _search(tree, search_type="files", pattern="*")
    hidden, _ = _search(tree, search_type="files", pattern="*", include_hidden=True)

    assert not any("/." in r["path"] for r in default)
    assert str(tree / ".hidden" / "secret.txt") in {r["path"] for r in hidden}
    assert not any(TRASH_DIR_NAME in r["path"] for r in hidden)


def test_file_globs_limit_files_and_drop_directories(tree: Path) -> None:
    results, _ = _search(tree, search_type="files", pattern="*", file_globs=["*.md"])

    assert _rel(tree, results) == ["README.md"]


# -- worker: content search -------------------------------------------------------


def test_content_search_lines_context_and_symlinks(tree: Path) -> None:
    results, summary = _search(tree, context_lines=1)

    assert [(r["line"], r["text"], r["before"], r["after"]) for r in results] == [
        (2, "main entry point", ["# Notes"], []),
        (2, "def main():", ["import os"], ["    return os.getcwd()"]),
        (1, "def Main_helper():", [], ["    pass"]),
    ]
    assert _rel(tree, results) == ["README.md", "src/pkg/app.py", "src/pkg/util.PY"]
    # link_file.txt and link_dir point outside the root and are never read.
    assert summary["files_scanned"] == 3


def test_content_search_regex_literal_and_case(tree: Path) -> None:
    regex, _ = _search(tree, pattern=r"def \w+\(")
    literal, _ = _search(tree, pattern="getcwd()", literal=True)
    case_sensitive, _ = _search(tree, pattern="Main", ignore_case=False)

    assert [r["line"] for r in regex] == [2, 1]
    assert [r["text"].strip() for r in literal] == ["return os.getcwd()"]
    assert [r["text"] for r in case_sensitive] == ["def Main_helper():"]


def test_content_search_single_file_and_globs(tree: Path) -> None:
    single, _ = _search(tree, start=str(tree / "README.md"))
    globbed, _ = _search(tree, file_globs=["*.py"])

    assert _rel(tree, single) == ["README.md"]
    assert _rel(tree, globbed) == ["src/pkg/app.py", "src/pkg/util.PY"]


def test_content_search_skips_binary_and_large_files(tree: Path) -> None:
    (tree / "blob.bin").write_bytes(b"main\x00\x01")
    (tree / "big.txt").write_text("main\n" * 100, encoding="utf-8")

    results, summary = _search(tree, max_file_bytes=200)

    assert "blob.bin" not in _rel(tree, results) and "big.txt" not in _rel(tree, results)
    assert summary["skipped"] == {"binary": 1, "too_large": 1, "unreadable": 0}


def test_content_search_truncates_long_lines(tree: Path) -> None:
    (tree / "long.txt").write_text("x" * 50 + "main" + "y" * 50 + "\n", encoding="utf-8")

    results, _ = _search(tree, file_globs=["long.txt"], max_line_chars=20)

    assert results == [{"path": str(tree / "long.txt"), "line": 1, "text": "x" * 20, "truncated": True}]


def test_limit_and_deadline_stop_the_worker(tree: Path) -> None:
    limited, limited_summary = _search(tree, max_results=2)
    _, late_summary = _search(tree, deadline_seconds=0)

    assert len(limited) == 2 and limited_summary["limit_reached"] is True
    assert late_summary["timed_out"] is True and late_summary["result_count"] == 0


def test_expand_file_pattern() -> None:
    assert expand_file_pattern(None) == []
    assert expand_file_pattern("*.py") == ["*.py"]
    assert expand_file_pattern("*.{ts,tsx}|*.md") == ["*.ts", "*.tsx", "*.md"]
    with pytest.raises(FsError, match="empty glob"):
        expand_file_pattern("*.py||")


# -- manager: sessions over real worker processes --------------------------------


@pytest.fixture
def manager(tree: Path) -> SearchManager:
    fs = Filesystem([FsRoot(tree)], FsLimits(max_search_file_bytes=1024 * 1024))
    manager = SearchManager(fs)
    yield manager
    manager.close()


def _wait_finished(manager: SearchManager, search_id: str, timeout: float = 10) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        page = manager.more(search_id)
        if page["status"] != "running" or time.monotonic() > deadline:
            return page
        time.sleep(0.05)


def test_start_returns_first_results_and_pages(tree: Path, manager: SearchManager) -> None:
    first = manager.start(str(tree), "*", search_type="files")
    total = first["total_results"]

    assert first["status"] == "completed" and first["has_more"] is False
    assert first["results"][0]["path"] == str(tree / "README.md")
    page = manager.more(first["search_id"], offset=1, length=2)
    tail = manager.more(first["search_id"], offset=-1)
    assert (page["offset"], len(page["results"]), page["has_more"]) == (1, 2, total > 3)
    assert tail["results"] == first["results"][-1:] and tail["offset"] == total - 1
    assert manager.more(first["search_id"], offset=total + 5)["results"] == []


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"search_type": "names"}, "search_type must be"),
        ({"pattern": ""}, "non-empty"),
        ({"search_type": "content", "pattern": "("}, "invalid regular expression"),
        ({"max_results": 0}, "max_results must be"),
        ({"context_lines": 11}, "context_lines must be"),
        ({"timeout_ms": 10}, "timeout_ms must be"),
        ({"file_pattern": "|"}, "empty glob"),
        ({"path": "README.md"}, "must be absolute"),
    ],
)
def test_start_validates_arguments(
    tree: Path, manager: SearchManager, kwargs: dict[str, Any], message: str
) -> None:
    args: dict[str, Any] = {"path": str(tree), "pattern": "x", **kwargs}

    with pytest.raises(FsError, match=message):
        manager.start(**args)


def test_start_enforces_path_rules(tree: Path, manager: SearchManager) -> None:
    with pytest.raises(FsPathDenied):
        manager.start(str(tree / "link_dir"), "main", search_type="content")
    with pytest.raises(FsPathDenied, match="reserved"):
        manager.start(str(tree / TRASH_DIR_NAME), "main")
    with pytest.raises(FsError, match="not a directory"):
        manager.start(str(tree / "README.md"), "main", search_type="files")
    with pytest.raises(FsError, match="not found"):
        manager.start(str(tree / "missing"), "main")
    # Literal patterns are not compiled as regular expressions.
    assert manager.start(str(tree), "(", search_type="content", literal=True)["status"] == "completed"


def test_stop_kills_a_running_search(tree: Path, manager: SearchManager) -> None:
    (tree / "slow.txt").write_text(HANGING_LINE, encoding="utf-8")
    started = manager.start(str(tree / "slow.txt"), HANGING_REGEX, search_type="content")

    assert started["status"] == "running" and started["has_more"] is True
    stopped = manager.stop(started["search_id"])
    assert stopped["status"] == "cancelled"
    assert manager._sessions[started["search_id"]].proc.poll() is not None
    assert manager.stop(started["search_id"])["status"] == "cancelled"


def test_timeout_kills_a_hung_search(
    tree: Path, manager: SearchManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_search, "KILL_GRACE_SECONDS", 0.2)
    (tree / "slow.txt").write_text(HANGING_LINE, encoding="utf-8")

    started = manager.start(str(tree / "slow.txt"), HANGING_REGEX, search_type="content", timeout_ms=200)

    finished = _wait_finished(manager, started["search_id"])
    assert finished["status"] == "timed_out"
    session = manager._sessions[started["search_id"]]
    assert session.finished.wait(5) and session.proc.poll() is not None


def test_running_searches_are_capped(
    tree: Path, manager: SearchManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_search, "MAX_RUNNING", 1)
    monkeypatch.setattr(fs_search, "INITIAL_WAIT_SECONDS", 0.05)
    (tree / "slow.txt").write_text(HANGING_LINE, encoding="utf-8")
    slow = manager.start(str(tree / "slow.txt"), HANGING_REGEX, search_type="content")

    with pytest.raises(FsError, match="already running") as excinfo:
        manager.start(str(tree), "main")
    assert excinfo.value.code == "busy"
    manager.stop(slow["search_id"])
    restarted = manager.start(str(tree), "main")
    assert _wait_finished(manager, restarted["search_id"])["status"] == "completed"


def test_old_finished_sessions_are_evicted(
    tree: Path, manager: SearchManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_search, "MAX_SESSIONS", 2)
    ids = [manager.start(str(tree), "main")["search_id"] for _ in range(3)]

    with pytest.raises(FsError, match="search not found") as excinfo:
        manager.more(ids[0])
    assert excinfo.value.code == "not_found"
    assert [s["search_id"] for s in manager.list()["searches"]] == ids[1:]


def test_session_byte_budget_stops_the_worker(
    tree: Path, manager: SearchManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_search, "MAX_SESSION_BYTES", 320)

    result = _wait_finished(manager, manager.start(str(tree), "*")["search_id"])

    assert result["status"] == "completed" and result["limit_reached"] is True
    assert 0 < result["total_results"] < 5


def test_list_shows_status_and_pattern(tree: Path, manager: SearchManager) -> None:
    started = manager.start(str(tree), "main" * 30, search_type="content")

    (entry,) = manager.list()["searches"]
    assert entry["search_id"] == started["search_id"]
    assert entry["status"] == "completed"
    assert entry["pattern"] == ("main" * 30)[:80]
    assert entry["started_at"].endswith("Z")


@pytest.mark.parametrize(
    "script",
    [
        "import sys; sys.stdin.read(); sys.exit(3)",
        "import sys; sys.stdin.read(); print('not json')",
        "import sys; sys.stdin.read(); print('{\"error\": \"boom /secret/path\"}')",
    ],
)
def test_broken_worker_marks_search_failed(
    tree: Path,
    manager: SearchManager,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    script: str,
) -> None:
    worker = tmp_path / "broken_worker.py"
    worker.write_text(script, encoding="utf-8")
    monkeypatch.setattr(fs_search, "WORKER", worker)

    result = _wait_finished(manager, manager.start(str(tree), "main")["search_id"])

    assert result["status"] == "failed"
    assert "/secret" not in result["error"]


@pytest.mark.skipif(not hasattr(signal, "alarm"), reason="no SIGALRM on this platform")
def test_orphaned_worker_dies_at_its_hard_deadline(tree: Path) -> None:
    # Run the worker with no server-side kill at all, as if the server had died.
    (tree / "slow.txt").write_text(HANGING_LINE, encoding="utf-8")
    job = _job(
        tree,
        start=str(tree / "slow.txt"),
        pattern=HANGING_REGEX,
        deadline_seconds=0.1,
        hard_deadline_seconds=1,
    )
    proc = subprocess.Popen(
        [sys.executable, "-I", str(fs_search.WORKER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
    )
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(job).encode())
    proc.stdin.close()
    try:
        returncode = proc.wait(timeout=10)
    finally:
        proc.kill()

    assert returncode == -signal.SIGALRM


def test_worker_runs_isolated_from_the_environment(
    tree: Path, manager: SearchManager, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # -I ignores PYTHONPATH, so a planted module cannot shadow the stdlib in the worker.
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "fnmatch.py").write_text("raise SystemExit(9)\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(planted))

    assert manager.start(str(tree), "app")["status"] == "completed"
