from __future__ import annotations

from pathlib import Path

import pytest

from conftest import record, write_jsonl
from uga.adapter import DatacoreRecordError, DatacoreStore


def _store(tmp_path: Path, *records: dict) -> DatacoreStore:
    return DatacoreStore.from_jsonl(write_jsonl(tmp_path / "d.jsonl", list(records)))


def test_unknown_top_level_fields_are_dropped(tmp_path: Path) -> None:
    store = _store(tmp_path, record("r1", status="open", secret_internal="DO-NOT-SHARE"))

    payload = store.fetch_record("r1")

    assert payload["status"] == "open"
    assert "secret_internal" not in payload
    assert store.search_records("DO-NOT-SHARE") == []


def test_search_ignores_json_keys_and_syntax(tmp_path: Path) -> None:
    store = _store(tmp_path, record("r1", metadata={"status": "zqv"}), record("r2"))

    assert store.search_records("status") == []
    assert store.search_records("{") == []
    assert store.search_records('"') == []
    assert [h["id"] for h in store.search_records("zqv")] == ["r1"]


def test_search_matches_non_ascii_values(tmp_path: Path) -> None:
    store = _store(
        tmp_path,
        record("r1", metadata={"owner": "café team"}),
        record("r2", tags=["Größe"]),
    )

    assert [h["id"] for h in store.search_records("café team")] == ["r1"]
    assert [h["id"] for h in store.search_records("größe")] == ["r2"]


def test_falsy_required_values_are_valid(tmp_path: Path) -> None:
    store = _store(tmp_path, record(0, text=""))

    assert store.fetch_record("0")["text"] == ""


@pytest.mark.parametrize(
    "bad",
    [
        record("r1", title=None),
        {k: v for k, v in record("r1").items() if k != "url"},
        record(""),
        record(True),
        record({"nested": 1}),
    ],
)
def test_missing_or_invalid_required_fields_are_rejected(tmp_path: Path, bad: dict) -> None:
    with pytest.raises(DatacoreRecordError, match="line 1"):
        _store(tmp_path, bad)


def test_search_hit_keeps_falsy_values(tmp_path: Path) -> None:
    store = _store(
        tmp_path,
        record("r1", bank_id=0, status=False, metadata={"bank_id": 7, "summary": "from meta"}),
    )

    (hit,) = store.search_records("r1")

    assert hit["bank_id"] == 0
    assert hit["status"] is False
    assert hit["summary"] == "from meta"


def test_empty_query_respects_limit(tmp_path: Path) -> None:
    store = _store(tmp_path, *(record(f"r{i}") for i in range(5)))

    assert len(store.search_records("", limit=2)) == 2
    assert len(store.search_records("")) == 5
    assert store.search_records("", limit=0) == []
