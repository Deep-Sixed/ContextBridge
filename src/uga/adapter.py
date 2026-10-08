"""Read-only Datacore adapter for the Unidirectional Gateway Appliance POC.

Loads approved ``datacore.fetch.v1`` records from a local JSONL file. No database
credentials, no writes, no filesystem paths in tool responses.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
from typing import Any


class DatacoreRecordError(ValueError):
    """Raised when a JSONL record fails validation."""


class DatacoreRecordNotFound(LookupError):
    """Raised when a requested record id is absent."""


_REQUIRED_FIELDS = ("id", "title", "text", "url")
# Approved top-level fields beyond the required ones. Anything else in a JSONL
# record is dropped at load time so it can never reach a client.
_OPTIONAL_TOP_LEVEL_FIELDS = frozenset(
    {
        "canonical_id",
        "bank_id",
        "source",
        "source_table",
        "source_pk",
        "record_kind",
        "fact_type",
        "status",
        "summary",
        "created_at",
        "updated_at",
        "exported_at",
        "document_id",
        "content_hash",
        "tags",
        "entities",
        "links",
        "lifecycle",
        "provenance",
        "related_record_ids",
        "snippet",
    }
)


@dataclass(frozen=True)
class DatacoreFetchRecord:
    id: str
    title: str
    text: str
    url: str
    metadata: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def search_hit(self) -> dict[str, str]:
        hit: dict[str, Any] = {"id": self.id, "title": self.title, "url": self.url}
        for key in ("summary", "snippet", "bank_id", "record_kind", "status", "updated_at"):
            value = self.extra.get(key)
            if value in (None, ""):
                value = self.metadata.get(key)
            if value not in (None, ""):
                hit[key] = value
        return hit

    def fetch_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "text": self.text,
            "url": self.url,
            "metadata": self.metadata,
        }
        payload.update(self.extra)
        return payload


def _validate_record(raw: dict[str, Any], *, line_no: int) -> DatacoreFetchRecord:
    missing = [f for f in _REQUIRED_FIELDS if raw.get(f) is None]
    if missing:
        raise DatacoreRecordError(
            f"line {line_no}: missing required field(s): {', '.join(missing)}"
        )
    record_id = raw["id"]
    if isinstance(record_id, bool) or not isinstance(record_id, (str, int)) or record_id == "":
        raise DatacoreRecordError(f"line {line_no}: id must be a non-empty string or integer")
    metadata = raw.get("metadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise DatacoreRecordError(f"line {line_no}: metadata must be an object")
    extra = {k: v for k, v in raw.items() if k in _OPTIONAL_TOP_LEVEL_FIELDS}
    return DatacoreFetchRecord(
        id=str(record_id),
        title=str(raw["title"]),
        text=str(raw["text"]),
        url=str(raw["url"]),
        metadata=dict(metadata),
        extra=extra,
    )


def load_records(path: Path | str) -> dict[str, DatacoreFetchRecord]:
    """Load and validate all records from a JSONL file."""
    p = Path(path)
    records: dict[str, DatacoreFetchRecord] = {}
    with p.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise DatacoreRecordError(f"line {line_no}: invalid JSON: {exc}") from exc
            if not isinstance(raw, dict):
                raise DatacoreRecordError(f"line {line_no}: record must be a JSON object")
            record = _validate_record(raw, line_no=line_no)
            if record.id in records:
                raise DatacoreRecordError(f"line {line_no}: duplicate id {record.id!r}")
            records[record.id] = record
    return records


def _scalar_values(value: Any) -> Iterator[str]:
    """Yield the scalar values nested in a JSON value, skipping keys and syntax."""
    if isinstance(value, dict):
        for item in value.values():
            yield from _scalar_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _scalar_values(item)
    elif value is not None:
        yield str(value)


def _search_text(record: DatacoreFetchRecord) -> str:
    parts = [record.title, record.text, record.url]
    parts.extend(_scalar_values(record.metadata))
    parts.extend(_scalar_values(record.extra))
    # NUL keeps a query from matching across two adjacent fields.
    return "\0".join(parts).casefold()


class DatacoreStore:
    """In-memory read-only store backed by a JSONL snapshot."""

    def __init__(self, records: dict[str, DatacoreFetchRecord]) -> None:
        self._records = records
        self._search_index = [(_search_text(r), r) for r in records.values()]

    def __len__(self) -> int:
        return len(self._records)

    @classmethod
    def from_jsonl(cls, path: Path | str) -> DatacoreStore:
        return cls(load_records(path))

    def search_records(self, query: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        max_results = None if limit is None else max(0, limit)
        if max_results == 0:
            return []
        needle = (query or "").strip().casefold()
        if needle:
            matches: Iterator[DatacoreFetchRecord] = (
                record for text, record in self._search_index if needle in text
            )
        else:
            matches = iter(self._records.values())
        return [record.search_hit() for record in islice(matches, max_results)]

    def fetch_record(self, record_id: str) -> dict[str, Any]:
        record = self._records.get(record_id)
        if record is None:
            raise DatacoreRecordNotFound(f"Record not found: {record_id}")
        return record.fetch_payload()
