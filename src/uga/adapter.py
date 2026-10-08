"""Read-only Datacore adapter for the Unidirectional Gateway Appliance POC.

Loads approved ``datacore.fetch.v1`` records from a local JSONL file. No database
credentials, no writes, no filesystem paths in tool responses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class DatacoreRecordError(ValueError):
    """Raised when a JSONL record fails validation."""


class DatacoreRecordNotFound(LookupError):
    """Raised when a requested record id is absent."""


_REQUIRED_FIELDS = ("id", "title", "text", "url")
_OPTIONAL_TOP_LEVEL_FIELDS = (
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
)


def repo_root() -> Path:
    import os

    nexus_root = (
        os.environ.get("NEXUS_ROOT")
        or os.environ.get("NEXUS_REPO_ROOT")
        or ""
    ).strip()
    if nexus_root:
        return Path(nexus_root).expanduser().resolve()

    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "configs" / "mcp-bridge").exists():
            return parent
    for parent in here.parents:
        if (parent / "pyproject.toml").exists() and (parent / "nexus-agent").exists():
            return parent
    return Path(__file__).resolve().parents[2]


def default_jsonl_path() -> Path:
    """Return the canonical tracked POC JSONL fixture (runtime data/ overrides if present)."""
    root = repo_root()
    runtime = root / "data" / "datacore" / "datacore.fetch.v1.jsonl"
    if runtime.exists():
        return runtime
    return root / "tests" / "fixtures" / "datacore" / "datacore.fetch.v1.jsonl"


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
            value = self.extra.get(key) or self.metadata.get(key)
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
    missing = [f for f in _REQUIRED_FIELDS if not raw.get(f)]
    if missing:
        raise DatacoreRecordError(
            f"line {line_no}: missing required field(s): {', '.join(missing)}"
        )
    metadata = raw.get("metadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise DatacoreRecordError(f"line {line_no}: metadata must be an object")
    extra = {k: v for k, v in raw.items() if k not in {"id", "title", "text", "url", "metadata"}}
    return DatacoreFetchRecord(
        id=str(raw["id"]),
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


class DatacoreStore:
    """In-memory read-only store backed by a JSONL snapshot."""

    def __init__(self, records: dict[str, DatacoreFetchRecord]) -> None:
        self._records = records

    @classmethod
    def from_jsonl(cls, path: Path | str | None = None) -> DatacoreStore:
        resolved = Path(path) if path is not None else default_jsonl_path()
        return cls(load_records(resolved))

    def search_records(self, query: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        max_results = None if limit is None else max(0, limit)
        if max_results == 0:
            return []
        needle = (query or "").strip().casefold()
        if not needle:
            hits = [r.search_hit() for r in self._records.values()]
            return hits if max_results is None else hits[:max_results]
        hits: list[dict[str, Any]] = []
        for record in self._records.values():
            haystacks = (
                record.title,
                record.text,
                record.url,
                json.dumps(record.metadata, sort_keys=True),
                json.dumps(record.extra, sort_keys=True),
            )
            if any(needle in h.casefold() for h in haystacks):
                hits.append(record.search_hit())
                if max_results is not None and len(hits) >= max_results:
                    break
        return hits

    def fetch_record(self, record_id: str) -> dict[str, Any]:
        record = self._records.get(record_id)
        if record is None:
            raise DatacoreRecordNotFound(f"Record not found: {record_id}")
        return record.fetch_payload()
