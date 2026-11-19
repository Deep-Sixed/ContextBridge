"""Tool-call counts for the owner dashboard, read from the audit log.

Every tool call, on any listener, starts with one ``requested`` event (see ``computer/audit.py``),
so counting those per UTC day gives calls per day and per month. The log only grows, so the counter
reads what was appended since its last look; if the file shrank or was replaced, it starts over.
"""

from __future__ import annotations

import json
import os
import threading
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

MAX_READ_BYTES = 64 * 1024 * 1024  # per refresh, so one look at a huge log cannot stall the page


class UsageCounter:
    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._days: Counter[str] = Counter()  # "2026-11-19" -> calls
        self._offset = 0
        self._inode: int | None = None

    def _refresh(self) -> None:
        if self.path is None:
            return
        try:
            st = os.stat(self.path)
        except OSError:
            return
        if st.st_ino != self._inode or st.st_size < self._offset:
            self._days.clear()
            self._offset, self._inode = 0, st.st_ino
        if st.st_size == self._offset:
            return
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read(MAX_READ_BYTES)
        except OSError:
            return
        end = chunk.rfind(b"\n") + 1  # a line still being written waits for the next look
        for line in chunk[:end].splitlines():
            if b'"requested"' not in line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and entry.get("event") == "requested" and isinstance(entry.get("ts"), str):
                self._days[entry["ts"][:10]] += 1
        self._offset += end

    def summary(self, today: date | None = None, months: int = 6) -> dict[str, object]:
        """This month's calls, the daily average so far, and the last ``months`` months' totals."""
        today = today or datetime.now(timezone.utc).date()
        with self._lock:
            self._refresh()
            days = dict(self._days)
        month_key = today.strftime("%Y-%m")
        this_month = sum(n for d, n in days.items() if d.startswith(month_key))
        series = []
        year, month = today.year, today.month
        for _ in range(months):
            key = f"{year:04d}-{month:02d}"
            series.append((date(year, month, 1).strftime("%b"), sum(n for d, n in days.items() if d.startswith(key))))
            year, month = (year, month - 1) if month > 1 else (year - 1, 12)
        return {
            "this_month": this_month,
            "daily_average": round(this_month / today.day),
            "since": date(today.year, today.month, 1),
            "today": today,
            "months": list(reversed(series)),
        }
