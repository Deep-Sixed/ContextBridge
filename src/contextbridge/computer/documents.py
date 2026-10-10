"""Document tools: PDF, Word (.docx), and Excel (.xlsx/.xlsm), under the same policy as text files.

* ``read_document``: PDF text by page, Word paragraphs/headings/lists/tables as
  Markdown with an outline, Excel cells by sheet and range (values, or formulas).
  ``find`` searches inside instead of returning everything.
* ``write_document``: create or replace a .docx or .pdf from simple Markdown
  (``#`` headings, ``-`` and ``1.`` lists, ``| a | b |`` tables, paragraphs).
* ``edit_document``: exact text replacement in a .docx, with the same match-count
  check as ``edit_block``.
* ``write_spreadsheet``: write a block of rows into an .xlsx sheet, creating the
  file or sheet if needed. A string starting with ``=`` is stored as a formula.
* ``edit_pdf``: delete, rotate, or insert pages.

Paths go through the policy like every file tool. Documents larger than
``filesystem.max_document_bytes`` are refused, Word and Excel files are checked
for zip bombs before parsing, XML is parsed without entity expansion
(python-docx's parser, and openpyxl with defusedxml), and output is bounded by
``max_read_bytes`` characters, 50 PDF pages, and 10,000 cells per call.
"""

from __future__ import annotations

import datetime as dt
import decimal
import html
import io
import os
import re
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .audit import mark_started
from .files import (
    DOCUMENT_SUFFIXES,
    FileOperationError,
    _atomic_write,
    _require_file,
    _require_parent,
)
from .policy import ComputerPolicy

PDF, DOCX, XLSX, XLSM = ".pdf", ".docx", ".xlsx", ".xlsm"
MAX_UNZIPPED_BYTES = 256 * 1024 * 1024
MAX_PDF_PAGES_PER_READ = 50
MAX_CELLS_PER_READ = 10_000
MAX_CELLS_PER_WRITE = 100_000
_SNIPPET = 160

__all__ = [
    "DOCUMENT_SUFFIXES",
    "edit_document",
    "edit_pdf",
    "read_document",
    "write_document",
    "write_spreadsheet",
]


# ----------------------------------------------------------------- helpers


def _suffix(path: Path) -> str:
    return path.suffix.lower()


def _check_size(policy: ComputerPolicy, path: Path, raw: str) -> None:
    size = path.stat().st_size
    if size > policy.max_document_bytes:
        raise FileOperationError(
            f"{raw} is {size} bytes; documents over {policy.max_document_bytes} bytes "
            "(filesystem.max_document_bytes) are not opened."
        )


def _check_zip(path: Path, raw: str) -> None:
    """Office files are zip archives: refuse corrupt ones and zip bombs before any XML is parsed."""
    try:
        with zipfile.ZipFile(path) as archive:
            unzipped = sum(info.file_size for info in archive.infolist())
    except zipfile.BadZipFile:
        raise FileOperationError(f"{raw} is not a valid Office document (not a zip archive).") from None
    if unzipped > MAX_UNZIPPED_BYTES:
        raise FileOperationError(f"{raw} expands to {unzipped} bytes; refusing to open it.")


def _open_source(policy: ComputerPolicy, raw: str, suffixes: tuple[str, ...], tool: str) -> Path:
    resolved = policy.resolve(raw)
    _require_file(resolved, raw)
    if _suffix(resolved) not in suffixes:
        raise FileOperationError(f"{tool} handles {', '.join(suffixes)} files; {raw} is not one.")
    _check_size(policy, resolved, raw)
    if _suffix(resolved) in (DOCX, XLSX, XLSM):
        _check_zip(resolved, raw)
    return resolved


def _parse_failure(raw: str, kind: str, exc: Exception) -> FileOperationError:
    return FileOperationError(f"{raw} is not a readable {kind} file: {type(exc).__name__}: {exc}"[:500])


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, dt.timedelta):
        return value.total_seconds()
    return str(value)


def _snippet(text: str, index: int, needle: str) -> str:
    start = max(0, index - _SNIPPET // 2)
    return text[start : index + len(needle) + _SNIPPET // 2].replace("\n", " ")


def _find_all(text: str, needle: str) -> Iterator[int]:
    haystack, target = text.casefold(), needle.casefold()
    index = haystack.find(target)
    while index != -1 and target:
        yield index
        index = haystack.find(target, index + len(target))


def parse_pages(spec: str, count: int) -> list[int]:
    """'1-3,5,8-' (1-based, open ranges allowed) -> sorted unique 0-based page indexes."""
    selected: list[int] = []
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "-" in part:
                first, last = part.split("-", 1)
                start, end = int(first or 1), int(last or count)
            else:
                start = end = int(part)
        except ValueError:
            raise FileOperationError(f"pages {spec!r}: use page numbers and ranges like 1-3,5.") from None
        if start < 1 or end > count or start > end:
            raise FileOperationError(f"pages {spec!r} is outside this PDF's {count} pages.")
        selected.extend(range(start - 1, end))
    if not selected:
        raise FileOperationError(f"pages {spec!r} selects no pages.")
    return sorted(set(selected))


def _write_output(resolved: Path, data: bytes) -> bool:
    created = not resolved.exists()
    if created:
        with resolved.open("xb") as fh:
            fh.write(data)
    else:
        _atomic_write(resolved, data)
    return created


def _prepare_output(policy: ComputerPolicy, raw: str, suffixes: tuple[str, ...], tool: str) -> Path:
    resolved = policy.resolve(raw, write=True)
    if _suffix(resolved) not in suffixes:
        raise FileOperationError(f"{tool} writes {', '.join(suffixes)} files; {raw} is not one.")
    if resolved.exists() and not resolved.is_file():
        raise FileOperationError(f"Not a regular file: {raw}")
    _require_parent(resolved, raw)
    return resolved


# ------------------------------------------------------------------ reading


def read_document(
    policy: ComputerPolicy,
    path: str,
    *,
    pages: str | None = None,
    sheet: str | None = None,
    cell_range: str | None = None,
    find: str | None = None,
    formulas: bool = False,
    max_chars: int | None = None,
) -> dict[str, Any]:
    resolved = _open_source(policy, path, DOCUMENT_SUFFIXES, "read_document")
    budget = max(1, min(max_chars or policy.max_read_bytes, policy.max_read_bytes))
    mark_started(path=str(resolved))
    suffix = _suffix(resolved)
    if suffix == PDF:
        return _read_pdf(policy, resolved, path, pages=pages, find=find, budget=budget)
    if suffix == DOCX:
        return _read_docx(policy, resolved, path, find=find, budget=budget)
    return _read_xlsx(
        policy, resolved, path, sheet=sheet, cell_range=cell_range, find=find, formulas=formulas, budget=budget
    )


def _pdf_reader(resolved: Path, raw: str):
    from pypdf import PdfReader

    try:
        reader = PdfReader(str(resolved))
        if reader.is_encrypted and not reader.decrypt(""):
            raise FileOperationError(f"{raw} is an encrypted PDF.")
        len(reader.pages)  # force the page tree to parse here, where failures are reported cleanly
    except FileOperationError:
        raise
    except Exception as exc:  # noqa: BLE001 -- third-party parsers raise anything on malformed input
        raise _parse_failure(raw, "PDF", exc) from None
    return reader


def _read_pdf(policy, resolved, raw, *, pages, find, budget) -> dict[str, Any]:
    reader = _pdf_reader(resolved, raw)
    count = len(reader.pages)
    indexes = parse_pages(pages, count) if pages else list(range(count))
    meta = reader.metadata or {}
    result: dict[str, Any] = {
        "path": str(resolved),
        "type": "pdf",
        "page_count": count,
        "title": _jsonable(meta.get("/Title")),
        "author": _jsonable(meta.get("/Author")),
    }
    if find:
        matches = []
        for index in indexes:
            text = reader.pages[index].extract_text() or ""
            for hit in _find_all(text, find):
                matches.append({"page": index + 1, "snippet": _snippet(text, hit, find)})
                if len(matches) >= policy.max_results:
                    break
            if len(matches) >= policy.max_results:
                break
        return {**result, "find": find, "matches": matches, "truncated": len(matches) >= policy.max_results}
    out, used, truncated = [], 0, len(indexes) > MAX_PDF_PAGES_PER_READ
    for index in indexes[:MAX_PDF_PAGES_PER_READ]:
        text = reader.pages[index].extract_text() or ""
        if used + len(text) > budget:
            text = text[: max(0, budget - used)]
            truncated = True
        used += len(text)
        out.append({"page": index + 1, "text": text})
        if used >= budget:
            break
    return {**result, "pages": out, "truncated": truncated}


def _docx_document(resolved: Path, raw: str):
    from docx import Document

    try:
        return Document(str(resolved))
    except Exception as exc:  # noqa: BLE001 -- third-party parsers raise anything on malformed input
        raise _parse_failure(raw, "Word", exc) from None


def _heading_level(style_name: str) -> int | None:
    if style_name == "Title":
        return 1
    match = re.fullmatch(r"Heading (\d)", style_name)
    return int(match.group(1)) if match else None


def _docx_blocks(doc) -> Iterator[tuple[str, str]]:
    """(kind, markdown) for each top-level paragraph and table, in document order."""
    from docx.table import Table

    for block in doc.iter_inner_content():
        if isinstance(block, Table):
            rows = []
            for row in block.rows:
                cells = [" ".join(p.text for p in cell.paragraphs).replace("|", "\\|").strip() for cell in row.cells]
                rows.append("| " + " | ".join(cells) + " |")
            if rows:
                width = rows[0].count(" | ") + 1
                rows.insert(1, "|" + "---|" * width)
            yield "table", "\n".join(rows)
            continue
        text = block.text
        style = block.style.name if block.style is not None else ""
        level = _heading_level(style)
        if level:
            yield "heading", f"{'#' * level} {text}"
        elif "List Number" in style:
            yield "list", f"1. {text}"
        elif "List" in style or block._p.pPr is not None and block._p.pPr.numPr is not None:
            yield "list", f"- {text}"
        else:
            yield "paragraph", text


def _read_docx(policy, resolved, raw, *, find, budget) -> dict[str, Any]:
    doc = _docx_document(resolved, raw)
    blocks = list(_docx_blocks(doc))
    outline = [
        {"level": len(md) - len(md.lstrip("#")), "text": md.lstrip("#").strip()}
        for kind, md in blocks
        if kind == "heading"
    ]
    result: dict[str, Any] = {
        "path": str(resolved),
        "type": "docx",
        "title": doc.core_properties.title or None,
        "paragraphs": sum(1 for kind, _ in blocks if kind != "table"),
        "tables": sum(1 for kind, _ in blocks if kind == "table"),
        "outline": outline[: policy.max_results],
    }
    if find:
        matches = []
        for number, (_, md) in enumerate(blocks, start=1):
            for hit in _find_all(md, find):
                matches.append({"block": number, "snippet": _snippet(md, hit, find)})
            if len(matches) >= policy.max_results:
                break
        matches = matches[: policy.max_results]
        return {**result, "find": find, "matches": matches, "truncated": len(matches) >= policy.max_results}
    content, truncated = "\n\n".join(md for _, md in blocks), False
    if len(content) > budget:
        content, truncated = content[:budget], True
    return {**result, "content": content, "truncated": truncated}


def _read_xlsx(policy, resolved, raw, *, sheet, cell_range, find, formulas, budget) -> dict[str, Any]:
    from openpyxl import load_workbook
    from openpyxl.utils.cell import get_column_letter, range_boundaries

    try:
        wb = load_workbook(str(resolved), read_only=True, data_only=not formulas, keep_links=False)
    except Exception as exc:  # noqa: BLE001 -- third-party parsers raise anything on malformed input
        raise _parse_failure(raw, "Excel", exc) from None
    try:
        names = wb.sheetnames
        if sheet is not None and sheet not in names:
            raise FileOperationError(f"{raw} has no sheet {sheet!r}; sheets: {', '.join(names)}.")
        result: dict[str, Any] = {"path": str(resolved), "type": "xlsx", "sheets": names}
        if find:
            matches = []
            for name in [sheet] if sheet else names:
                for row in wb[name].iter_rows():
                    for cell in row:
                        value = getattr(cell, "value", None)
                        if value is not None and find.casefold() in str(value).casefold():
                            matches.append({"sheet": name, "cell": cell.coordinate, "value": _jsonable(value)})
                            if len(matches) >= policy.max_results:
                                return {**result, "find": find, "matches": matches, "truncated": True}
            return {**result, "find": find, "matches": matches, "truncated": False}

        ws = wb[sheet] if sheet else wb[names[0]]
        if cell_range:
            try:
                min_col, min_row, max_col, max_row = range_boundaries(cell_range.upper())
            except ValueError:
                raise FileOperationError(f"cell_range {cell_range!r}: use A1 notation like B2:F40.") from None
        else:
            min_col = min_row = 1
            max_col, max_row = ws.max_column or 1, ws.max_row or 1
        min_col, min_row = min_col or 1, min_row or 1
        max_col = max_col or (ws.max_column or min_col)
        max_row = max_row or (ws.max_row or min_row)
        width = max(1, max_col - min_col + 1)
        row_cap = max(1, MAX_CELLS_PER_READ // width)
        rows, used, truncated = [], 0, max_row - min_row + 1 > row_cap
        for row in ws.iter_rows(
            min_row=min_row, max_row=min(max_row, min_row + row_cap - 1), min_col=min_col, max_col=max_col, values_only=True
        ):
            values = [_jsonable(v) for v in row]
            used += sum(len(str(v)) for v in values if v is not None)
            if used > budget:
                truncated = True
                break
            rows.append(values)
        last_row = min_row + max(len(rows), 1) - 1
        return {
            **result,
            "sheet": ws.title,
            "range": f"{get_column_letter(min_col)}{min_row}:{get_column_letter(max_col)}{last_row}",
            "formulas": formulas,
            "rows": rows,
            "truncated": truncated,
        }
    finally:
        wb.close()  # read-only workbooks hold the file open (and locked, on Windows)


# ------------------------------------------------------------------ writing


def _markdown_blocks(text: str) -> list[tuple[str, int, Any]]:
    """Parse the Markdown subset write_document understands into (kind, level, value) blocks."""
    blocks: list[tuple[str, int, Any]] = []
    paragraph: list[str] = []
    table: list[list[str]] = []

    def flush() -> None:
        if paragraph:
            blocks.append(("paragraph", 0, " ".join(paragraph)))
            paragraph.clear()
        if table:
            blocks.append(("table", 0, [row[:] for row in table]))
            table.clear()

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|") and len(stripped) > 1:
            if paragraph:
                blocks.append(("paragraph", 0, " ".join(paragraph)))
                paragraph.clear()
            cells = [c.strip() for c in stripped[1:-1].split("|")]
            if not all(re.fullmatch(r":?-{2,}:?", c) for c in cells):  # skip |---|---| separators
                table.append(cells)
            continue
        if table:
            blocks.append(("table", 0, [row[:] for row in table]))
            table.clear()
        if not stripped:
            flush()
        elif heading := re.match(r"^(#{1,6})\s+(.*)$", stripped):
            flush()
            blocks.append(("heading", len(heading.group(1)), heading.group(2)))
        elif bullet := re.match(r"^[-*+]\s+(.*)$", stripped):
            flush()
            blocks.append(("bullet", 0, bullet.group(1)))
        elif number := re.match(r"^\d+[.)]\s+(.*)$", stripped):
            flush()
            blocks.append(("number", 0, number.group(1)))
        else:
            paragraph.append(stripped)
    flush()
    return blocks


def _docx_bytes(blocks: list[tuple[str, int, Any]], title: str | None) -> bytes:
    from docx import Document

    doc = Document()
    if title:
        doc.core_properties.title = title
    for kind, level, value in blocks:
        if kind == "heading":
            doc.add_heading(value, level=level)
        elif kind == "bullet":
            doc.add_paragraph(value, style="List Bullet")
        elif kind == "number":
            doc.add_paragraph(value, style="List Number")
        elif kind == "table":
            width = max(len(row) for row in value)
            table = doc.add_table(rows=len(value), cols=width)
            table.style = "Table Grid"
            for r, row in enumerate(value):
                for c, text in enumerate(row):
                    table.cell(r, c).text = text
        else:
            doc.add_paragraph(value)
    buffer = io.BytesIO()
    doc.save(buffer)
    return buffer.getvalue()


_FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "segoeui.ttf"),
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "arial.ttf"),
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/Library/Fonts/Arial.ttf",
)
_pdf_font: str | None = None


def _unicode_font() -> str:
    """A TrueType font with broad Unicode coverage if the machine has one; Helvetica (Latin-1) otherwise."""
    global _pdf_font
    if _pdf_font is None:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        _pdf_font = "Helvetica"
        for candidate in _FONT_CANDIDATES:
            if os.path.isfile(candidate):
                try:
                    pdfmetrics.registerFont(TTFont("ContextBridgeSans", candidate))
                except Exception:  # noqa: BLE001,S112 -- an unusable font file: try the next one
                    continue
                _pdf_font = "ContextBridgeSans"
                break
    return _pdf_font


def _pdf_bytes(blocks: list[tuple[str, int, Any]], title: str | None) -> tuple[bytes, str]:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        ListFlowable,
        ListItem,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    font = _unicode_font()
    sheet = getSampleStyleSheet()
    styles = {name: ParagraphStyle(name, parent=sheet[name], fontName=font) for name in ("BodyText", "Heading1", "Heading2", "Heading3", "Heading4", "Heading5", "Heading6")}

    def para(text: str, style: str = "BodyText") -> Paragraph:
        return Paragraph(html.escape(text), styles[style])

    story: list[Any] = []
    pending: list[tuple[str, str]] = []  # consecutive list items, flushed as one list

    def flush_list() -> None:
        if pending:
            kind = pending[0][0]
            items = [ListItem(para(text)) for _, text in pending]
            story.append(ListFlowable(items, bulletType="bullet" if kind == "bullet" else "1", leftIndent=14))
            pending.clear()

    for kind, level, value in blocks:
        if kind in ("bullet", "number"):
            if pending and pending[0][0] != kind:
                flush_list()
            pending.append((kind, value))
            continue
        flush_list()
        if kind == "heading":
            story.append(para(value, f"Heading{min(level, 6)}"))
        elif kind == "table":
            width = max(len(row) for row in value)
            rows = [[para(text) for text in row + [""] * (width - len(row))] for row in value]
            table = Table(rows, repeatRows=1)
            table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story.append(table)
            story.append(Spacer(1, 6))
        else:
            story.append(para(value))
    flush_list()
    if not story:
        story.append(Spacer(1, 1))
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title=title or "", author="ContextBridge", invariant=1)
    doc.build(story)
    return buffer.getvalue(), font


def write_document(policy: ComputerPolicy, path: str, content: str, *, title: str | None = None) -> dict[str, Any]:
    resolved = _prepare_output(policy, path, (DOCX, PDF), "write_document")
    if len(content.encode("utf-8")) > policy.max_write_bytes:
        raise FileOperationError(f"content exceeds max_write_bytes ({policy.max_write_bytes}).")
    blocks = _markdown_blocks(content)
    extra: dict[str, Any] = {}
    if _suffix(resolved) == DOCX:
        data = _docx_bytes(blocks, title)
    else:
        data, extra["font"] = _pdf_bytes(blocks, title)
    mark_started(path=str(resolved), bytes=len(data))
    created = _write_output(resolved, data)
    return {
        "path": str(resolved),
        "type": _suffix(resolved).lstrip("."),
        "bytes_written": len(data),
        "blocks": len(blocks),
        "created": created,
        **extra,
    }


def _docx_paragraphs(doc) -> Iterator[Any]:
    """Every paragraph: body, table cells (nested, merged cells once), headers, and footers."""
    seen: set[int] = set()

    def from_tables(tables) -> Iterator[Any]:
        for table in tables:
            for row in table.rows:
                for cell in row.cells:
                    if id(cell._tc) in seen:
                        continue
                    seen.add(id(cell._tc))
                    yield from cell.paragraphs
                    yield from from_tables(cell.tables)

    yield from doc.paragraphs
    yield from from_tables(doc.tables)
    for section in doc.sections:
        for part in (section.header, section.footer):
            if part.is_linked_to_previous:
                continue
            yield from part.paragraphs
            yield from from_tables(part.tables)


def edit_document(
    policy: ComputerPolicy, path: str, old_text: str, new_text: str, *, expected_replacements: int = 1
) -> dict[str, Any]:
    if not old_text:
        raise FileOperationError("old_text must not be empty.")
    if expected_replacements < 1:
        raise FileOperationError("expected_replacements must be at least 1.")
    resolved = policy.resolve(path, write=True)
    _require_file(resolved, path)
    if _suffix(resolved) != DOCX:
        raise FileOperationError(
            "edit_document edits .docx files; use write_spreadsheet for Excel and edit_pdf for PDF pages."
        )
    _check_size(policy, resolved, path)
    _check_zip(resolved, path)
    doc = _docx_document(resolved, path)
    paragraphs = list(_docx_paragraphs(doc))
    # Text in hyperlinks and fields is outside paragraph runs; only run text is matched and edited.
    found = sum("".join(r.text for r in p.runs).count(old_text) for p in paragraphs)
    if found != expected_replacements:
        raise FileOperationError(
            f"Expected {expected_replacements} occurrence(s) of old_text in {path}, found {found}."
        )
    mark_started(path=str(resolved), replacements=found)
    formatting_kept = True
    for paragraph in paragraphs:
        runs = paragraph.runs
        joined = "".join(r.text for r in runs)
        if old_text not in joined:
            continue
        if sum(r.text.count(old_text) for r in runs) == joined.count(old_text):
            for run in runs:  # every match sits inside one run: formatting is untouched
                run.text = run.text.replace(old_text, new_text)
        else:  # a match spans runs: the paragraph keeps its first run's formatting
            runs[0].text = joined.replace(old_text, new_text)
            for run in runs[1:]:
                run.text = ""
            formatting_kept = False
    buffer = io.BytesIO()
    doc.save(buffer)
    _atomic_write(resolved, buffer.getvalue())
    return {"path": str(resolved), "replacements": found, "formatting_kept": formatting_kept}


def write_spreadsheet(
    policy: ComputerPolicy,
    path: str,
    rows: list[list[Any]],
    *,
    sheet: str | None = None,
    start_cell: str = "A1",
) -> dict[str, Any]:
    from openpyxl import Workbook, load_workbook
    from openpyxl.utils.cell import (
        column_index_from_string,
        coordinate_from_string,
        get_column_letter,
    )

    resolved = _prepare_output(policy, path, (XLSX, XLSM), "write_spreadsheet")
    cells = sum(len(row) for row in rows)
    if not rows or not cells:
        raise FileOperationError("rows must contain at least one value.")
    if cells > MAX_CELLS_PER_WRITE:
        raise FileOperationError(f"{cells} cells is more than one call may write ({MAX_CELLS_PER_WRITE}).")
    try:
        column_letter, first_row = coordinate_from_string(start_cell.upper())
        first_col = column_index_from_string(column_letter)
    except ValueError:
        raise FileOperationError(f"start_cell {start_cell!r}: use A1 notation like B2.") from None

    created = not resolved.exists()
    if created:
        if _suffix(resolved) == XLSM:
            raise FileOperationError("New workbooks must be .xlsx; existing .xlsm files can be edited.")
        wb = Workbook()
        wb.active.title = sheet or "Sheet1"
    else:
        _check_size(policy, resolved, path)
        _check_zip(resolved, path)
        try:
            wb = load_workbook(str(resolved), keep_vba=_suffix(resolved) == XLSM, keep_links=True)
        except Exception as exc:  # noqa: BLE001 -- third-party parsers raise anything on malformed input
            raise _parse_failure(path, "Excel", exc) from None
    sheet_created = bool(sheet) and sheet not in wb.sheetnames
    ws = wb.create_sheet(sheet) if sheet_created else (wb[sheet] if sheet else wb.active)
    width = max(len(row) for row in rows)
    for r, values in enumerate(rows):
        for c, value in enumerate(values):
            ws.cell(row=first_row + r, column=first_col + c, value=value)
    last = f"{get_column_letter(first_col + width - 1)}{first_row + len(rows) - 1}"
    buffer = io.BytesIO()
    wb.save(buffer)
    data = buffer.getvalue()
    mark_started(path=str(resolved), sheet=ws.title, cells=cells)
    _write_output(resolved, data)
    return {
        "path": str(resolved),
        "sheet": ws.title,
        "range": f"{get_column_letter(first_col)}{first_row}:{last}",
        "cells_written": cells,
        "created": created,
        "sheet_created": sheet_created or created,
    }


def edit_pdf(
    policy: ComputerPolicy,
    path: str,
    *,
    delete_pages: str | None = None,
    rotate_pages: str | None = None,
    rotate_degrees: int = 90,
    insert_pdf: str | None = None,
    insert_at: int | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    from pypdf import PdfWriter

    if not (delete_pages or rotate_pages or insert_pdf):
        raise FileOperationError("Nothing to do: give delete_pages, rotate_pages, or insert_pdf.")
    if rotate_degrees % 90:
        raise FileOperationError("rotate_degrees must be a multiple of 90.")
    source = _open_source(policy, path, (PDF,), "edit_pdf")
    target = _prepare_output(policy, output_path or path, (PDF,), "edit_pdf")
    reader = _pdf_reader(source, path)
    count = len(reader.pages)
    deleted = set(parse_pages(delete_pages, count)) if delete_pages else set()
    rotated = set(parse_pages(rotate_pages, count)) if rotate_pages else set()
    writer = PdfWriter()
    for index, page in enumerate(reader.pages):
        if index in deleted:
            continue
        if index in rotated:
            page.rotate(rotate_degrees)
        writer.add_page(page)
    inserted = 0
    if insert_pdf:
        other = _pdf_reader(_open_source(policy, insert_pdf, (PDF,), "edit_pdf"), insert_pdf)
        position = len(writer.pages) if insert_at is None else max(0, min(insert_at - 1, len(writer.pages)))
        for offset, page in enumerate(other.pages):
            writer.insert_page(page, index=position + offset)
            inserted += 1
    if not len(writer.pages):
        raise FileOperationError("That would leave the PDF with no pages.")
    buffer = io.BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()
    mark_started(path=str(target), source=str(source), pages=len(writer.pages))
    created = _write_output(target, data)
    return {
        "path": str(target),
        "source": str(source),
        "pages_before": count,
        "pages_after": len(writer.pages),
        "deleted": len(deleted),
        "rotated": len(rotated),
        "inserted": inserted,
        "created": created,
    }
