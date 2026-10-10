"""Document tools: PDF, Word, and Excel through the computer policy."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from contextbridge.computer import documents
from contextbridge.computer.dispatch import (
    DOCUMENT_READ_TOOLS,
    DOCUMENT_WRITE_TOOLS,
    Engine,
    InvalidArguments,
)
from contextbridge.computer.documents import (
    edit_document,
    edit_pdf,
    parse_pages,
    read_document,
    write_document,
    write_spreadsheet,
)
from contextbridge.computer.files import FileOperationError, read_file
from contextbridge.computer.policy import PolicyViolation

REPORT = """# Quarterly report

Revenue grew in every region.

## Highlights

- Friday migrated to ContextBridge
- Thanatos enrolled as a device

1. Plan
2. Ship

| Region | Revenue |
|---|---|
| North | 120 |
| South | 95 |
"""


@pytest.fixture
def policy(make_policy):
    return make_policy()


def test_docx_round_trip(policy, workspace):
    written = write_document(policy, "work/report.docx", REPORT, title="Q3")
    assert written["created"] and written["type"] == "docx"
    doc = read_document(policy, "work/report.docx")
    assert doc["title"] == "Q3" and doc["tables"] == 1
    assert doc["outline"] == [{"level": 1, "text": "Quarterly report"}, {"level": 2, "text": "Highlights"}]
    content = doc["content"]
    for expected in ("# Quarterly report", "## Highlights", "- Friday migrated to ContextBridge", "1. Plan",
                     "| North | 120 |", "Revenue grew in every region."):
        assert expected in content, expected
    hits = read_document(policy, "work/report.docx", find="thanatos")["matches"]
    assert len(hits) == 1 and "Thanatos enrolled" in hits[0]["snippet"]


def test_docx_edit_keeps_formatting_within_a_run(policy, workspace):
    from docx import Document

    doc = Document()
    para = doc.add_paragraph()
    para.add_run("Status: ")
    para.add_run("pending").bold = True
    split = doc.add_paragraph()
    split.add_run("Ow")
    split.add_run("ner: Friday")
    table = doc.add_table(rows=1, cols=1)
    table.cell(0, 0).text = "pending review"
    doc.sections[0].header.paragraphs[0].text = "Header pending"
    doc.save(workspace / "work" / "status.docx")

    with pytest.raises(FileOperationError, match="found 3"):
        edit_document(policy, "work/status.docx", "pending", "done")
    result = edit_document(policy, "work/status.docx", "pending", "done", expected_replacements=3)
    assert result["replacements"] == 3 and result["formatting_kept"] is True
    reread = Document(workspace / "work" / "status.docx")
    assert reread.paragraphs[0].runs[1].text == "done" and reread.paragraphs[0].runs[1].bold
    assert reread.tables[0].cell(0, 0).text == "done review"
    assert reread.sections[0].header.paragraphs[0].text == "Header done"

    spanning = edit_document(policy, "work/status.docx", "Owner", "Keeper")
    assert spanning["formatting_kept"] is False
    assert Document(workspace / "work" / "status.docx").paragraphs[1].text == "Keeper: Friday"


def test_pdf_create_read_find_and_edit(policy, workspace):
    write_document(policy, "work/a.pdf", "# Part A\n\nAlpha page with Grüße.", title="A")
    write_document(policy, "work/b.pdf", "# Part B\n\nBeta page.")
    first = read_document(policy, "work/a.pdf")
    assert first["page_count"] == 1 and first["title"] == "A"
    assert "Alpha page with Grüße." in first["pages"][0]["text"]

    merged = edit_pdf(policy, "work/a.pdf", insert_pdf="work/b.pdf", output_path="work/merged.pdf")
    assert merged["pages_before"] == 1 and merged["pages_after"] == 2 and merged["created"]
    pages = read_document(policy, "work/merged.pdf", pages="2")["pages"]
    assert [p["page"] for p in pages] == [2] and "Beta page." in pages[0]["text"]
    assert read_document(policy, "work/merged.pdf", find="beta")["matches"][0]["page"] == 2

    edit_pdf(policy, "work/merged.pdf", insert_pdf="work/b.pdf", insert_at=1)  # B, A, B
    trimmed = edit_pdf(policy, "work/merged.pdf", delete_pages="3", rotate_pages="1", rotate_degrees=180)
    assert trimmed["pages_after"] == 2 and trimmed["rotated"] == 1
    texts = [p["text"] for p in read_document(policy, "work/merged.pdf")["pages"]]
    assert "Beta" in texts[0] and "Alpha" in texts[1]

    with pytest.raises(FileOperationError, match="no pages"):
        edit_pdf(policy, "work/a.pdf", delete_pages="1")
    with pytest.raises(FileOperationError, match="Nothing to do"):
        edit_pdf(policy, "work/a.pdf")
    with pytest.raises(FileOperationError, match="multiple of 90"):
        edit_pdf(policy, "work/a.pdf", rotate_pages="1", rotate_degrees=45)


def test_page_specs():
    assert parse_pages("1-3,5", 6) == [0, 1, 2, 4]
    assert parse_pages("4-", 6) == [3, 4, 5]
    assert parse_pages("2,2,1", 3) == [0, 1]
    for bad in ("0", "7", "3-1", "x", ","):
        with pytest.raises(FileOperationError):
            parse_pages(bad, 6)


def test_spreadsheet_write_read_formulas_and_find(policy, workspace):
    first = write_spreadsheet(policy, "work/data.xlsx", [["item", "qty"], ["bolts", 4], ["nuts", 6]], sheet="Stock")
    assert first["created"] and first["range"] == "A1:B3" and first["sheet"] == "Stock"
    total = write_spreadsheet(policy, "work/data.xlsx", [["=SUM(B2:B3)"]], sheet="Stock", start_cell="B4")
    assert total["range"] == "B4:B4" and not total["created"]
    other = write_spreadsheet(policy, "work/data.xlsx", [["owner", "Friday"]], sheet="Meta")
    assert other["sheet_created"] is True

    book = read_document(policy, "work/data.xlsx", sheet="Stock")
    assert book["sheets"] == ["Stock", "Meta"]
    assert book["rows"][:3] == [["item", "qty"], ["bolts", 4], ["nuts", 6]]
    assert book["rows"][3] == [None, None]  # a formula's value is unknown until Excel calculates it
    formulas = read_document(policy, "work/data.xlsx", sheet="Stock", cell_range="B4:B4", formulas=True)
    assert formulas["rows"] == [["=SUM(B2:B3)"]] and formulas["range"] == "B4:B4"
    hits = read_document(policy, "work/data.xlsx", find="friday")["matches"]
    assert hits == [{"sheet": "Meta", "cell": "B1", "value": "Friday"}]
    with pytest.raises(FileOperationError, match="no sheet"):
        read_document(policy, "work/data.xlsx", sheet="Nope")
    with pytest.raises(FileOperationError, match="must be .xlsx"):
        write_spreadsheet(policy, "work/new.xlsm", [["x"]])


def test_documents_obey_the_policy(make_policy, workspace):
    policy = make_policy()
    write_document(policy, "work/r.docx", "hello")
    with pytest.raises(PolicyViolation, match="writable"):
        write_document(policy, "docs/r.docx", "hello")  # docs/ is readable, not writable
    (workspace / ".ssh" / "keys.pdf").write_bytes(b"%PDF-1.4")
    with pytest.raises(PolicyViolation, match="denied"):
        read_document(policy, ".ssh/keys.pdf")
    with pytest.raises(FileOperationError, match="read_document"):
        read_file(policy, "work/r.docx")  # read_file points to the right tool
    with pytest.raises(FileOperationError, match="handles"):
        read_document(policy, "docs/notes.md")

    tiny = make_policy(filesystem={"max_document_bytes": 100})
    with pytest.raises(FileOperationError, match="max_document_bytes"):
        read_document(tiny, "work/r.docx")


def test_corrupt_and_oversized_archives_are_refused(policy, workspace, monkeypatch):
    (workspace / "work" / "broken.pdf").write_bytes(b"%PDF-1.7 this is not really a pdf")
    with pytest.raises(FileOperationError, match="not a readable PDF"):
        read_document(policy, "work/broken.pdf")
    (workspace / "work" / "broken.docx").write_bytes(b"not a zip")
    with pytest.raises(FileOperationError, match="not a zip"):
        read_document(policy, "work/broken.docx")
    write_document(policy, "work/ok.docx", "hello")
    monkeypatch.setattr(documents, "MAX_UNZIPPED_BYTES", 1000)
    with pytest.raises(FileOperationError, match="expands to"):
        read_document(policy, "work/ok.docx")


def test_engine_surface_and_argument_validation(policy, workspace):
    engine = Engine(policy)
    assert DOCUMENT_READ_TOOLS | DOCUMENT_WRITE_TOOLS <= engine.tools
    with pytest.raises(InvalidArguments, match="rows"):
        engine.execute("write_spreadsheet", {"path": "work/x.xlsx", "rows": [[{"nested": 1}]]})
    result = engine.execute("write_spreadsheet", {"path": "work/x.xlsx", "rows": [[1, "two", True, None]]})
    assert result["cells_written"] == 4
    read_only = Engine(policy.__class__(roots=policy.roots))
    assert DOCUMENT_READ_TOOLS <= read_only.tools and not DOCUMENT_WRITE_TOOLS & read_only.tools


def test_written_pdf_is_a_real_pdf(policy, workspace):
    from pypdf import PdfReader

    write_document(policy, "work/r.pdf", REPORT)
    reader = PdfReader(io.BytesIO((workspace / "work" / "r.pdf").read_bytes()))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "Quarterly report" in text and "Region" in text and "North" in text
    assert Path(workspace / "work" / "r.pdf").read_bytes().startswith(b"%PDF-")
