"""Fonts, palette, and flowable helpers shared by the docs/ PDF generators.

Requires reportlab (pip install -e '.[docs]') and the DejaVu Sans fonts. Fonts are
looked up under the usual system font directories, or under CONTEXTBRIDGE_FONT_DIR.
"""
import os
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import ListFlowable, ListItem, Paragraph, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parent.parent
FONT_DIRS = [
    os.environ.get("CONTEXTBRIDGE_FONT_DIR"),
    "/usr/share/fonts",
    "/usr/local/share/fonts",
    "~/.local/share/fonts",
    "~/Library/Fonts",
    "/Library/Fonts",
]
FONTS = {"Sans": "DejaVuSans.ttf", "Sans-Bold": "DejaVuSans-Bold.ttf", "Mono": "DejaVuSansMono.ttf"}


def find_font(filename):
    for d in FONT_DIRS:
        if not d:
            continue
        base = Path(d).expanduser()
        if not base.is_dir():
            continue
        match = next(base.rglob(filename), None)
        if match:
            return match
    sys.exit(f"font {filename} not found; install DejaVu fonts or set CONTEXTBRIDGE_FONT_DIR")


def register_fonts():
    for name, filename in FONTS.items():
        pdfmetrics.registerFont(TTFont(name, str(find_font(filename))))
    pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-Bold", italic="Sans", boldItalic="Sans-Bold")


INK = colors.HexColor("#1f2933")
MUTED = colors.HexColor("#52606d")
ACCENT = colors.HexColor("#1d4e89")
RULE = colors.HexColor("#cbd2d9")
HEAD_BG = colors.HexColor("#e4ebf5")
ZEBRA = colors.HexColor("#f5f7fa")
NOTE_BG = colors.HexColor("#fff8e6")
NOTE_BORDER = colors.HexColor("#e0b84c")
KEY_BG = colors.HexColor("#eaf4ec")
KEY_BORDER = colors.HexColor("#5a9e6f")

title = ParagraphStyle("title", fontName="Sans-Bold", fontSize=20, leading=25, textColor=INK, spaceAfter=4)
subtitle = ParagraphStyle("subtitle", fontName="Sans", fontSize=10.5, leading=15, textColor=MUTED, spaceAfter=14)
h1 = ParagraphStyle("h1", fontName="Sans-Bold", fontSize=13.5, leading=18, textColor=ACCENT, spaceBefore=14, spaceAfter=6, keepWithNext=1)
h2 = ParagraphStyle("h2", fontName="Sans-Bold", fontSize=10.5, leading=14, textColor=INK, spaceBefore=8, spaceAfter=3, keepWithNext=1)
body = ParagraphStyle("body", fontName="Sans", fontSize=9.5, leading=13.5, textColor=INK, spaceAfter=6, alignment=TA_LEFT)
cell = ParagraphStyle("cell", parent=body, fontSize=9, leading=12, spaceAfter=0)
cell_head = ParagraphStyle("cell_head", parent=cell, fontName="Sans-Bold")
mono = ParagraphStyle("mono", parent=cell, fontName="Mono", fontSize=8.6)
bullet = ParagraphStyle("bullet", parent=body, spaceAfter=1)

CONTENT_W = letter[0] - 1.5 * inch


def code(name):
    return f'<font name="Mono" size="8.6">{name}</font>'


def table(header, rows, widths, styles=None):
    """A zebra-striped table; ``styles`` gives each column's ParagraphStyle."""
    styles = styles or [cell] * len(header)
    data = [[Paragraph(h, cell_head) for h in header]]
    for r in rows:
        data.append([Paragraph(text, style) for text, style in zip(r, styles)])
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, ACCENT),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    for i in range(2, len(data), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), ZEBRA))
    t.setStyle(TableStyle(style))
    return t


def boxed(content, bg, border):
    """Wrap flowables in a shaded box with a coloured left rule."""
    t = Table([[content]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEBEFORE", (0, 0), (0, -1), 3, border),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return [Spacer(1, 4), t, Spacer(1, 8)]


def callout(label, text, bg=NOTE_BG, border=NOTE_BORDER):
    return boxed(Paragraph(f"<b>{label}</b> {text}", cell), bg, border)


def bullets(items):
    return ListFlowable(
        [ListItem(Paragraph(i, bullet), leftIndent=12, bulletColor=MUTED) for i in items],
        bulletType="bullet", start="•", leftIndent=12, bulletFontName="Sans", bulletFontSize=8,
        spaceAfter=6,
    )


def footer(label):
    """Return an onPage callback that draws ``label`` and the page number."""
    def on_page(c, doc):
        c.saveState()
        c.setFont("Sans", 7.5)
        c.setFillColor(MUTED)
        c.drawString(0.75 * inch, 0.5 * inch, label)
        c.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
        c.setStrokeColor(RULE)
        c.setLineWidth(0.5)
        c.line(0.75 * inch, 0.65 * inch, letter[0] - 0.75 * inch, 0.65 * inch)
        c.restoreState()
    return on_page
