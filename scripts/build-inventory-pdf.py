#!/usr/bin/env python3
"""Build docs/desktop-commander-inventory.pdf.

Usage: scripts/build-inventory-pdf.py [OUTPUT]

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
from reportlab.platypus import (
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "docs" / "desktop-commander-inventory.pdf"
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


def table(header, rows, widths, first_mono=True):
    data = [[Paragraph(h, cell_head) for h in header]]
    for r in rows:
        data.append([
            Paragraph(r[0], mono if first_mono else cell),
            Paragraph(r[1], cell),
        ])
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


def callout(label, text, bg=NOTE_BG, border=NOTE_BORDER):
    p = Paragraph(f"<b>{label}</b> {text}", cell)
    t = Table([[p]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEBEFORE", (0, 0), (0, -1), 3, border),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return [Spacer(1, 4), t, Spacer(1, 8)]


def bullets(items):
    return ListFlowable(
        [ListItem(Paragraph(i, bullet), leftIndent=12, bulletColor=MUTED) for i in items],
        bulletType="bullet", start="•", leftIndent=12, bulletFontName="Sans", bulletFontSize=8,
        spaceAfter=6,
    )


def build_story():
    W2 = [1.9 * inch, CONTENT_W - 1.9 * inch]
    story = []

    story.append(Paragraph("Desktop Commander — Complete Functionality Inventory", title))
    story.append(Paragraph("Compatibility target and implementation checklist for ContextBridge", subtitle))
    story.append(Paragraph(
        "Desktop Commander is more than a filesystem tool. It provides remote computer access, terminal execution, "
        "file editing, document handling, process management, search, device management, and MCP integration.", body))
    story.append(Paragraph(
        "The tools exposed by the connected Desktop Commander Remote installation were checked and compared with the "
        "official documentation. The current connection exposes <b>31 tools</b>, including account, diagnostic, and "
        "feedback functions.", body))
    story.append(Paragraph(
        "Below is the functionality inventory to use as a development checklist for ContextBridge.", body))

    # 1
    story.append(Paragraph("1. Filesystem operations", h1))
    story.append(table(["Function", "Description"], [
        ("read_file", "Read individual files"),
        ("read_multiple_files", "Read several files in one operation"),
        ("write_file", "Create, overwrite, or append to files"),
        ("edit_block", "Make targeted edits without rewriting an entire file"),
        ("create_directory", "Create folders and nested directory structures"),
        ("list_directory", "List files and folders recursively"),
        ("move_file", "Move or rename files and directories"),
        ("get_file_info", "Retrieve size, dates, permissions, type, and other metadata"),
    ], W2))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Additional capabilities include reading selected line ranges, negative offsets to read the ends of files, "
        "configurable line limits, exact text replacement, ambiguity detection, and directory access restrictions.", body))
    story += callout("Deletion:",
        "The current remote tool inventory does not expose a dedicated delete-file tool. Deletion can be performed "
        "through authorized terminal commands. ContextBridge should implement a native deletion function with "
        "appropriate safeguards.")

    # 2
    story.append(Paragraph("2. File and content search", h1))
    story.append(table(["Function", "Description"], [
        ("start_search", "Search file names or file contents"),
        ("get_more_search_results", "Retrieve paginated search results"),
        ("stop_search", "Cancel an active search"),
        ("list_searches", "View active search sessions"),
    ], W2))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Search capabilities include recursive traversal, text-pattern matching, filename searching, large-result "
        "pagination, asynchronous searching, and Excel content searching.", body))

    # 3
    story.append(Paragraph("3. Terminal and command execution", h1))
    story.append(table(["Function", "Description"], [
        ("start_process", "Start a command or interactive process"),
        ("read_process_output", "Retrieve new output from a running process"),
        ("interact_with_process", "Send input to an existing process"),
        ("force_terminate", "Stop an active terminal session"),
        ("list_sessions", "List active terminal sessions"),
    ], W2))
    story.append(Paragraph("Other supported functionality", h2))
    story.append(bullets([
        "Bash, PowerShell, CMD, and other installed shells.",
        "Configurable command timeouts.",
        "Background and long-running execution.",
        "Output streaming and pagination.",
        "Persistent REPL sessions.",
        "Interactive Python, Node.js, and similar runtimes.",
        "Working with Git, SSH, compilers, package managers, and development tools through terminal commands.",
        "Capturing stdout, stderr, exit status, and process information.",
    ]))
    story += callout("Priority:",
        "This is one of Desktop Commander's most important capabilities to replicate.", KEY_BG, KEY_BORDER)

    # 4
    story.append(Paragraph("4. Process and system management", h1))
    story.append(table(["Function", "Description"], [
        ("list_processes", "List running system processes"),
        ("kill_process", "Terminate processes by PID"),
        ("list_sessions", "Show managed terminal sessions"),
        ("force_terminate", "Terminate a managed session"),
    ], W2))
    story.append(Paragraph("Also manageable through terminal commands", h2))
    story.append(bullets([
        "Linux systemd services.",
        "Windows services.",
        "Installed applications.",
        "Docker and Podman.",
        "Git repositories and developer environments.",
        "Scheduled tasks.",
        "System logs.",
        "Network interfaces and diagnostic utilities.",
    ]))
    story.append(Paragraph(
        "Those are capabilities provided through OS commands, rather than individual dedicated Desktop Commander tools.",
        body))

    # 5
    story.append(Paragraph("5. Document and structured-file operations", h1))
    story.append(Paragraph(
        "These functions are part of the documented Desktop Commander implementation and supported file handlers.", body))
    story.append(table(["File type", "Supported functionality"], [
        ("TXT / Markdown", "Read, create, edit, append, search"),
        ("Python / JS / source code", "Read, edit, search, rewrite"),
        ("JSON / YAML / XML", "Read and edit structured text"),
        ("CSV", "Read and analyze, including via terminal tools"),
        ("Excel (.xlsx, .xls, .xlsm)", "Read cells, write data, edit ranges, search sheets"),
        ("PDF", "Extract text, read pages, create and modify PDFs"),
        ("Word (.docx)", "Read, create, inspect, and edit content"),
        ("Images", "Read and present supported image formats"),
        ("Web URLs", "Fetch supported remote file contents"),
    ], W2, first_mono=False))
    story.append(Spacer(1, 6))
    story.append(bullets([
        f"For PDFs, the remote interface includes a dedicated {code('write_pdf')} tool for creation, insertion, and "
        "removal of pages.",
        "For Excel, it supports sheet selection and cell ranges.",
        "For DOCX, it supports text-bearing outlines and targeted XML editing.",
    ]))

    # 6
    story.append(Paragraph("6. Remote device management", h1))
    story.append(Paragraph("These are the capabilities provided by Desktop Commander Remote.", body))
    story.append(table(["Function", "Description"], [
        ("list_devices", "Display registered devices and online/offline status"),
        ("ping", "Verify device connectivity"),
        ("shutdown", "Shut down a remote agent process"),
        ("who_am_i", "Identify the authenticated account"),
        ('<font name="Sans">Remote tool routing</font>', "Execute a tool against a selected registered device"),
        ('<font name="Sans">Device pairing</font>', "Register and authorize machines"),
        ('<font name="Sans">Agent reconnection</font>', "Restore remote service availability after interruption"),
    ], W2))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Remote Desktop Commander uses a hosted relay and OAuth-based connectivity. It supports Windows, Linux, and "
        "macOS device agents.", body))
    story += callout("For ContextBridge:",
        "These capabilities must be self-hosted to avoid relying on Desktop Commander's infrastructure.",
        KEY_BG, KEY_BORDER)

    # 7
    story.append(Paragraph("7. Configuration and permissions", h1))
    story.append(table(["Function", "Description"], [
        ("get_config", "Retrieve configuration and environment information"),
        ("set_config_value", "Change supported configuration values"),
    ], W2))
    story.append(Paragraph("The configuration system includes", h2))
    story.append(bullets([
        "Allowed filesystem directories.",
        "Blocked commands.",
        "Preferred shell.",
        "File reading and writing limits.",
        "Telemetry settings.",
        "Connected-client information.",
        "Server and operating-system details.",
    ]))
    story += callout("Critical distinction:",
        "Filesystem allowlists do not automatically restrict all possible filesystem access through terminal "
        "commands. ContextBridge should enforce its security boundaries consistently across both file tools and "
        "command execution.")

    # 8
    story.append(Paragraph("8. Monitoring, diagnostics, and session history", h1))
    story.append(table(["Function", "Description"], [
        ("get_usage_stats", "Retrieve usage metrics"),
        ("get_recent_tool_calls", "Inspect recent tool activity"),
        ("get_tool_result", "Retrieve pending or completed remote call results"),
        ("list_remote_tool_calls", "Inspect remote calls continuing beyond the initial wait"),
        ("get_config", "Examine current configuration"),
        ("give_feedback_to_desktop_commander", "Open the feedback interface"),
    ], [2.8 * inch, CONTENT_W - 2.8 * inch]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This covers execution history, troubleshooting, usage visibility, and asynchronous call tracking.", body))
    story += callout("For ContextBridge:",
        "Preserve a durable local audit log instead of relying exclusively on in-memory session history.",
        KEY_BG, KEY_BORDER)

    # 9
    CHECKLIST = [
        ("Filesystem", [
            "Read and read multiple files",
            "Create, overwrite, and append files",
            "Targeted file editing",
            "Create, move, rename, and delete directories/files",
            "Recursive listing and metadata",
            "Path and permission enforcement",
        ]),
        ("Search", [
            "Search filenames",
            "Search file contents",
            "Recursive search",
            "Paginated results",
            "Asynchronous search sessions",
            "Cancel active searches",
        ]),
        ("Terminal", [
            "Execute Bash, PowerShell, and CMD",
            "Persistent interactive shells",
            "Stream stdout and stderr",
            "Send input to active processes",
            "Timeouts and bounded output",
            "Terminate process trees",
        ]),
        ("System and processes", [
            "List and terminate processes",
            "Manage authorized system services",
            "Inspect system information and logs",
            "Support development tools and Git",
        ]),
        ("Documents", [
            "Excel read/write/edit/search",
            "PDF read/create/modify",
            "Word read/create/edit",
            "Images and supported URLs",
            "CSV and structured data handling",
        ]),
        ("Remote access", [
            "Linux and Windows native agents",
            "Device enrollment and revocation",
            "Online/offline status and heartbeat",
            "Encrypted bidirectional connection",
            "Self-hosted relay with reconnect",
            "Per-device command routing",
        ]),
        ("Security and operations", [
            "OAuth-compatible MCP client access",
            "Per-device and per-tool permission profiles",
            "Credential and secret isolation",
            "Complete audit and execution history",
            "Configurable scopes and resource limits",
            "Recovery after interrupted operations",
        ]),
        ("Synchronization (ContextBridge addition)", [
            "Bidirectional file transfer",
            "Directory synchronization",
            "Checksums and change detection",
            "Conflict preservation",
            "Resumable transfers",
            "Recoverable deletion propagation",
        ]),
    ]
    total = sum(len(items) for _, items in CHECKLIST)

    story.append(PageBreak())
    story.append(Paragraph("9. ContextBridge implementation checklist", h1))
    story.append(Paragraph(
        "The following is the actionable scope for building an independent replacement.", body))
    story.append(Paragraph(
        f"<b>Implementation tracker — 0 / {total} complete.</b> Check completed capabilities as they are implemented "
        "and verified. All items start unchecked; this is not a live repository status report.", body))

    box = '<font name="Sans" size="11">☐</font>'
    date_head = ParagraphStyle("dh", parent=cell_head, textColor=MUTED, fontSize=8)
    for group, items in CHECKLIST:
        rows = [[Paragraph(f"{group}", cell_head), Paragraph(f"0/{len(items)}", cell_head),
                 Paragraph("Verified (date / notes)", date_head)]]
        for it in items:
            rows.append([Paragraph(f"{box}&nbsp;&nbsp;{it}", cell), "", ""])
        t = Table(rows, colWidths=[CONTENT_W - 2.6 * inch, 0.5 * inch, 2.1 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, ACCENT),
            *[("SPAN", (0, r), (1, r)) for r in range(1, len(rows))],
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, RULE),
            ("LINEBELOW", (2, 1), (2, -1), 0.4, RULE),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether([t, Spacer(1, 10)]))

    # 10
    sec10 = []
    sec10.append(Paragraph("10. What Desktop Commander does not provide as a dedicated synchronization system", h1))
    sec10.append(Paragraph(
        "For this objective, there is an important difference between remote access and automatic synchronization.",
        body))
    sec10.append(Paragraph(
        "Desktop Commander already lets an AI assistant read a file from <b>Friday</b>, modify it, and write a file to "
        "<b>Thanatos</b>. However, its documented toolset is not a continuous bidirectional file synchronization engine "
        "with conflict resolution.", body))
    sec10.append(Paragraph(
        "ContextBridge could go beyond parity by providing native synchronization, resumable transfers, hash "
        "verification, explicit conflict handling, and recovery after network disconnections.", body))
    sec10 += callout("Recommendation:",
        "Use Desktop Commander's current tools as the compatibility target, then add ContextBridge's independent "
        "device infrastructure and bidirectional synchronization.", KEY_BG, KEY_BORDER)
    sec10 += callout("Acceptance test:",
        "Desktop Commander can be completely disabled while ContextBridge continues operating against Friday and "
        "Thanatos using its own agents, permissions, transport, and tools.", HEAD_BG, ACCENT)

    story.append(KeepTogether(sec10))
    return story, total


def on_page(c, doc):
    c.saveState()
    c.setFont("Sans", 7.5)
    c.setFillColor(MUTED)
    c.drawString(0.75 * inch, 0.5 * inch, "ContextBridge · Desktop Commander functionality inventory")
    c.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
    c.setStrokeColor(RULE)
    c.setLineWidth(0.5)
    c.line(0.75 * inch, 0.65 * inch, letter[0] - 0.75 * inch, 0.65 * inch)
    c.restoreState()


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    register_fonts()
    story, total = build_story()
    doc = SimpleDocTemplate(
        str(out), pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=0.75 * inch, bottomMargin=0.85 * inch,
        title="Desktop Commander — Complete Functionality Inventory",
        subject="Compatibility target and implementation checklist for ContextBridge",
        author="ContextBridge",
        invariant=True,
    )
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f"wrote {out} ({total} checklist items)")


if __name__ == "__main__":
    main()
