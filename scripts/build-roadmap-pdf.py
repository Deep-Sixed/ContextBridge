#!/usr/bin/env python3
"""Build docs/capability-roadmap.pdf.

Usage: scripts/build-roadmap-pdf.py [OUTPUT]

Requires reportlab (pip install -e '.[docs]') and the DejaVu Sans fonts. Fonts are
looked up under the usual system font directories, or under CONTEXTBRIDGE_FONT_DIR.
"""
import sys
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from pdf_common import (
    ACCENT, CONTENT_W, HEAD_BG, KEY_BG, KEY_BORDER, MUTED, ROOT, RULE,
    body, bullets, callout, cell, cell_head, footer, h1, h2, register_fonts, subtitle, table, title,
)

DEFAULT_OUT = ROOT / "docs" / "capability-roadmap.pdf"
DOC_TITLE = "ContextBridge — Capability Roadmap"
DOC_SUBJECT = "Target capabilities and implementation checklist"


def build_story():
    W2 = [1.9 * inch, CONTENT_W - 1.9 * inch]
    story = []

    story.append(Paragraph(DOC_TITLE, title))
    story.append(Paragraph(DOC_SUBJECT, subtitle))
    story.append(Paragraph(
        "ContextBridge's target scope is more than a filesystem tool. It covers remote computer access, terminal "
        "execution, file editing, document handling, process management, search, device management, and MCP "
        "integration.", body))
    story.append(Paragraph(
        "Sections 1–8 describe the target capabilities by area. Section 9 is the implementation checklist, and "
        "section 10 covers synchronization.", body))

    # 1
    story.append(Paragraph("1. Filesystem operations", h1))
    story.append(table(["Capability", "Description"], [
        ("Read a file", "Read individual files"),
        ("Read multiple files", "Read several files in one operation"),
        ("Write a file", "Create, overwrite, or append to files"),
        ("Edit a file", "Make targeted edits without rewriting an entire file"),
        ("Create a directory", "Create folders and nested directory structures"),
        ("List a directory", "List files and folders recursively"),
        ("Move a file", "Move or rename files and directories"),
        ("File information", "Retrieve size, dates, permissions, type, and other metadata"),
    ], W2))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Additional capabilities include reading selected line ranges, negative offsets to read the ends of files, "
        "configurable line limits, exact text replacement, ambiguity detection, and directory access restrictions.", body))
    story += callout("Deletion:",
        "Provide a native delete operation with appropriate safeguards rather than relying on terminal commands.")

    # 2
    story.append(Paragraph("2. File and content search", h1))
    story.append(table(["Capability", "Description"], [
        ("Start a search", "Search file names or file contents"),
        ("More results", "Retrieve paginated search results"),
        ("Stop a search", "Cancel an active search"),
        ("List searches", "View active search sessions"),
    ], W2))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Search capabilities include recursive traversal, text-pattern matching, filename searching, large-result "
        "pagination, asynchronous searching, and Excel content searching.", body))

    # 3
    story.append(Paragraph("3. Terminal and command execution", h1))
    story.append(table(["Capability", "Description"], [
        ("Start a process", "Start a command or interactive process"),
        ("Read output", "Retrieve new output from a running process"),
        ("Send input", "Send input to an existing process"),
        ("Terminate a session", "Stop an active terminal session"),
        ("List sessions", "List active terminal sessions"),
    ], W2))
    story.append(Paragraph("Other target functionality", h2))
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
    story += callout("Priority:", "Terminal execution is one of the most important capabilities.", KEY_BG, KEY_BORDER)

    # 4
    story.append(Paragraph("4. Process and system management", h1))
    story.append(table(["Capability", "Description"], [
        ("List processes", "List running system processes"),
        ("Kill a process", "Terminate processes by PID"),
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
    story.append(Paragraph("These are reached through OS commands rather than dedicated tools.", body))

    # 5
    story.append(Paragraph("5. Document and structured-file operations", h1))
    story.append(Paragraph("File handlers for common formats.", ParagraphStyle("intro", parent=body, keepWithNext=1)))
    story.append(table(["File type", "Target functionality"], [
        ("TXT / Markdown", "Read, create, edit, append, search"),
        ("Python / JS / source code", "Read, edit, search, rewrite"),
        ("JSON / YAML / XML", "Read and edit structured text"),
        ("CSV", "Read and analyze, including via terminal tools"),
        ("Excel (.xlsx, .xls, .xlsm)", "Read cells, write data, edit ranges, search sheets"),
        ("PDF", "Extract text, read pages, create and modify PDFs"),
        ("Word (.docx)", "Read, create, inspect, and edit content"),
        ("Images", "Read and present supported image formats"),
        ("Web URLs", "Fetch supported remote file contents"),
    ], W2))
    story.append(Spacer(1, 6))
    story.append(bullets([
        "PDF: create documents, and insert or remove pages.",
        "Excel: sheet selection and cell ranges.",
        "Word: text-bearing outlines and targeted XML editing.",
    ]))

    # 6
    story.append(Paragraph("6. Remote device management", h1))
    story.append(table(["Capability", "Description"], [
        ("List devices", "Display registered devices and online/offline status"),
        ("Ping", "Verify device connectivity"),
        ("Shut down an agent", "Shut down a remote agent process"),
        ("Account identity", "Identify the authenticated account"),
        ("Remote tool routing", "Execute a tool against a selected registered device"),
        ("Device pairing", "Register and authorize machines"),
        ("Agent reconnection", "Restore remote service availability after interruption"),
    ], W2))
    story += callout("Self-hosted:",
        "The relay and device agents run on infrastructure ContextBridge controls, with native agents for Linux "
        "and Windows. No third-party hosted relay.", KEY_BG, KEY_BORDER)

    # 7
    story.append(Paragraph("7. Configuration and permissions", h1))
    story.append(table(["Capability", "Description"], [
        ("Read configuration", "Retrieve configuration and environment information"),
        ("Change configuration", "Change supported configuration values"),
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
    story.append(table(["Capability", "Description"], [
        ("Usage statistics", "Retrieve usage metrics"),
        ("Recent tool calls", "Inspect recent tool activity"),
        ("Remote call results", "Retrieve pending or completed remote call results"),
        ("Long-running remote calls", "Inspect remote calls continuing beyond the initial wait"),
    ], W2))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This covers execution history, troubleshooting, usage visibility, and asynchronous call tracking.", body))
    story += callout("Audit:",
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
        ("Synchronization", [
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
    story.append(Paragraph("The following is the actionable scope, by area.", body))
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
    sec10.append(Paragraph("10. Synchronization beyond remote access", h1))
    sec10.append(Paragraph(
        "For this objective, there is an important difference between remote access and automatic synchronization.",
        body))
    sec10.append(Paragraph(
        "Remote access lets an AI assistant read a file from <b>Friday</b>, modify it, and write a file to "
        "<b>Thanatos</b>. That is not a continuous bidirectional file synchronization engine with conflict "
        "resolution.", body))
    sec10.append(Paragraph(
        "ContextBridge goes beyond remote access by providing native synchronization, resumable transfers, hash "
        "verification, explicit conflict handling, and recovery after network disconnections.", body))
    sec10 += callout("Recommendation:",
        "Treat sections 1–8 as the baseline scope, then add bidirectional synchronization on top of "
        "ContextBridge's own device infrastructure.", KEY_BG, KEY_BORDER)
    sec10 += callout("Acceptance test:",
        "ContextBridge operates against Friday and Thanatos using only its own agents, permissions, transport, and "
        "tools, with no third-party remote-access service.", HEAD_BG, ACCENT)

    story.append(KeepTogether(sec10))
    return story, total


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    register_fonts()
    story, total = build_story()
    doc = SimpleDocTemplate(
        str(out), pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=0.75 * inch, bottomMargin=0.85 * inch,
        title=DOC_TITLE,
        subject=DOC_SUBJECT,
        author="ContextBridge",
        invariant=True,
    )
    on_page = footer("ContextBridge · Capability roadmap")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f"wrote {out} ({total} checklist items)")


if __name__ == "__main__":
    main()
