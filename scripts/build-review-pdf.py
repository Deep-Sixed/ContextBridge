#!/usr/bin/env python3
"""Build docs/computer-use-linux-review.pdf.

Usage: scripts/build-review-pdf.py [OUTPUT]

Requires reportlab (pip install -e '.[docs]') and the DejaVu Sans fonts. Fonts are
looked up under the usual system font directories, or under CONTEXTBRIDGE_FONT_DIR.
"""
import sys
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from pdf_common import (
    ACCENT, CONTENT_W, HEAD_BG, INK, MUTED, NOTE_BG, ROOT, RULE, ZEBRA,
    body, boxed, bullets, cell, code, footer, h1, h2, mono, register_fonts, subtitle, table, title,
)

DEFAULT_OUT = ROOT / "docs" / "computer-use-linux-review.pdf"
DOC_TITLE = "Code Review: agent-sh/computer-use-linux"
DOC_SUBJECT = "ContextBridge evaluation"

# Inline <font color> markup takes hex strings.
GREEN = "#2f7d4a"
RED = "#b42318"
AMBER = "#b54708"
BLUE = "#1d4e89"
GREY = "#52606d"

GUI_BG = colors.HexColor("#fdf3e7")
GUI_BORDER = colors.HexColor("#b7791f")
ALERT_BG = colors.HexColor("#fdecea")
ALERT_BORDER = colors.HexColor("#c0392b")

note = ParagraphStyle("note", parent=body, textColor=MUTED)
panel_text = ParagraphStyle("panel_text", parent=cell, spaceAfter=5)
grade_label = ParagraphStyle("grade_label", parent=cell, textColor=MUTED, alignment=TA_CENTER)
grade_value = ParagraphStyle("grade_value", parent=cell, fontName="Sans-Bold", fontSize=15, leading=20, alignment=TA_CENTER)


def colored(text, color, bold=True):
    inner = f"<b>{text}</b>" if bold else text
    return f'<font color="{color}">{inner}</font>'


def panel(label, paragraphs, bg, border, label_color):
    """A boxed note with its label on its own line."""
    content = [Paragraph(colored(label, label_color), panel_text)]
    content += [Paragraph(p, panel_text) for p in paragraphs]
    return boxed(content, bg, border)


def architecture_diagram():
    w, h = CONTENT_W, 290
    d = Drawing(w, h)
    cx = w / 2

    def box(x, y, bw, bh, fill, stroke, dashed=False):
        r = Rect(x, y, bw, bh, rx=6, ry=6, fillColor=fill, strokeColor=stroke, strokeWidth=1)
        if dashed:
            r.strokeDashArray = [4, 3]
        d.add(r)

    def text(x, y, s, font="Sans", size=9, color=INK):
        d.add(String(x, y, s, fontName=font, fontSize=size, fillColor=color, textAnchor="middle"))

    def arrow(top, bottom):
        d.add(Line(cx, top, cx, bottom + 7, strokeColor=MUTED, strokeWidth=1.2))
        d.add(Polygon([cx - 5, bottom + 7, cx + 5, bottom + 7, cx, bottom], fillColor=MUTED, strokeColor=MUTED))

    box(cx - 170, 254, 340, 34, colors.white, RULE)
    text(cx, 267, "ChatGPT / Claude / OpenCode", "Sans-Bold", 10)
    arrow(254, 222)

    box(cx - 170, 174, 340, 48, HEAD_BG, ACCENT)
    text(cx, 202, "ContextBridge Gateway", "Sans-Bold", 10, ACCENT)
    text(cx, 186, "Auth · Policies · Audit · Remote device routing", size=8, color=MUTED)
    arrow(174, 146)

    box(20, 10, w - 40, 136, ZEBRA, ACCENT, dashed=True)
    text(cx, 124, "Friday — ContextBridge Agent", "Sans-Bold", 10, ACCENT)

    left_cx, right_cx = 40 + 100, w - 40 - 100
    box(40, 50, 200, 52, colors.white, RULE)
    text(left_cx, 80, "Native tools", "Sans-Bold", 10)
    text(left_cx, 64, "Files, shell, processes, sync", size=8, color=MUTED)
    box(w - 240, 50, 200, 52, GUI_BG, GUI_BORDER)
    text(right_cx, 80, "Linux GUI engine", "Sans-Bold", 10, GUI_BORDER)
    text(right_cx, 64, "Windows, screenshots, input", size=8, color=MUTED)
    text(right_cx, 30, "Bundled Rust component · local MCP stdio", size=7.5, color=MUTED)
    return d


def assessment_grid():
    def grade(label, value, color):
        return [Paragraph(label, grade_label), Paragraph(colored(value, color), grade_value)]

    t = Table(
        [
            [grade("Linux GUI functionality", "Strong", GREEN), grade("Remote infrastructure", "Not included", GREY)],
            [grade("Implementation independence", "Good", GREEN), grade("Windows compatibility", "None", RED)],
        ],
        colWidths=[CONTENT_W / 2] * 2,
    )
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, RULE),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, RULE),
        ("BACKGROUND", (0, 0), (-1, -1), ZEBRA),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def build_story():
    story = []

    story.append(Paragraph(DOC_TITLE, title))
    story.append(Paragraph(f"{colored('Strong candidate', GREEN)} · Rust · MIT license · v0.7.12", subtitle))
    story.append(Paragraph(
        "This project could be a useful addition to ContextBridge, particularly for controlling Friday's Linux "
        "desktop. It covers a major capability that filesystem and terminal tools do not address directly: "
        "graphical desktop interaction.", body))
    story.append(Paragraph(
        "The project is a native Rust MCP server providing Linux desktop automation through AT-SPI accessibility, "
        "desktop environment APIs, Wayland portals, and simulated keyboard/mouse input.", body))

    # 1
    W2 = [2.6 * inch, CONTENT_W - 2.6 * inch]
    story.append(Paragraph("1. What the project actually does", h1))
    story.append(Paragraph("Its key functionality includes:", body))
    story.append(table(["Capability", "Implementation"], [
        ("Screenshot capture", "GNOME screenshot APIs, portals, X11 fallback"),
        ("Mouse clicking", "Accessibility actions or coordinates"),
        ("Keyboard typing", "Wayland input backends / X11"),
        ("Drag and drop", "Desktop coordinate controls"),
        ("Scrolling", "Accessibility and pointer backends"),
        ("Window discovery", "GNOME, KDE, Hyprland, niri, i3, COSMIC, X11"),
        ("Window focus", "Identify and activate applications"),
        ("Window positioning", "Move and resize where supported"),
        ("Accessibility inspection", "AT-SPI application element trees"),
        ("Semantic UI operations", "Find controls by role, name, text, or state"),
        ("Shell execution", "Optional, disabled by default"),
        ("MCP integration", "Native Rust MCP server"),
        ("Diagnostics", f"{code('doctor')} readiness report"),
    ], W2))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "One particularly useful feature is that the agent can inspect the accessibility tree and interact with "
        "named UI elements instead of relying exclusively on screenshot coordinates.", body))
    story.append(Paragraph(
        "For example, an agent could identify a <b>Save</b> button in a desktop application and invoke its "
        "accessibility action, rather than guessing where the button appears on-screen.", body))

    # 2
    story.append(PageBreak())
    story.append(Paragraph("2. How it fits ContextBridge", h1))
    story.append(Paragraph("ContextBridge and computer-use-linux solve different problems.", body))
    story.append(table(["Capability", "ContextBridge target", "computer-use-linux"], [
        ("Filesystem operations", "Yes", "Through optional shell"),
        ("Terminal execution", "Yes", "Optional limited execution"),
        ("Remote device management", "Yes", "No standalone relay"),
        ("Windows support", "Yes", "No"),
        ("Graphical desktop control", "Planned", "Yes"),
        ("Accessibility automation", "Planned", "Yes"),
        ("Bidirectional synchronization", "Yes", "No"),
        ("Local MCP server", "Yes", "Yes"),
        ("Authentication and authorization", "Required", "Relies primarily on its MCP host and local access boundary"),
    ], [2.5 * inch, 1.5 * inch, CONTENT_W - 4.0 * inch]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The main benefit is avoiding the need to independently implement Linux graphical automation.", body))
    story.append(Paragraph(
        "Instead of writing your own mouse, keyboard, screenshot, and accessibility control backends, ContextBridge "
        "could incorporate this Rust implementation.", body))

    # 3
    story.append(Paragraph("3. Code quality assessment", h1))
    story.append(Paragraph(
        "I inspected the repository's source layout, MCP server implementation, process execution code, "
        "dependency manifest, and security documentation.", body))
    for heading, text in [
        ("Modular architecture",
         "Separate modules handle accessibility, screenshots, window targeting, keyboard input, command execution, "
         "and diagnostics. This makes selective reuse practical."),
        ("Process supervision",
         "The command runner implements timeouts, output limits, process-group termination, and cleanup on "
         "cancellation. These are worthwhile patterns for ContextBridge's terminal engine."),
        ("Careful MCP tool registration",
         f"Shell execution is removed from the advertised tools unless {code('COMPUTER_USE_LINUX_ENABLE_SHELL=1')}. "
         "Tool annotations distinguish observation from state-changing operations."),
        ("Resource boundaries",
         "Screenshot dimensions and payload sizes are capped. Terminal output is bounded, and several potentially "
         "slow operations have deadlines."),
    ]:
        story.append(Paragraph(heading, h2))
        story.append(Paragraph(text, body))
    story.append(Paragraph(
        "These findings indicate a thoughtfully engineered implementation, although I have not executed the "
        "project or completed a full security audit.", note))

    # 4
    story.append(PageBreak())
    story.append(Paragraph("4. Risks and limitations", h1))
    high, medium, low = colored("High", RED), colored("Medium", AMBER), colored("Low", GREY)
    story.append(table(["Severity", "Finding", "Implication"], [
        (high, "No independent remote authorization layer",
         "ContextBridge must authorize every computer-control request before forwarding it"),
        (high, "Shell access is effectively host-user access",
         "Timeouts and output limits are not a security sandbox"),
        (medium, "GUI automation requires an active desktop session",
         "A system service running without access to the graphical user session may fail"),
        (medium, "GNOME-specific functionality varies by compositor",
         "Friday's actual desktop environment needs testing"),
        (medium, "No native Windows implementation", "Thanatos needs a separate backend"),
        (low, "Rust and Python integration",
         "Requires process supervision, protocol integration, and packaging coordination"),
    ], [0.95 * inch, 2.35 * inch, CONTENT_W - 3.3 * inch]))
    story.append(Spacer(1, 8))
    story += panel("Important for Friday", [
        "The project reports manual validation on Ubuntu GNOME Wayland, with additional compositor-specific testing.",
        "Friday may be running Cinnamon or XFCE components, based on its installed desktop applications. That does "
        "not establish which desktop session is active.",
        "If Friday uses X11, the project has generic X11/EWMH support. If it uses GNOME Wayland, the GNOME backend "
        "is more mature.",
        f"I would run its {code('doctor')} command before deciding which components to integrate.",
    ], NOTE_BG, GUI_BORDER, BLUE)

    # 5
    story.append(PageBreak())
    story.append(Paragraph("5. The architecture I recommend", h1))
    story.append(Paragraph(
        "Rather than porting all this Rust code into Python, make it a locally bundled subsystem of ContextBridge.",
        body))
    story.append(Spacer(1, 6))
    story.append(architecture_diagram())
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "This is still an independent architecture because ContextBridge would own the agent, distribution, "
        "authentication, tool authorization, and remote connectivity. The Rust engine would be a locally bundled "
        "open-source dependency, not an external hosted service.", body))
    story.append(Paragraph(
        "The project's MIT license permits reuse and modification, provided required copyright and license notices "
        "are preserved.", body))
    story.append(Paragraph(
        "If the goal is independence from all external maintained software, you could vendor a reviewed version "
        "into ContextBridge and maintain it yourself.", body))

    # 6
    story.append(PageBreak())
    story.append(Paragraph("6. What I would reuse", h1))
    story.append(Paragraph(
        "My preference is selective integration, not replacing the ContextBridge code already being developed.",
        body))
    prio_high, prio_medium = colored("High", BLUE), colored("Medium", AMBER)
    story.append(table(["Source component", "Proposed ContextBridge use", "Priority"], [
        ("atspi_tree.rs", "Semantic UI discovery and actions", prio_high),
        ("windowing/", "Window identification and focus", prio_high),
        ("screenshot.rs", "Screen capture", prio_high),
        ("remote_desktop.rs", "Wayland input support", prio_high),
        ("ydotool.rs", "Input fallback", prio_high),
        ("diagnostics.rs", "Desktop readiness checks", prio_high),
        ("command_runner.rs", "Reference for process safety", prio_medium),
        ("indicator.rs", "Visual indication of agent activity", prio_medium),
        ("server.rs", "MCP integration reference", prio_medium),
    ], [2.2 * inch, CONTENT_W - 3.2 * inch, 1.0 * inch], [mono, cell, cell]))
    story.append(Spacer(1, 8))
    story += panel("Essential security change", [
        "The ContextBridge agent must authorize GUI actions locally as well as at the gateway. An approved "
        "screenshot request should not imply permission to type commands into a terminal or approve desktop "
        "security prompts.",
    ], ALERT_BG, ALERT_BORDER, RED)

    # 7
    story.append(Paragraph("7. Final assessment", h1))
    story.append(Paragraph("<b>Assessment for ContextBridge</b>", cell))
    story.append(Spacer(1, 6))
    story.append(assessment_grid())
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "I would adopt computer-use-linux as the Linux graphical control engine, while continuing to build "
        "ContextBridge's independent filesystem, terminal, synchronization, authorization, and remote-agent "
        "capabilities.", body))
    story.append(Paragraph("Together, that gives ContextBridge:", body))
    story.append(bullets([
        "Filesystem and terminal control.",
        "Graphical desktop control through screenshots and accessibility.",
        "Native remote agents for Friday and Thanatos.",
        "Full bidirectional file and directory synchronization.",
        "Self-hosted remote access without a third-party relay or Authentik.",
    ]))
    story.append(Paragraph(
        "The next practical step is a read-only compatibility test on Friday: identify its desktop session, inspect "
        "the repository's required system components, and run the diagnostic tool without enabling input or "
        "modifying desktop settings.", body))
    story += panel("Bottom line", [
        "This repository is worth integrating into ContextBridge. It is a strong potential building block for the "
        "Linux desktop-control layer, but not a replacement for ContextBridge's remote gateway or security model.",
    ], HEAD_BG, ACCENT, BLUE)
    return story


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    register_fonts()
    doc = SimpleDocTemplate(
        str(out), pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=0.75 * inch, bottomMargin=0.85 * inch,
        title=DOC_TITLE,
        subject=DOC_SUBJECT,
        author="ContextBridge",
        invariant=True,
    )
    on_page = footer(f"{DOC_TITLE} — {DOC_SUBJECT}")
    doc.build(build_story(), onFirstPage=on_page, onLaterPages=on_page)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
