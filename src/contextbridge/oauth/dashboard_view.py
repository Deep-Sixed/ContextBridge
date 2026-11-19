"""Look of the owner dashboard: the Nocturne design system as plain HTML and CSS.

The dashboard is served under the approval pages' rules (no scripts, no outside fonts or images,
see ``provider._page``), so everything here is inline: the stylesheet, and icons drawn as inline SVG.
Expanding sections are ``<details>``; every change is a form POST.
"""

from __future__ import annotations

import html

from .logo import logo

# Nocturne tokens. Dark is the design's own theme; light reverses each tonal ramp so every
# "muted text" or "tinted fill" step keeps its role on a light ground.
_DARK = """
--color-bg:#161826;--color-surface:#232532;--color-text:#e9e9ed;--color-accent:#9184d9;
--color-divider:color-mix(in srgb,#e9e9ed 16%,transparent);
--color-neutral-100:#f3f5fe;--color-neutral-200:#e4e7f5;--color-neutral-300:#cfd3e5;--color-neutral-400:#b2b6ca;
--color-neutral-500:#9397ab;--color-neutral-600:#75798c;--color-neutral-700:#595d6c;--color-neutral-800:#3f424d;
--color-neutral-900:#292b31;
--color-accent-100:#f5f4ff;--color-accent-200:#e7e5fe;--color-accent-300:#d2cefd;--color-accent-400:#b5abfc;
--color-accent-500:#968ae0;--color-accent-600:#796cbf;--color-accent-700:#5d5294;--color-accent-800:#423a6a;
--color-accent-900:#2b2741;
--shadow-sm:0 0 0 1px #3f424d;--shadow-md:0 0 0 1px #595d6c,0 6px 18px rgba(0,0,0,.55);
--shadow-lg:0 0 0 1px #9397ab,0 16px 40px rgba(0,0,0,.65);color-scheme:dark;
"""
_LIGHT = """
--color-bg:#f4f5fa;--color-surface:#ffffff;--color-text:#1d1f2b;--color-accent:#6a5dc0;
--color-divider:color-mix(in srgb,#1d1f2b 16%,transparent);
--color-neutral-100:#292b31;--color-neutral-200:#3f424d;--color-neutral-300:#4b4e5c;--color-neutral-400:#595d6c;
--color-neutral-500:#6c7083;--color-neutral-600:#8a8ea2;--color-neutral-700:#b2b6ca;--color-neutral-800:#dfe2ee;
--color-neutral-900:#eceef6;
--color-accent-100:#2b2741;--color-accent-200:#423a6a;--color-accent-300:#5d5294;--color-accent-400:#796cbf;
--color-accent-500:#968ae0;--color-accent-600:#b5abfc;--color-accent-700:#c9c2fb;--color-accent-800:#e3dffd;
--color-accent-900:#f1effe;
--shadow-sm:0 0 0 1px #dfe2ee;--shadow-md:0 0 0 1px #c9cdda,0 6px 18px rgba(29,31,43,.10);
--shadow-lg:0 0 0 1px #b2b6ca,0 16px 40px rgba(29,31,43,.16);color-scheme:light;
"""

STYLE = (
    ":root{" + _DARK + "--space-1:2.8px;--space-2:5.6px;--space-3:8.4px;--space-4:11.2px;--space-6:16.8px;"
    "--space-8:22.4px;--radius-sm:4px;--radius-md:8px;--radius-lg:14px;"
    "--font:system-ui,-apple-system,'Segoe UI',sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}"
    ":root[data-theme=light]{" + _LIGHT + "}"
    + """
*{box-sizing:border-box}
body{margin:0;background:var(--color-bg);color:var(--color-text);font:15px/1.55 var(--font)}
h1,h2,h3,h4,h5{font-weight:500;line-height:1.12;letter-spacing:-.015em;margin:0 0 var(--space-2)}
h2{font-size:32px}h4{font-size:20px}h5{font-size:17px}
p{margin:0}a{color:var(--color-accent-300);text-underline-offset:3px}a:hover{color:var(--color-accent-200)}
code,.mono{font-family:var(--mono)}
:focus{outline:none}:focus-visible{outline:2px solid var(--color-accent);outline-offset:2px}
::selection{background:color-mix(in srgb,var(--color-accent) 30%,transparent)}
svg.i{width:1em;height:1em;flex:none;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
form{margin:0}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;cursor:pointer;text-decoration:none;
 font:500 14px/1.2 var(--font);color:var(--color-text);background:transparent;border:1px solid transparent;
 padding:var(--space-2) calc(var(--space-3)*1.2);border-radius:var(--radius-md);white-space:nowrap;flex:none}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn-primary{color:var(--color-accent);border-color:var(--color-accent)}
.btn-primary:hover{background:color-mix(in srgb,var(--color-accent) 12%,transparent);color:var(--color-accent)}
.btn-primary:active{background:color-mix(in srgb,var(--color-accent) 22%,transparent)}
.btn-secondary{border-color:var(--color-divider)}
.btn-secondary:hover{background:color-mix(in srgb,var(--color-text) 7%,transparent);color:var(--color-text)}
.btn-ghost{color:var(--color-accent);padding-inline:var(--space-2)}
.btn-ghost:hover{background:color-mix(in srgb,var(--color-accent) 10%,transparent);color:var(--color-accent)}
.btn-quiet{color:var(--color-neutral-400);font-size:13px;padding:4px 8px}
.btn-quiet:hover{color:var(--color-text);background:color-mix(in srgb,var(--color-text) 7%,transparent)}
.btn-sm{font-size:13px}
.tag{display:inline-flex;align-items:center;font-size:11px;letter-spacing:.02em;padding:3px 10px;border-radius:6px;white-space:nowrap}
.tag-accent{background:var(--color-accent-800);color:var(--color-accent-100)}
.tag-neutral{background:var(--color-neutral-800);color:var(--color-neutral-100)}
.tag-outline{border:1px solid var(--color-accent);color:var(--color-accent)}
.field>label,.field>span{display:block;font-size:12px;margin-bottom:5px;color:color-mix(in srgb,var(--color-text) 70%,transparent)}
.input{width:100%;min-height:36px;padding:6px 10px;font:inherit;font-size:14px;color:var(--color-text);
 caret-color:var(--color-accent);background:var(--color-surface);border:1px solid var(--color-divider);border-radius:var(--radius-md)}
.input:hover{border-color:color-mix(in srgb,var(--color-text) 45%,transparent)}
.input:focus-visible{border-color:var(--color-accent);outline-offset:0}
.seg{display:inline-flex;overflow:hidden;border:1px solid var(--color-divider);border-radius:var(--radius-md)}
.seg button{padding:7px 12px;font:13px var(--font);cursor:pointer;background:transparent;color:var(--color-text);border:0}
.seg button+button{border-left:1px solid var(--color-divider)}
.seg button[aria-pressed=true]{color:var(--color-accent);box-shadow:inset 0 0 0 1px var(--color-accent)}
.seg button[aria-pressed=false]:hover{background:color-mix(in srgb,var(--color-text) 7%,transparent)}
.muted{color:var(--color-neutral-400)}.faint{color:var(--color-neutral-500)}.fainter{color:var(--color-neutral-600)}
.small{font-size:12px}.sm{font-size:13px}.strong{font-weight:500}

.app{display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh}
.side{display:flex;flex-direction:column;gap:var(--space-6);padding:var(--space-6) var(--space-4);
 border-right:1px solid var(--color-neutral-900);position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:var(--space-3);padding:0 var(--space-2)}
.brand b{display:block;font-weight:500;font-size:14px;line-height:1.2}.brand span{font-size:12px;color:var(--color-neutral-500)}
.nav{display:flex;flex-direction:column;gap:2px}
.nav a{display:flex;align-items:center;gap:var(--space-3);padding:7px var(--space-3);border-radius:var(--radius-md);
 color:var(--color-neutral-400);font-size:14px;text-decoration:none}
.nav a:hover{background:color-mix(in srgb,var(--color-text) 6%,transparent);color:var(--color-text)}
.nav a[aria-current=page]{background:color-mix(in srgb,var(--color-accent) 12%,transparent);color:var(--color-accent-300)}
.nav a .i{font-size:17px}.nav .label{flex:1}.nav .badge{font-size:11px;color:var(--color-neutral-500)}
.nav .ext{font-size:12px}
.side-foot{margin-top:auto;display:flex;flex-direction:column;gap:var(--space-3)}
.gw{display:flex;flex-direction:column;gap:var(--space-2);padding:var(--space-4);border-radius:var(--radius-md);
 background:var(--color-surface);box-shadow:var(--shadow-sm);font-size:12px}
.gw-top{display:flex;justify-content:space-between;color:var(--color-neutral-400)}
.gw-run{display:flex;align-items:center;gap:6px;color:var(--color-accent-300)}
.dot{width:7px;height:7px;border-radius:50%;flex:none;background:var(--color-neutral-700)}
.dot.on{background:var(--color-accent)}.gw .dot{width:6px;height:6px}
.owner{display:flex;align-items:center;gap:var(--space-3);padding:0 var(--space-2);font-size:13px;color:var(--color-neutral-300)}
.avatar{width:26px;height:26px;border-radius:50%;background:var(--color-accent-900);color:var(--color-accent-300);
 display:grid;place-items:center;font-size:13px;flex:none}
.avatar.lg{width:36px;height:36px;font-size:16px}

main{padding:48px 40px 80px;min-width:0}
.content{max-width:820px;display:flex;flex-direction:column;gap:var(--space-8)}
.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:var(--space-6);flex-wrap:wrap}
.page-head p{color:var(--color-neutral-400);font-size:14px}
.panel{border-radius:var(--radius-lg);background:var(--color-surface);box-shadow:var(--shadow-sm);overflow:hidden}
.pad{padding:var(--space-6)}
.stack{display:flex;flex-direction:column}.gap2{gap:var(--space-2)}.gap3{gap:var(--space-3)}.gap4{gap:var(--space-4)}
.gap6{gap:var(--space-6)}.gap8{gap:var(--space-8)}
.row{display:flex;align-items:center;gap:var(--space-4)}.wrap{flex-wrap:wrap}.grow{flex:1;min-width:0}
.panel-title{font-weight:500;font-size:15px}
.list-head{display:flex;align-items:center;justify-content:space-between;padding:var(--space-4) var(--space-6)}
.item{display:flex;align-items:center;gap:var(--space-4);padding:var(--space-4) var(--space-6);border-top:1px solid var(--color-neutral-900)}
.item:hover{background:color-mix(in srgb,var(--color-text) 3%,transparent)}
.item .name{font-family:var(--mono);font-size:14px}
.foot{padding:var(--space-4) var(--space-6);border-top:1px solid var(--color-neutral-900);font-size:13px;color:var(--color-neutral-400)}
.note{padding:var(--space-4);border-radius:var(--radius-md);font-size:13px}
.note-ok{box-shadow:0 0 0 1px var(--color-accent-700);background:color-mix(in srgb,var(--color-accent) 6%,transparent)}
.note-warn{box-shadow:0 0 0 1px #8a5a4a;background:color-mix(in srgb,#d0705a 8%,transparent)}
.urlbox{flex:1;min-width:0;font-family:var(--mono);font-size:13px;background:var(--color-bg)}
pre.cmd{margin:0;padding:10px 12px;border-radius:var(--radius-md);background:var(--color-bg);box-shadow:var(--shadow-sm);
 font:12px/1.6 var(--mono);white-space:pre-wrap;word-break:break-all;user-select:all}
pre.cmd .prompt{color:var(--color-accent);user-select:none}

details>summary{list-style:none;cursor:pointer}details>summary::-webkit-details-marker{display:none}
.chev{color:var(--color-neutral-500);transition:transform .15s}
.rename>summary{display:inline-flex}.rename[open]>summary{color:var(--color-text)}details[open]>summary .chev{transform:rotate(180deg)}
.disclosure>summary{display:flex;align-items:center;gap:var(--space-4);padding:var(--space-4) var(--space-6)}
.disclosure>summary:hover{background:color-mix(in srgb,var(--color-text) 3%,transparent)}
.grant{border-radius:var(--radius-lg);background:var(--color-surface);box-shadow:var(--shadow-sm);overflow:hidden}
.grant[open]{box-shadow:var(--shadow-md)}
.grant-body{display:flex;flex-direction:column;gap:var(--space-6);padding:var(--space-4) var(--space-6) var(--space-6);
 border-top:1px solid var(--color-neutral-900)}
.chip{font-size:11px;padding:1px 6px;border-radius:var(--radius-sm);background:var(--color-neutral-900);color:var(--color-neutral-300)}
.grid-scroll{overflow-x:auto}
.grid{display:grid;align-items:center;gap:var(--space-2);min-width:520px}
.grid-head{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--color-neutral-500);padding-bottom:var(--space-2)}
.grid-row{padding:var(--space-2) 0;border-top:1px solid var(--color-neutral-900)}
.grid-row.out .devname{color:var(--color-neutral-500)}
.grid-sep{grid-column:1/-1;padding-top:var(--space-3);border-top:1px solid var(--color-neutral-900);font-size:12px;color:var(--color-neutral-500)}
.cell{display:grid;place-items:center}
.cell label{display:grid;place-items:center;width:30px;height:30px;border-radius:var(--radius-sm);cursor:pointer}
.cell label:hover{background:color-mix(in srgb,var(--color-text) 7%,transparent)}
.cell label.beyond{outline:1px dashed var(--color-accent);outline-offset:-1px}
.cell input{accent-color:var(--color-accent);width:15px;height:15px;margin:0;cursor:pointer}
.cell .deny{color:var(--color-neutral-700);font-size:13px;cursor:help}
.legend{display:flex;flex-wrap:wrap;gap:var(--space-4);font-size:11px;color:var(--color-neutral-500)}
.swatch{width:12px;height:12px;border-radius:3px;outline:1px dashed var(--color-accent);outline-offset:-1px;display:inline-block}
.log{display:grid;grid-template-columns:110px minmax(0,1fr);gap:var(--space-2) var(--space-3);font-size:12px}
.log .at{font-family:var(--mono);color:var(--color-neutral-600)}.log .what{color:var(--color-neutral-300)}
.mono-badge{width:34px;height:34px;flex:none;border-radius:var(--radius-md);background:var(--color-neutral-900);
 box-shadow:var(--shadow-sm);display:grid;place-items:center;font:12px var(--mono);color:var(--color-neutral-300)}
.steps{list-style:none;margin:0;padding:0 var(--space-6) var(--space-6) 74px;display:flex;flex-direction:column;gap:var(--space-4)}
.steps li{display:flex;gap:var(--space-3)}
.num{width:20px;height:20px;flex:none;border-radius:50%;background:var(--color-neutral-900);color:var(--color-neutral-300);
 display:grid;place-items:center;font:11px var(--mono)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:var(--space-4)}
.big{font-size:36px;font-weight:500;letter-spacing:-.02em;line-height:1.1}
.chart{display:grid;grid-template-columns:48px minmax(0,1fr);gap:var(--space-3)}
.yaxis{display:flex;flex-direction:column;justify-content:space-between;height:200px;font:11px var(--mono);
 color:var(--color-neutral-600);text-align:right}
.bars{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:var(--space-3);align-items:end;height:200px;
 border-bottom:1px solid var(--color-neutral-800)}
.bar{background:var(--color-accent-700);border-top:2px solid var(--color-accent);border-radius:var(--radius-sm) var(--radius-sm) 0 0}
.bar:hover{background:var(--color-accent-600)}
.xaxis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:var(--space-3);font:11px var(--mono);
 color:var(--color-neutral-500);text-align:center}
.tabs{display:grid;grid-template-columns:repeat(2,1fr);border:1px solid var(--color-divider);border-radius:var(--radius-md);overflow:hidden}
.tabs a{padding:8px;text-align:center;font-size:13px;color:var(--color-neutral-400);text-decoration:none}
.tabs a:hover{background:color-mix(in srgb,var(--color-text) 6%,transparent)}
.tabs a[aria-current=page]{color:var(--color-accent);box-shadow:inset 0 0 0 1px var(--color-accent)}
.method{border-radius:var(--radius-md);box-shadow:var(--shadow-sm)}.method[open]{box-shadow:0 0 0 1px var(--color-accent-700)}
.method>summary{display:flex;align-items:center;gap:var(--space-3);padding:var(--space-4)}
.method-body{display:flex;flex-direction:column;gap:var(--space-3);padding:0 var(--space-4) var(--space-4)}
.stepper{display:flex;gap:var(--space-6);flex-wrap:wrap}
.stepper span{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--color-neutral-600)}
.stepper span.on{color:var(--color-accent)}
.stepper b{width:18px;height:18px;border-radius:50%;display:grid;place-items:center;font-size:10px;font-weight:400;border:1px solid currentColor}
.center{min-height:100vh;display:grid;place-items:center;padding:var(--space-6)}
.card{width:min(400px,100%);display:flex;flex-direction:column;gap:var(--space-4);padding:var(--space-8);
 border-radius:var(--radius-lg);background:var(--color-surface);box-shadow:var(--shadow-lg)}
.actions{display:flex;justify-content:flex-end;gap:var(--space-2);flex-wrap:wrap}

@media (max-width:760px){
 .app{grid-template-columns:minmax(0,1fr)}
 .side{min-width:0}
 .side{position:static;height:auto;border-right:0;border-bottom:1px solid var(--color-neutral-900);gap:var(--space-4);padding:var(--space-4)}
 .nav{flex-direction:row;overflow-x:auto}.nav a{flex:none}.nav .badge,.nav .ext{display:none}
 .side-foot{display:none}
 main{padding:var(--space-8) 16px 64px}
 .item,.list-head,.foot,.disclosure>summary{padding-left:var(--space-4);padding-right:var(--space-4)}
 .grant-body{padding-left:var(--space-4);padding-right:var(--space-4)}
 .steps{padding-left:var(--space-6)}
 h2{font-size:26px}
}
"""
)

_ICONS = {
    "bridge": '<path d="M3 17h18M6 17v-5M18 17v-5M12 17v-3M3 9c3.5 0 5.5 3 9 3s5.5-3 9-3"/>',
    "desktop": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "plugs": '<path d="M10 14a3.5 3.5 0 0 0 5 0l3-3a3.5 3.5 0 0 0-5-5l-1 1"/>'
             '<path d="M14 10a3.5 3.5 0 0 0-5 0l-3 3a3.5 3.5 0 0 0 5 5l1-1"/>',
    "chart": '<path d="M4 20h16M7 16v-5M12 16V7M17 16V9"/>',
    "gear": '<circle cx="12" cy="12" r="3"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8'
            'M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8"/>',
    "question": '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.4a2.5 2.5 0 1 1 3.4 2.4c-.6.3-1 .8-1 1.5v.5M12 17h.01"/>',
    "external": '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "left": '<path d="M19 12H5M11 6l-6 6 6 6"/>',
    "right": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "caret": '<path d="M6 9l6 6 6-6"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 20c1.5-4 4.5-6 8-6s6.5 2 8 6"/>',
    "shield": '<path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    "download": '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
    "x": '<path d="M6 6l12 12M18 6L6 18"/>',
    "pending": '<path d="M12 3a9 9 0 1 0 9 9"/>',
}


def icon(name: str) -> str:
    return f'<svg class="i" viewBox="0 0 24 24" aria-hidden="true">{_ICONS[name]}</svg>'


def esc(value: object) -> str:
    return html.escape(str(value))


def hidden(name: str, value: str) -> str:
    return f'<input type="hidden" name="{esc(name)}" value="{esc(value)}">'


NAV = (
    ("devices", "/devices", "Devices", "desktop"),
    ("endpoints", "/devices/endpoints", "Endpoints", "plugs"),
    ("usage", "/devices/usage", "Usage", "chart"),
    ("settings", "/devices/settings", "Settings", "gear"),
)


def shell(content: str, *, current: str, device_count: int, gateway: str, calls_this_month: int) -> str:
    """The signed-in layout: the sidebar (pages, gateway status, owner) and the page content."""
    nav = "".join(
        f'<a href="{href}"{" aria-current=page" if key == current else ""}>{icon(ic)}<span class="label">{label}</span>'
        f'<span class="badge">{device_count if key == "devices" else ""}</span></a>'
        for key, href, label, ic in NAV
    )
    calls = f"{calls_this_month:,} tool call{'s' if calls_this_month != 1 else ''} this month"
    return f"""<div class="app">
<aside class="side">
 <div class="brand">{logo(30)}<div><b>ContextBridge</b><span>Remote MCP</span></div></div>
 <nav class="nav" aria-label="Dashboard">{nav}
  <a href="https://github.com/Deep-Sixed/ContextBridge#readme" target="_blank" rel="noopener noreferrer">{icon("question")}
  <span class="label">Help center</span><span class="ext">{icon("external")}</span></a>
 </nav>
 <div class="side-foot">
  <div class="gw"><div class="gw-top"><span>Gateway</span><span class="gw-run"><span class="dot on"></span>Running</span></div>
  <span class="mono">{esc(gateway)}</span><span class="faint">{esc(calls)}</span></div>
  <div class="owner"><span class="avatar">{icon("user")}</span>Gateway owner</div>
 </div>
</aside>
<main><div class="content">{content}</div></main>
</div>"""


def centered(content: str) -> str:
    """A single card in the middle of the page: sign-in and confirmations."""
    return f'<div class="center"><div class="card">{content}</div></div>'
