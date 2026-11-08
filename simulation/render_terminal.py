"""Render a text file as a terminal-style PNG (for report figures). usage: render_terminal.py in.txt out.png [title] [maxlines]"""
import sys, html
from pathlib import Path
from playwright.sync_api import sync_playwright
src, out = sys.argv[1], sys.argv[2]; title = sys.argv[3] if len(sys.argv) > 3 else ""; mx = int(sys.argv[4]) if len(sys.argv) > 4 else 60
lines = Path(src).read_text().splitlines()[:mx]
def col(l):
    e = html.escape(l)
    return (e.replace("PASSED", '<span style="color:#3fb950">PASSED</span>').replace("FAILED", '<span style="color:#f85149">FAILED</span>')
            if "passed" not in l.lower() or "PASSED" in l else f'<span style="color:#3fb950">{e}</span>')
body = "\n".join(col(l) for l in lines)
page = f'<body style="margin:0;background:#0d1117"><div style="padding:14px 18px;color:#c9d1d9;font:13px/1.45 Consolas,Menlo,DejaVu Sans Mono,monospace;width:1180px"><div style="color:#8b949e;margin-bottom:8px">$ {html.escape(title)}</div><pre style="margin:0;white-space:pre-wrap">{body}</pre></div></body>'
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium", args=["--no-sandbox"]); pg = b.new_page(viewport={"width": 1220, "height": 200})
    pg.set_content(page); pg.locator("div").first.screenshot(path=out); b.close()
