"""Execute every catalogued test case with pytest, write results/testcases.json and render one terminal screenshot per case."""
import html, json, re, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from simulation.testcases import CASES
from playwright.sync_api import sync_playwright

out = []
for cid, tech, title, inp, exp, req, nodes in CASES:
    cmd = ["python", "-m", "pytest", "-v", "-p", "no:cacheprovider", "--no-header", "-W", "ignore", *nodes]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    lines = [l for l in r.stdout.splitlines() if re.search(r"PASSED|FAILED|ERROR|passed|failed", l)]
    lines = [re.sub(r"\s+\[\s*\d+%\]", "", l) for l in lines]
    summ = lines[-1] if lines else "no output"
    m = re.search(r"(\d+) passed", summ); p = int(m.group(1)) if m else 0
    m = re.search(r"(\d+) failed", summ); f = int(m.group(1)) if m else 0
    out.append({"id": cid, "technique": tech, "title": title, "input": inp, "expected": exp, "requirement": req, "tests": p + f,
                "passed": p, "failed": f, "result": "Pass" if f == 0 and p > 0 else "Fail", "cmd": "pytest -v " + " ".join(sorted({n.split("::")[0] for n in nodes})) + f"  [{len(nodes)} test functions selected for {cid}]", "lines": lines})
    print(cid, summ)
Path(ROOT / "results/testcases.json").write_text(json.dumps(out, indent=1))

def render(case, path, pg):
    ls = case["lines"]
    shown = ls[:-1][:14]; extra = len(ls) - 1 - len(shown)
    def col(l): return l.replace("PASSED", '<span style="color:#3fb950">PASSED</span>').replace("FAILED", '<span style="color:#f85149">FAILED</span>')
    body = "\n".join(html.escape(l[:150]) if False else col(html.escape(l[:140])) for l in shown)
    if extra > 0: body += f'\n<span style="color:#8b949e">... {extra} more PASSED lines ...</span>'
    body += f'\n<span style="color:{"#3fb950" if case["failed"]==0 else "#f85149"}">{html.escape(ls[-1])}</span>'
    cmd = html.escape(case["cmd"][:160])
    pg.set_content(f'<body style="margin:0;background:#0d1117"><div id=b style="padding:12px 16px;color:#c9d1d9;font:14px/1.4 Consolas,Menlo,DejaVu Sans Mono,monospace;width:780px"><div style="color:#8b949e;margin-bottom:6px;word-break:break-all">$ {cmd}</div><pre style="margin:0;white-space:pre-wrap">{body}</pre></div></body>')
    pg.locator("#b").screenshot(path=str(path))

with sync_playwright() as pw:
    b = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium", args=["--no-sandbox"]); pg = b.new_page(viewport={"width": 840, "height": 200})
    for c in out: render(c, ROOT / "shots" / f"TC_{c['id'][2:]}.png", pg)
    b.close()
print("cases", len(out), "tests", sum(c["tests"] for c in out), "failed", sum(c["failed"] for c in out))
