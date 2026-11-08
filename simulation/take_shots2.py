"""Second batch of screenshots: flows that need the verified (biometric) path, a failed login and the analyst's restricted view."""
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "shots"); OUT.mkdir(exist_ok=True)

def login(pg, u, p):
    pg.goto(BASE); pg.fill("input[autocomplete=username]", u); pg.fill("input[type=password]", p); pg.click("button.primary")

with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium", args=["--no-sandbox"])
    # failed login
    ctx = b.new_context(viewport={"width": 1440, "height": 900}); pg = ctx.new_page()
    def shot(n): pg.wait_for_timeout(600); pg.screenshot(path=str(OUT / f"{n}.png")); print("shot", n)
    login(pg, "admin", "wrong-password"); pg.wait_for_selector("text=Invalid"); shot("15_login_failed"); ctx.close()
    # analyst (restricted)
    ctx = b.new_context(viewport={"width": 1440, "height": 900}); pg = ctx.new_page()
    login(pg, "analyst", "Analyst@EDR-2026!"); pg.wait_for_selector("text=Overview"); shot("16_analyst_view"); ctx.close()
    # admin verified flows
    ctx = b.new_context(viewport={"width": 1440, "height": 900}); pg = ctx.new_page(); pg.on("dialog", lambda d: d.accept())
    login(pg, "admin", "Admin@EDR-2026!"); pg.wait_for_selector("text=Overview")
    pg.click("nav a:has-text('Administration')"); pg.click("button:has-text('Enrol this browser')"); pg.wait_for_selector("text=Enrolled device")
    def approve():
        pg.wait_for_selector("text=Biometric verification required"); pg.click("text=Scan + fingerprint matches"); pg.wait_for_selector("text=Verified. Proceeding"); shot_n = None
    # isolation via verified biometric
    pg.click("nav a:has-text('Tickets')"); pg.wait_for_selector("tbody tr")
    row = pg.locator("tbody tr:has-text('WS-A14')")
    row.locator("button:has-text('Assigned')").click(); pg.wait_for_timeout(700)
    pg.locator("tbody tr:has-text('WS-A14')").locator("button:has-text('Under Investigation')").click(); pg.wait_for_timeout(700)
    pg.locator("tbody tr:has-text('WS-A14')").locator("button:has-text('Open incident')").click(); pg.wait_for_selector("text=Timeline")
    pg.click("button:has-text('Isolate WS-A14')"); pg.wait_for_selector("text=Biometric verification required"); pg.click("text=Scan + fingerprint matches"); pg.wait_for_selector("text=Verified. Proceeding"); pg.screenshot(path=str(OUT / "17_verified_ok.png")); print("shot 17_verified_ok")
    pg.wait_for_selector("text=network-isolated"); shot("18_isolation_executed")
    # backup create + verify
    pg.click("nav a:has-text('Administration')"); pg.click("button:has-text('Backup')"); pg.click("button:has-text('Create backup')")
    pg.wait_for_selector("text=Biometric verification required"); pg.click("text=Scan + fingerprint matches"); pg.wait_for_selector("text=Backup created"); shot("19_backup_created")
    pg.locator("tbody tr").first.locator("button:has-text('Verify')").click(); pg.wait_for_selector("text=checksum and contents valid"); shot("20_backup_verified")
    # tool terminal
    pg.click("button:has-text('Tool terminal')"); pg.select_option("select[aria-label=Tool]", "ad_lookup"); pg.fill("input[aria-label='Arguments (JSON)']", '{"sam":"tkgosi"}'); pg.click("button:has-text('Run')")
    pg.wait_for_selector("text=Biometric verification required"); pg.click("text=Scan + fingerprint matches"); pg.wait_for_selector("pre"); shot("21_tool_terminal_result")
    b.close()
