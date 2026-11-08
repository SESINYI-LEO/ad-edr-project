"""Capture dashboard screenshots from a running server (used for the Chapter 4 figures)."""
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "shots"); OUT.mkdir(exist_ok=True)

with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium", args=["--no-sandbox"]) if Path("/opt/pw-browsers/chromium").exists() else p.chromium.launch(args=["--no-sandbox"])
    ctx = b.new_context(viewport={"width": 1440, "height": 900}, color_scheme="light")
    pg = ctx.new_page()
    errs = []
    pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
    def shot(n): pg.wait_for_timeout(600); pg.screenshot(path=str(OUT / f"{n}.png")); print("shot", n)
    pg.goto(BASE); shot("01_login")
    pg.fill("input[autocomplete=username]", "admin"); pg.fill("input[type=password]", "Admin@EDR-2026!"); pg.click("button.primary")
    pg.wait_for_selector("text=Overview"); shot("02_overview")
    pg.click("nav a:has-text('Administration')"); pg.click("button:has-text('Enrol this browser')"); pg.wait_for_selector("text=Enrolled device"); shot("02b_device_enrolment")
    pg.click("nav a:has-text('Alerts')"); pg.wait_for_selector("tbody tr"); shot("03_alerts")
    pg.click("tbody tr:has-text('LSASS')"); pg.wait_for_selector("text=Responsible identity"); shot("04_alert_detail"); pg.click("button:has-text('Close')")
    pg.click("nav a:has-text('Tickets')"); pg.wait_for_selector("tbody tr"); shot("05_tickets")
    pg.click("nav a:has-text('Incidents')"); pg.wait_for_selector("tbody tr"); shot("06_incidents")
    pg.click("tbody tr >> nth=0"); pg.wait_for_selector("text=Timeline"); shot("07_incident_report")
    pg.click("nav a:has-text('Endpoints')"); pg.wait_for_selector("tbody tr"); pg.click("tbody tr:has-text('WS-A10')"); pg.wait_for_selector("text=Recent events"); shot("08_endpoints")
    pg.click("nav a:has-text('Detection rules')"); pg.wait_for_selector("tbody tr"); shot("09_rules")
    pg.click("tbody tr:has-text('R001') button"); pg.wait_for_selector("text=Biometric verification"); shot("10_verify_qr")
    pg.click("button:has-text('fingerprint does not match')") if False else pg.click("text=Fingerprint does not match"); pg.wait_for_selector("text=Verification failed"); shot("11_verify_failed")
    pg.click("button:has-text('Cancel')")
    pg.click("nav a:has-text('Audit log')"); pg.wait_for_selector("tbody tr"); pg.click("text=Verify integrity"); pg.wait_for_selector("text=Chain intact"); shot("12_audit")
    pg.click("nav a:has-text('Administration')"); pg.click("button:has-text('Backup')"); pg.wait_for_selector("text=Backups"); shot("13_admin_backups")
    pg.click("button:has-text('Tool terminal')"); shot("14_tool_terminal")
    print("console errors:", errs)
    b.close()
