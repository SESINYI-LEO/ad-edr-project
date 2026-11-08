import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from agent import parse_sysmon

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
def ev(eid, rec, data):
    d = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event xmlns='{NS}'><System><EventID>{eid}</EventID><EventRecordID>{rec}</EventRecordID>"
            f"<TimeCreated SystemTime='2026-10-06T10:00:00.000000000Z'/></System><EventData>{d}</EventData></Event>")

def test_sysmon_mapping():
    xml = (ev(1, 10, {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "CommandLine": "powershell -enc AAAA",
                      "ProcessId": "4820", "ParentImage": r"C:\Program Files\Word\winword.exe", "User": r"CORP\tshepo"})
           + ev(3, 11, {"Image": r"C:\x\a.exe", "DestinationIp": "1.2.3.4", "DestinationPort": "4444", "User": r"CORP\tshepo"})
           + ev(13, 12, {"Image": r"C:\Windows\reg.exe", "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X"})
           + ev(5, 13, {"Image": "x"}))
    out = parse_sysmon(xml)
    assert out[0]["event_type"] == "powershell" and out[0]["process_id"] == 4820 and out[0]["parent_process"] == "winword.exe"
    assert out[0]["raw_username"] == "CORP\\tshepo"
    assert out[1]["event_type"] == "network" and out[1]["remote_port"] == 4444
    assert out[2]["event_type"] == "registry" and "\\Run\\" in out[2]["registry_key"]
    assert out[3].get("_skip") and out[3]["_rec"] == 13
