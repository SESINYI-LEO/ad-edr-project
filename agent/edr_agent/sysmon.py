"""Parse Sysmon / Windows Security XML events into the EDR telemetry schema."""
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SENSITIVE_MAX = 8192


def _ts(system_time: str) -> str:
    """'2026-10-19T08:00:00.123456789Z' -> ISO-8601 UTC with microsecond precision."""
    s = system_time.rstrip("Z")
    if "." in s:
        head, frac = s.split(".")
        s = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).isoformat()


def parse_event_xml(xml_text: str) -> dict | None:
    """Return an EDR event dict for supported event IDs, otherwise None. Never raises on malformed input."""
    try:
        root = ET.fromstring(xml_text)
        sysel = root.find("e:System", NS)
        eid = int(sysel.find("e:EventID", NS).text)
        provider = sysel.find("e:Provider", NS).get("Name", "")
        when = _ts(sysel.find("e:TimeCreated", NS).get("SystemTime"))
        data = {d.get("Name"): (d.text or "") for d in root.findall("e:EventData/e:Data", NS)}
    except (ET.ParseError, AttributeError, TypeError, ValueError):
        return None

    if "Sysmon" in provider:
        if eid == 1:
            return {"event_type": "process_create", "timestamp": when, "process_name": data.get("Image"),
                    "parent_process": data.get("ParentImage"), "command_line": data.get("CommandLine", "")[:SENSITIVE_MAX],
                    "user": data.get("User"), "details": {"pid": int(data.get("ProcessId") or 0)}}
        if eid == 3:
            return {"event_type": "network_connect", "timestamp": when, "process_name": data.get("Image"),
                    "user": data.get("User"),
                    "details": {"dest_ip": data.get("DestinationIp"), "dest_port": int(data.get("DestinationPort") or 0),
                                "protocol": data.get("Protocol")}}
        if eid == 10:
            return {"event_type": "process_access", "timestamp": when, "process_name": data.get("SourceImage"),
                    "user": data.get("SourceUser"),
                    "details": {"target_process": data.get("TargetImage"), "granted_access": (data.get("GrantedAccess") or "").lower()}}
        if eid == 11:
            return {"event_type": "file_create", "timestamp": when, "process_name": data.get("Image"),
                    "user": data.get("User"), "details": {"file_path": data.get("TargetFilename")}}
        if eid == 13:
            return {"event_type": "registry_set", "timestamp": when, "process_name": data.get("Image"),
                    "user": data.get("User"), "details": {"registry_key": data.get("TargetObject"),
                                                          "value": (data.get("Details") or "")[:500]}}
        return None
    if provider == "Microsoft-Windows-Security-Auditing" and eid in (4624, 4625):
        dom, usr = data.get("TargetDomainName", ""), data.get("TargetUserName", "")
        return {"event_type": "logon_success" if eid == 4624 else "logon_failure", "timestamp": when,
                "user": f"{dom}\\{usr}" if dom else usr,
                "details": {"logon_type": int(data.get("LogonType") or 0), "source_ip": data.get("IpAddress")}}
    return None
