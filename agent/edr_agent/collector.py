"""Windows collectors: poll Sysmon and Security logs with wevtutil, remembering the last EventRecordID."""
import json
import logging
import platform
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from .sysmon import NS, parse_event_xml

log = logging.getLogger("edr_agent")
CHANNELS = {"Microsoft-Windows-Sysmon/Operational": None,
            "Security": "*[System[(EventID=4624 or EventID=4625)]]"}


class WindowsCollector:
    def __init__(self, state_dir: str, max_per_poll: int = 500):
        self.state = Path(state_dir) / "bookmarks.json"
        self.marks = json.loads(self.state.read_text()) if self.state.exists() else {}
        self.max = max_per_poll

    def poll(self) -> list[dict]:
        if platform.system() != "Windows":
            raise RuntimeError("WindowsCollector can only run on Windows")
        out = []
        for channel, xpath in CHANNELS.items():
            last = self.marks.get(channel, 0)
            q = f"*[System[EventRecordID>{last}]]" if xpath is None else f"{xpath}"
            cmd = ["wevtutil", "qe", channel, f"/q:{q}", "/f:xml", f"/c:{self.max}", "/rd:false"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True)
            except (subprocess.SubprocessError, OSError) as exc:
                log.error("wevtutil failed for %s: %s", channel, exc)
                continue
            for chunk in res.stdout.split("</Event>"):
                if "<Event" not in chunk:
                    continue
                xml = chunk[chunk.index("<Event"):] + "</Event>"
                try:
                    rid = int(ET.fromstring(xml).find("e:System/e:EventRecordID", NS).text)
                except (ET.ParseError, AttributeError, ValueError):
                    continue
                if rid <= last and xpath is None:
                    continue
                last = max(last, rid)
                ev = parse_event_xml(xml)
                if ev:
                    out.append(ev)
            self.marks[channel] = last
        self.state.write_text(json.dumps(self.marks))
        return out
