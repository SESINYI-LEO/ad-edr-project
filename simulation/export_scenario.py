"""Write scenario events as JSONL (timestamps = now) so they can be replayed by the real agent:
    python simulation/export_scenario.py A10 > simulation/sample_events.jsonl
    python simulation/export_scenario.py ALL > all.jsonl
    cd agent && python -m edr_agent.main --replay ../simulation/sample_events.jsonl
"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from simulation.scenarios import build

want = (sys.argv[1] if len(sys.argv) > 1 else "ALL").upper()
for sc in build():
    if want in ("ALL", sc["id"]):
        for e in sc["events"]:
            print(json.dumps(e))
