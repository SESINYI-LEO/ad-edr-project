"""Generate the lab Active Directory fixture (lab.local) used when AD_MODE=mock."""
import json
from pathlib import Path

DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"
BASE = "DC=lab,DC=local"
U = [
    ("jsmith", "John Smith", "Finance", ["Domain Users"], "Fin@nce-2026"),
    ("mdlamini", "Mpho Dlamini", "Human Resources", ["Domain Users"], "Hr@lab-2026"),
    ("kmotsumi", "Kabo Motsumi", "Sales", ["Domain Users"], "Sales@lab-2026"),
    ("tkgosi", "Tebogo Kgosi", "IT", ["Domain Users", "Domain Admins"], "Adm1n@lab-2026"),
    ("svc_backup", "Backup Service", "IT", ["Domain Users", "Backup Operators"], "Bkp@lab-2026"),
    ("lmokoena", "Lerato Mokoena", "Finance", ["Domain Users"], "Fin2@lab-2026"),
    ("rseretse", "Roy Seretse", "Operations", ["Domain Users", "Server Operators"], "Ops@lab-2026"),
    ("analyst01", "Neo Analyst", "Security", ["Domain Users"], "Analyst@lab-2026"),
    ("admin01", "Sam Administrator", "Security", ["Domain Users", "Domain Admins"], "SecAdmin@lab-2026"),
    ("pkhumalo", "Palesa Khumalo", "Legal", ["Domain Users"], "Legal@lab-2026"),
    ("odisabled", "Old Account", "Sales", ["Domain Users"], "Old@lab-2026"),
]
users = []
for i, (sam, name, dept, groups, pw) in enumerate(U):
    users.append({"sam": sam, "sid": f"{DOMAIN_SID}-{1105 + i}", "display_name": name, "department": dept,
                  "groups": groups, "password": pw, "uac": 514 if sam == "odisabled" else 512,
                  "dn": f"CN={name},CN=Users,{BASE}"})
out = Path(__file__).with_name("lab_directory.json")
out.write_text(json.dumps({"domain": "lab.local", "users": users}, indent=2))
print("wrote", out, len(users), "users")
