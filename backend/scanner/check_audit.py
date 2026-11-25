import json
import sys
import time

import requests

BASE = "http://localhost:8000"
url = sys.argv[1] if len(sys.argv) > 1 else "https://www.iiitg.ac.in/"

job = requests.post(f"{BASE}/audit", json={"url": url}).json()
print("job:", job)
job_id = job["job_id"]

while True:
    data = requests.get(f"{BASE}/audit/{job_id}").json()
    print("status:", data["status"])
    if data["status"] in ("done", "failed"):
        break
    time.sleep(10)

if data["status"] == "failed":
    print("ERROR:", data["error"])
else:
    r = data["result"]
    print("Score:", r["score"]["score"], r["score"]["grade"])
    print("Ledger valid:", r["ledger_valid"])
    print("Claims method:", r["claims"].get("_method"))
    for c in r["contradictions"]:
        print(" -", c["id"], "|", c["evidence"])
    with open("audit_report.json", "w", encoding="utf-8") as f:
        json.dump(r, f, indent=2, default=str)
    print("saved audit_report.json")