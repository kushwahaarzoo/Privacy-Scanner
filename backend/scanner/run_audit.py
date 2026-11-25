import json
import sys

from backend.scanner.audit import full_audit

url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
result = full_audit(url)

print("Score :", result["score"]["score"], result["score"]["grade"])
print("Ledger valid:", result["ledger_valid"])
print("Root hash   :", result["evidence_root_hash"])
print("\nContradictions:")
for c in result["contradictions"]:
    print(" -", c["id"], "|", c["claim"], "|", c["evidence"])

with open("audit_report.json", "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, default=str)