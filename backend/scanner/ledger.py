import hashlib
import json
import time


class EvidenceLedger:
    """Hash-chained log: altering any entry breaks every later hash."""

    def __init__(self, target_url: str):
        self.entries = []
        self.add("scan_started", {"url": target_url})

    def add(self, kind: str, data: dict):
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        body = {"ts": time.time(), "kind": kind, "data": data, "prev": prev}
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True, default=str).encode()
        ).hexdigest()
        self.entries.append({**body, "hash": digest})

    def verify(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            body = {k: e[k] for k in ("ts", "kind", "data", "prev")}
            h = hashlib.sha256(
                json.dumps(body, sort_keys=True, default=str).encode()
            ).hexdigest()
            if e["prev"] != prev or e["hash"] != h:
                return False
            prev = e["hash"]
        return True

    @property
    def root(self) -> str:
        return self.entries[-1]["hash"]