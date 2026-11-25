import base64
import hashlib
import secrets
import urllib.parse

from playwright.sync_api import sync_playwright

from backend.scanner.domains import get_hostname, is_third_party
from backend.scanner.trackers import find_tracker

EMAIL_SELECTORS = (
    "input[type='email'], input[name*='email' i], "
    "input[id*='email' i], input[placeholder*='email' i]"
)


def make_canary() -> str:
    return f"canary{secrets.token_hex(4)}@example.com"


def canary_variants(value: str) -> dict:
    """All encodings a tracker might use for an email."""
    v = value.lower().strip()
    raw = v.encode()
    return {
        "plaintext": v,
        "urlencoded": urllib.parse.quote(v, safe=""),
        "base64": base64.b64encode(raw).decode(),
        "md5": hashlib.md5(raw).hexdigest(),
        "sha1": hashlib.sha1(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def scan_pii_leaks(url: str) -> dict:
    canary = make_canary()
    variants = canary_variants(canary)
    captured = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()

        def on_request(req):
            try:
                body = req.post_data or ""
            except Exception:
                body = ""
            captured.append({
                "url": req.url,
                "method": req.method,
                "body": body[:20000],
                "time_ms": 0,
            })

        context.on("request", on_request)
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(3000)

            fields = page.locator(EMAIL_SELECTORS)
            filled = 0
            for i in range(min(fields.count(), 3)):
                f = fields.nth(i)
                try:
                    if f.is_visible():
                        f.click(timeout=2000)
                        f.type(canary, delay=40)   # real key events
                        f.blur()                   # many trackers fire on blur
                        filled += 1
                except Exception:
                    continue

            page.wait_for_timeout(3000)
            final_url = page.url
        finally:
            browser.close()

    leaks = []
    for item in captured:
        haystack = urllib.parse.unquote(item["url"]) + " " + item["body"]
        haystack_raw = item["url"] + " " + item["body"]
        for kind, token in variants.items():
            if token in haystack or token in haystack_raw:
                host = get_hostname(item["url"])
                tracker = find_tracker(host)
                leaks.append({
                    "encoding": kind,
                    "destination": host,
                    "third_party": is_third_party(item["url"], final_url),
                    "known_tracker": tracker["name"] if tracker else None,
                    "company": tracker["company"] if tracker else None,
                    "method": item["method"],
                    "in": "url" if token in item["url"] else "body",
                    "hashed": kind not in ("plaintext", "urlencoded"),
                })
                break

    return {
        "canary_used": "synthetic email (not a real address)",
        "fields_filled": filled,
        "leak_count": len(leaks),
        "third_party_leaks": [l for l in leaks if l["third_party"]],
        "leaks": leaks,
        "limitations": [
            "Only email-type inputs are tested; forms are never submitted.",
            "Leaks via encodings not listed here are missed.",
        ],
    }