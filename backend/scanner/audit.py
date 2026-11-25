import time

from backend.scanner.browser import scan_website
from backend.scanner.consent import scan_consent_behavior
from backend.scanner.contradiction import find_contradictions
from backend.scanner.cookies import analyze_cookies, cookie_summary
from backend.scanner.domains import get_hostname, get_registered_domain, is_third_party
from backend.scanner.ledger import EvidenceLedger
from backend.scanner.pii_leak import scan_pii_leaks
from backend.scanner.policy_llm import extract_policy_claims
from backend.scanner.privacy_policy import _extract_topics, get_policy_text
from backend.scanner.privacy_signals import scan_privacy_signals
from backend.scanner.scoring import risk_score
from backend.scanner.trackers import find_tracker

CONSENT_DETAIL_KEYS = (
    "consent_button", "request_count", "requests_before_action",
    "third_party_request_count", "tracker_count",
    "cookie_count_before_action", "cookie_count_after_action",
    "navigation_error",
)


# ---------------------------------------------------------------- helpers

def _to_pw(c: dict) -> dict:
    """consent.py cookie snapshot -> Playwright cookie format."""
    return {
        "name": c.get("name"), "domain": c.get("domain"), "path": c.get("path"),
        "secure": c.get("secure", False), "httpOnly": c.get("http_only", False),
        "sameSite": c.get("same_site"), "expires": c.get("expires"),
    }


def _analyze_cookies(snapshot: list, page_url: str) -> list:
    items = analyze_cookies([_to_pw(c) for c in snapshot], page_url)
    for c in items:
        c["attributed_to"] = None
        if c["category"] == "unknown":
            t = find_tracker((c.get("domain") or "").lstrip("."))
            if t:
                c["category"] = t["category"]
                c["attributed_to"] = t["name"]
    return items


def _is_tracker_cookie(c: dict) -> bool:
    return c["category"] not in ("essential", "unknown")


def _tracker_cookie_table(before: list, rejected: list, accepted: list) -> list:
    key = lambda c: (c["name"], c["domain"])
    seen = {
        "before_choice": {key(c) for c in before if _is_tracker_cookie(c)},
        "after_reject": {key(c) for c in rejected if _is_tracker_cookie(c)},
        "after_accept": {key(c) for c in accepted if _is_tracker_cookie(c)},
    }
    merged = {}
    for c in before + rejected + accepted:
        if _is_tracker_cookie(c):
            merged.setdefault(key(c), c)

    rows = []
    for k, c in merged.items():
        rows.append({
            "name": c["name"], "domain": c["domain"], "category": c["category"],
            "attributed_to": c["attributed_to"], "party": c["party"],
            "before_choice": k in seen["before_choice"],
            "after_reject": k in seen["after_reject"],
            "after_accept": k in seen["after_accept"],
        })
    return sorted(rows, key=lambda r: (not r["after_reject"], not r["before_choice"], r["name"] or ""))


def _tracker_table(none_t: list, reject_t: list, accept_t: list) -> list:
    by = {}
    for label, lst in (("before_choice", none_t), ("after_reject", reject_t), ("after_accept", accept_t)):
        for t in lst:
            row = by.setdefault(t["domain"], {
                "name": t["name"], "company": t["company"], "category": t["category"],
                "domain": t["domain"], "requests": 0,
                "before_choice": False, "after_reject": False, "after_accept": False,
            })
            row[label] = True
            row["requests"] = max(row["requests"], len(t.get("requests", [])))
    return sorted(by.values(), key=lambda r: (not r["before_choice"], r["name"] or ""))


def _third_party_table(requests: list, page_url: str) -> list:
    agg = {}
    for r in requests:
        u = r.get("url", "")
        if not is_third_party(u, page_url):
            continue
        host = get_hostname(u)
        dom = get_registered_domain(host)
        if not dom:
            continue
        row = agg.setdefault(dom, {
            "domain": dom, "requests": 0, "resource_types": set(), "hosts": set(),
            "tracker": None, "company": None, "category": None,
        })
        row["requests"] += 1
        row["resource_types"].add(r.get("resource_type"))
        row["hosts"].add(host)
        if row["tracker"] is None:
            t = find_tracker(host)
            if t:
                row.update(tracker=t["name"], company=t["company"], category=t["category"])

    out = []
    for row in agg.values():
        row["resource_types"] = sorted(x for x in row["resource_types"] if x)
        row["hosts"] = sorted(row["hosts"])[:5]
        out.append(row)
    return sorted(out, key=lambda r: (r["tracker"] is None, -r["requests"]))


def _safe_storage(raw: dict) -> dict:
    """Keys and sizes only. Stored values may hold identifiers."""
    def sizes(d):
        return [{"key": k, "bytes": len(str(v))} for k, v in (d or {}).items()]
    return {
        "local_storage": sizes(raw.get("local_storage")),
        "session_storage": sizes(raw.get("session_storage")),
        "indexed_db": raw.get("indexed_db", []),
        "cache_storage": raw.get("cache_storage", []),
        "service_workers": raw.get("service_workers", []),
    }


# ------------------------------------------------------------------ audit

def full_audit(url: str, on_progress=None) -> dict:
    ledger = EvidenceLedger(url)
    timings = {}

    def timed(name, fn, *args):
        if on_progress:
            on_progress(name)
        start = time.time()
        try:
            return fn(*args)
        finally:
            timings[name] = round(time.time() - start, 1)

    # 1. Site scan (domains, storage, network, screenshot)
    site = None
    try:
        site = timed("1/6 site scan", scan_website, url)
        ledger.add("site_scan", {
            "scan_info": site["scan_info"],
            "storage_summary": site["storage"]["summary"],
            "total_requests": site["network"]["total_requests"],
        })
    except Exception as exc:
        ledger.add("site_scan_error", {"error": type(exc).__name__})

    # 2. Consent behaviour
    consent = timed("2/6 consent scan", scan_consent_behavior, url)
    ledger.add("consent", consent["comparison"])

    # 3. GPC / DNT + fingerprinting
    signals = timed("3/6 GPC/DNT + fingerprint scan", scan_privacy_signals, url)
    ledger.add("gpc_dnt", signals["comparison"])

    # 4. Canary PII test
    leaks = timed("4/6 PII canary test", scan_pii_leaks, url)
    ledger.add("pii_leaks", leaks["leaks"])

    # 5. Policy fetch
    policy = timed("5/6 fetch policy", get_policy_text, url)
    ledger.add("policy_source", {"url": policy["url"], "chars": len(policy["text"])})

    # 6. Claim extraction
    claims = {}
    if policy["text"]:
        try:
            claims = timed("6/6 claim extraction", extract_policy_claims, policy["text"])
        except Exception as exc:
            ledger.add("policy_llm_error", {"error": type(exc).__name__})
    ledger.add("policy_claims", claims)

    if on_progress:
        on_progress("building report")

    sc = consent["scenarios"]
    final_url = (site or {}).get("scan_info", {}).get("final_url") or sc["none"]["final_url"]

    # Cookies per consent scenario, classified
    ck_before = _analyze_cookies(sc["none"]["cookies_after_action"], final_url)
    ck_reject = _analyze_cookies(sc["reject"]["cookies_after_action"], final_url)
    ck_accept = _analyze_cookies(sc["accept"]["cookies_after_action"], final_url)
    tracker_cookies = _tracker_cookie_table(ck_before, ck_reject, ck_accept)

    requests = site["network"]["requests"] if site else sc["accept"]["requests"]
    third_parties = _third_party_table(requests, final_url)
    trackers = _tracker_table(sc["none"]["trackers"], sc["reject"]["trackers"], sc["accept"]["trackers"])

    # Fingerprinting (baseline run), evidence trimmed to frame URLs
    fp = signals["baseline"].get("fingerprinting", {})
    fp_findings = [{
        "code": f["code"], "severity": f["severity"], "message": f["message"],
        "observed_calls": f["observed_calls"],
        "evidence": sorted({e["frame_url"] for e in f["evidence"]})[:5],
    } for f in fp.get("findings", [])]

    policy_topics = _extract_topics(policy["text"]) if policy["text"] else {}

    observed = {
        "trackers": sc["accept"]["trackers"],
        "third_party_domains": sc["accept"]["third_party_domains"],
        "pii_leaks": leaks["leaks"],
        "trackers_before_consent": [t["name"] for t in sc["none"]["trackers"]],
        "trackers_after_reject": [t["name"] for t in sc["reject"]["trackers"]],
        "gpc_trackers_remaining": signals["comparison"]["signals_on_tracker_domains"],
    }
    contradictions = find_contradictions(claims, observed) if claims else []
    dark = sc["none"].get("dark_patterns") or {"findings": []}

    # Cookie findings
    cookie_findings = []
    label = lambda r: f'{r["name"]} ({r["domain"]})'
    pre = [label(r) for r in tracker_cookies if r["before_choice"]]
    post = [label(r) for r in tracker_cookies if r["after_reject"]]
    if pre:
        cookie_findings.append({
            "id": "TRACKER_COOKIES_BEFORE_CHOICE", "severity": "high",
            "message": "Analytics/advertising cookies were set before any consent choice.",
            "evidence": pre[:20],
        })
    if post and sc["reject"]["consent_button"]["clicked"]:
        cookie_findings.append({
            "id": "TRACKER_COOKIES_AFTER_REJECT", "severity": "high",
            "message": "Analytics/advertising cookies were present after the reject action.",
            "evidence": post[:20],
        })

    findings = (
        consent["comparison"]["findings"] + dark["findings"]
        + cookie_findings + fp_findings + contradictions
    )
    ledger.add("findings", findings)

    return {
        "url": url,
        "policy_url": policy["url"],
        "score": risk_score(findings),
        "contradictions": contradictions,
        "dark_patterns": dark,
        "claims": claims,
        "policy_topics": policy_topics,
        "consent": consent["comparison"],
        "consent_detail": {
            name: {k: s.get(k) for k in CONSENT_DETAIL_KEYS} for name, s in sc.items()
        },
        "pii_leaks": leaks,
        "site": {
            "scan_info": (site or {}).get("scan_info", {}),
            "total_requests": (site or {}).get("network", {}).get("total_requests"),
            "first_party_domains": (site or {}).get("domains", {}).get("first_party_domains", []),
            "third_party_domains": (site or {}).get("domains", {}).get("third_party_domains", []),
        },
        "cookies": {"summary": cookie_summary(ck_accept), "items": ck_accept[:150]},
        "tracker_cookies": tracker_cookies,
        "trackers": trackers,
        "third_parties": third_parties,
        "storage": _safe_storage(site["storage"]["items"]) if site else {},
        "fingerprinting": {
            "api_call_counts": fp.get("api_call_counts", {}),
            "events_observed": fp.get("events_observed", 0),
            "frames_checked": fp.get("frames_checked", 0),
            "findings": fp_findings,
        },
        "privacy_signals": {
            "gpc_dnt_browser_values": signals["signals_on"]["browser_values"],
            "comparison": signals["comparison"],
        },
        "timings_seconds": timings,
        "evidence_root_hash": ledger.root,
        "ledger_valid": ledger.verify(),
        "ledger": ledger.entries,
        "_screenshot_src": (site or {}).get("screenshot"),
    }