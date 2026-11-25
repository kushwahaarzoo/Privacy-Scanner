import json
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

GRADE_COLORS = {
    "A": "#1a7f37", "B": "#2da44e", "C": "#bf8700", "D": "#d1242f", "F": "#82071e",
}


def _ev(e):
    if e is None:
        return ""
    if isinstance(e, (list, tuple)):
        return ", ".join(
            json.dumps(x, default=str) if isinstance(x, dict) else str(x) for x in e
        )
    if isinstance(e, dict):
        return json.dumps(e, default=str)
    return str(e)


def build_pdf(result: dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
        title="Privacy Audit Report",
    )
    ss = getSampleStyleSheet()
    body = ss["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    h2 = ss["Heading2"]

    def P(text, style=body):
        return Paragraph(escape(_ev(text)), style)

    def table(rows, widths_mm):
        data = [[P(c, small) for c in row] for row in rows]
        t = Table(data, colWidths=[w * mm for w in widths_mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8ecf4")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    story = []
    score = result.get("score", {})
    grade = score.get("grade", "?")
    gcolor = GRADE_COLORS.get(grade, "#444444")

    story.append(P("Website Privacy Audit Report", ss["Title"]))
    story.append(P(f"Target: {result.get('url')}"))
    story.append(P(f"Privacy policy: {result.get('policy_url') or 'not found'}"))
    story.append(Paragraph(
        f'Score: <b>{score.get("score", "?")}/100</b> &nbsp; '
        f'Grade: <font color="{gcolor}"><b>{escape(str(grade))}</b></font>', body))
    story.append(P(f"Evidence ledger valid: {result.get('ledger_valid')}"))
    story.append(P(f"Evidence root hash (SHA-256): {result.get('evidence_root_hash')}", small))
    story.append(P(f"Claim extraction method: {result.get('claims', {}).get('_method')}", small))

    def section(title, rows, widths, empty="None observed."):
        story.append(Spacer(1, 6 * mm))
        story.append(P(title, h2))
        if len(rows) > 1:
            story.append(table(rows, widths))
        else:
            story.append(P(empty, small))

    # Findings
    rows = [["Severity", "ID", "Detail", "Evidence", "Regulations"]]
    for f in score.get("findings", []):
        rows.append([
            f.get("severity"), f.get("id") or f.get("code"),
            f.get("message") or f.get("detail") or f.get("claim"),
            _ev(f.get("evidence"))[:300], ", ".join(f.get("regulations", [])),
        ])
    section("Findings", rows, [18, 40, 45, 45, 32])

    # Contradictions
    rows = [["ID", "Policy says", "Scanner observed"]]
    for c in result.get("contradictions", []):
        rows.append([c.get("id"), c.get("claim"), _ev(c.get("evidence"))[:300]])
    section("Policy vs. observed behaviour (contradictions)", rows, [50, 65, 65])

    # Consent comparison
    cons = result.get("consent", {})
    tc, cc = cons.get("tracker_counts", {}), cons.get("cookie_counts", {})
    rows = [
        ["Metric", "Before choice", "After reject", "After accept"],
        ["Tracker domains", tc.get("before_choice"), tc.get("after_reject"), tc.get("after_accept")],
        ["Cookies", cc.get("before_choice"), cc.get("after_reject"), cc.get("after_accept")],
    ]
    section("Consent behaviour", rows, [50, 40, 45, 45])

    # Dark patterns
    dp = result.get("dark_patterns", {})
    rows = [["Severity", "ID", "Detail"]]
    for f in dp.get("findings", []):
        rows.append([f.get("severity"), f.get("id"), f.get("detail")])
    section("Consent banner dark patterns", rows, [25, 50, 105])

    # PII leaks
    leaks = result.get("pii_leaks", {})
    rows = [["Destination", "Encoding", "Third party", "Known tracker", "Found in"]]
    for l in leaks.get("leaks", []):
        rows.append([l.get("destination"), l.get("encoding"), l.get("third_party"),
                     l.get("known_tracker"), l.get("in")])
    section(
        f"Canary email leak test (fields filled: {leaks.get('fields_filled')})",
        rows, [55, 25, 25, 40, 35],
        empty="The synthetic email was not observed in any outgoing request.",
    )

    # Claims
    rows = [["Claim", "Value", "Quote", "Quote verified"]]
    for k, v in result.get("claims", {}).items():
        if isinstance(v, dict) and "value" in v:
            rows.append([k, v.get("value"), v.get("quote"), v.get("quote_verified")])
    section("Claims extracted from the privacy policy", rows, [45, 20, 90, 25],
            empty="No claims (policy not found or extraction failed).")

    # ---- Site overview
    site = result.get("site", {})
    info = site.get("scan_info", {})
    rows = [
        ["Item", "Value"],
        ["Final URL", info.get("final_url")],
        ["HTTP status", info.get("status_code")],
        ["Page title", info.get("title")],
        ["Total network requests", site.get("total_requests")],
        ["First-party domains", len(site.get("first_party_domains", []))],
        ["Third-party domains", len(site.get("third_party_domains", []))],
    ]
    section("Site overview", rows, [60, 120])

    # ---- Tracker cookies
    rows = [["Cookie", "Domain", "Category", "Attributed to", "Before choice", "After reject", "After accept"]]
    for c in result.get("tracker_cookies", []):
        rows.append([c.get("name"), c.get("domain"), c.get("category"), c.get("attributed_to"),
                     "yes" if c.get("before_choice") else "-",
                     "yes" if c.get("after_reject") else "-",
                     "yes" if c.get("after_accept") else "-"])
    section("Tracker cookies (analytics / advertising)", rows, [32, 38, 22, 26, 20, 20, 22],
            empty="No tracker cookies identified.")

    # ---- All cookies
    ck = result.get("cookies", {})
    cs = ck.get("summary", {})
    rows = [["Cookie", "Domain", "Party", "Category", "Secure", "HttpOnly", "SameSite"]]
    for c in ck.get("items", [])[:60]:
        rows.append([c.get("name"), c.get("domain"), c.get("party"), c.get("category"),
                     c.get("secure"), c.get("http_only"), c.get("same_site")])
    section(f"All cookies (total {cs.get('total', 0)}, third-party {cs.get('third_party', 0)}; first 60 shown)",
            rows, [38, 40, 22, 22, 16, 18, 24], empty="No cookies observed.")

    # ---- Trackers
    rows = [["Tracker", "Company", "Category", "Domain", "Requests", "Before choice", "After reject"]]
    for t in result.get("trackers", []):
        rows.append([t.get("name"), t.get("company"), t.get("category"), t.get("domain"),
                     t.get("requests"), "yes" if t.get("before_choice") else "-",
                     "yes" if t.get("after_reject") else "-"])
    section("Known trackers detected", rows, [30, 28, 24, 40, 14, 22, 22], empty="No known trackers detected.")

    # ---- Third parties
    rows = [["Domain", "Requests", "Resource types", "Known tracker", "Company", "Category"]]
    for t in result.get("third_parties", [])[:80]:
        rows.append([t.get("domain"), t.get("requests"), ", ".join(t.get("resource_types", [])),
                     t.get("tracker"), t.get("company"), t.get("category")])
    section("Third-party domains contacted (up to 80)", rows, [45, 18, 45, 30, 22, 20],
            empty="No third-party requests.")

    # ---- Fingerprinting
    fp = result.get("fingerprinting", {})
    rows = [["API", "Observed calls"]] + [[k, v] for k, v in fp.get("api_call_counts", {}).items()]
    section(f"Fingerprinting-related API use (events: {fp.get('events_observed')}, "
            f"frames checked: {fp.get('frames_checked')})", rows, [80, 40],
            empty="No monitored fingerprinting APIs were called.")

    # ---- GPC / DNT
    ps = result.get("privacy_signals", {})
    cmp_ = ps.get("comparison", {})
    rows = [
        ["Item", "Value"],
        ["Browser values with signals on", ps.get("gpc_dnt_browser_values")],
        ["Trackers only in baseline", cmp_.get("trackers_only_in_baseline")],
        ["Trackers only with signals on", cmp_.get("trackers_only_with_signals")],
        ["Third-party domains only in baseline", cmp_.get("third_party_domains_only_in_baseline")],
        ["Third-party domains only with signals", cmp_.get("third_party_domains_only_with_signals")],
    ]
    section("GPC / Do-Not-Track comparison", rows, [60, 120])

    # ---- Consent detail
    rows = [["Scenario", "Button found", "Clicked", "Requests", "3rd-party requests", "Trackers"]]
    for name, d in result.get("consent_detail", {}).items():
        b = d.get("consent_button") or {}
        rows.append([name, b.get("found"), b.get("clicked"), d.get("request_count"),
                     d.get("third_party_request_count"), d.get("tracker_count")])
    section("Consent scenarios (none / reject / accept)", rows, [30, 28, 25, 30, 40, 27])

    # ---- Policy topics
    rows = [["Topic", "Mentioned", "Matched phrases"]]
    for k, v in result.get("policy_topics", {}).items():
        rows.append([k, "yes" if v.get("mentioned") else "no", ", ".join(v.get("matched_phrases", []))])
    section("Privacy policy topic coverage (keyword based)", rows, [45, 25, 110],
            empty="Policy text not available.")

    # ---- Storage
    st = result.get("storage", {})
    rows = [["Type", "Name / key", "Size (bytes)"]]
    for x in st.get("local_storage", []):
        rows.append(["localStorage", x["key"], x["bytes"]])
    for x in st.get("session_storage", []):
        rows.append(["sessionStorage", x["key"], x["bytes"]])
    for x in st.get("indexed_db", []):
        rows.append(["IndexedDB", x.get("name"), ""])
    for x in st.get("cache_storage", []):
        rows.append(["CacheStorage", x, ""])
    for x in st.get("service_workers", []):
        rows.append(["ServiceWorker", x.get("scope"), ""])
    section("Browser storage (names only, values are not stored)", rows, [40, 100, 40],
            empty="No browser storage used.")
    
    # Timings
    rows = [["Stage", "Seconds"]] + [[k, v] for k, v in result.get("timings_seconds", {}).items()]
    section("Scan timings", rows, [100, 40])

    story.append(Spacer(1, 6 * mm))
    story.append(P(
        "Limitations: heuristic detection; observations are not legal conclusions. "
        "A third-party request does not by itself prove personal data was shared.", small))

    doc.build(story)
    return buf.getvalue()