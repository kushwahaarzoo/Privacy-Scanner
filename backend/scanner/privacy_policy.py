
# backend/scanner/privacy_policy.py

import re
from collections import Counter
from urllib.parse import urljoin, urlparse

import tldextract
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


POLICY_TERMS = (
    "privacy policy",
    "privacy notice",
    "privacy statement",
    "data protection",
    "personal data",
    "your privacy",
)

# These are heuristic topics, not a complete legal checklist.
POLICY_TOPICS = {
    "cookies": [
        "cookie", "cookies", "cookie preferences", "similar technologies"
    ],
    "analytics": [
        "analytics", "usage data", "website usage", "performance monitoring"
    ],
    "advertising_and_tracking": [
        "advertising", "targeted ads", "targeted advertising",
        "tracking technologies", "interest-based advertising"
    ],
    "data_sharing": [
        "share your information", "share personal data",
        "third parties", "service providers", "sell personal information"
    ],
    "data_retention": [
        "retain your data", "data retention", "retention period",
        "how long we keep", "store your information"
    ],
    "user_rights": [
        "your rights", "access your data", "delete your data",
        "correct your data", "data portability", "withdraw consent"
    ],
    "contact_information": [
        "contact us", "privacy team", "data protection officer",
        "privacy@"
    ],
}

TRACKING_HINTS = (
    "analytics", "track", "pixel", "collect", "beacon",
    "doubleclick", "facebook", "google-analytics", "segment",
    "hotjar", "mixpanel", "amplitude", "clarity.ms",
)


def _valid_http_url(url: str) -> bool:
    """Basic URL validation. Not a complete SSRF defense."""
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and not parsed.username
            and not parsed.password
        )
    except (TypeError, ValueError):
        return False


def _registrable_domain(host: str) -> str:
    """Return the registrable domain using tldextract."""
    try:
        result = tldextract.extract(host)
        return result.registered_domain or host.lower()
    except Exception:
        return host.lower()


def _same_site(first_url: str, second_url: str) -> bool:
    """Restrict policy discovery to the same registrable domain."""
    first_host = (urlparse(first_url).hostname or "").lower()
    second_host = (urlparse(second_url).hostname or "").lower()

    if not first_host or not second_host:
        return False

    return _registrable_domain(first_host) == _registrable_domain(second_host)


def _policy_link_score(text: str, href: str) -> int:
    candidate = f"{text} {href}".lower()
    score = 0

    for term in POLICY_TERMS:
        if term in candidate:
            score += 10

    if "privacy" in candidate:
        score += 5
    if "policy" in candidate or "notice" in candidate:
        score += 3
    if any(word in candidate for word in ("cookie", "terms", "preferences")):
        score -= 2

    return score


def _discover_policy_links(page, start_url: str) -> list[dict]:
    """Find likely policy links on the visited page."""
    try:
        anchors = page.locator("a[href]").evaluate_all(
            """elements => elements.map(a => ({
                text: (a.innerText || a.getAttribute('aria-label') || '').trim(),
                href: a.href || ''
            }))"""
        )
    except Exception:
        return []

    candidates = []
    seen = set()

    for anchor in anchors:
        href = urljoin(start_url, anchor.get("href", ""))
        text = re.sub(r"\\s+", " ", anchor.get("text", "")).strip()

        if not _valid_http_url(href):
            continue
        if not _same_site(start_url, href):
            continue

        score = _policy_link_score(text, href)
        if score <= 0 or href in seen:
            continue

        seen.add(href)
        candidates.append({
            "url": href,
            "link_text": text[:200],
            "score": score,
        })

    return sorted(candidates, key=lambda item: item["score"], reverse=True)


def _extract_topics(policy_text: str) -> dict:
    text = policy_text.lower()
    topics = {}

    for topic, phrases in POLICY_TOPICS.items():
        matched = [phrase for phrase in phrases if phrase in text]
        topics[topic] = {
            "mentioned": bool(matched),
            "matched_phrases": matched[:10],
        }

    return topics


def _capture_page_evidence(page) -> dict:
    """Capture limited evidence without collecting cookie values."""
    request_urls = []
    third_party_hosts = set()
    tracker_like_hosts = set()

    start_host = (urlparse(page.url).hostname or "").lower()

    def on_request(request):
        request_urls.append(request.url)

        request_host = (urlparse(request.url).hostname or "").lower()
        if request_host and start_host and request_host != start_host:
            third_party_hosts.add(request_host)

            url_lower = request.url.lower()
            if any(hint in url_lower for hint in TRACKING_HINTS):
                tracker_like_hosts.add(request_host)

    page.on("request", on_request)

    # Requests already made before this listener was registered are not
    # included; the caller registers this listener before navigating.

    try:
        storage = page.evaluate(
            """() => ({
                localStorageKeys: Object.keys(localStorage),
                sessionStorageKeys: Object.keys(sessionStorage)
            })"""
        )
    except Exception:
        storage = {
            "localStorageKeys": [],
            "sessionStorageKeys": [],
        }

    return {
        "request_urls": request_urls,
        "third_party_hosts": sorted(third_party_hosts),
        "tracker_like_hosts": sorted(tracker_like_hosts),
        "storage": storage,
    }


def _fetch_policy_text(browser, policy_url: str) -> dict:
    context = browser.new_context()
    page = context.new_page()

    try:
        response = page.goto(
            policy_url,
            wait_until="domcontentloaded",
            timeout=20000,
        )

        status = response.status if response else None

        try:
            page.locator("body").wait_for(timeout=5000)
            text = page.locator("body").inner_text(timeout=5000)
        except Exception:
            text = ""

        return {
            "url": page.url,
            "http_status": status,
            "text": re.sub(r"\\s+", " ", text).strip()[:100000],
        }
    except PlaywrightTimeoutError:
        return {
            "url": policy_url,
            "http_status": None,
            "text": "",
            "error": "Policy page navigation timed out.",
        }
    except Exception as exc:
        return {
            "url": policy_url,
            "http_status": None,
            "text": "",
            "error": f"Could not retrieve policy: {type(exc).__name__}",
        }
    finally:
        context.close()


def _build_findings(
    policy_found: bool,
    policy_text: str,
    topics: dict,
    evidence: dict,
) -> list[dict]:
    findings = []

    if not policy_found:
        findings.append({
            "id": "POLICY_NOT_FOUND",
            "severity": "medium",
            "confidence": "low",
            "title": "Privacy policy was not located",
            "observation": (
                "The scanner did not locate a likely privacy policy link "
                "using its link-text and URL heuristics."
            ),
            "evidence": [],
            "recommendation": (
                "Manually verify whether a privacy notice exists, including "
                "in the footer, account pages, or a linked legal page."
            ),
        })
        return findings

    if not policy_text:
        findings.append({
            "id": "POLICY_TEXT_UNAVAILABLE",
            "severity": "low",
            "confidence": "high",
            "title": "Policy text could not be extracted",
            "observation": (
                "A likely policy link was found, but readable policy text "
                "was not retrieved."
            ),
            "evidence": [],
            "recommendation": (
                "Check whether the page requires JavaScript, consent, "
                "authentication, or a different retrieval method."
            ),
        })
        return findings

    missing_topics = [
        topic for topic, result in topics.items()
        if not result["mentioned"]
    ]

    if missing_topics:
        findings.append({
            "id": "POLICY_TOPICS_NOT_DETECTED",
            "severity": "low",
            "confidence": "low",
            "title": "Some expected privacy topics were not detected",
            "observation": (
                "Keyword analysis did not detect these topics: "
                + ", ".join(missing_topics)
                + ". This does not prove they are absent; wording, language, "
                  "or document structure may affect detection."
            ),
            "evidence": [
                {"topic": topic, "matched_phrases": []}
                for topic in missing_topics
            ],
            "recommendation": (
                "Review the policy manually and consider improving the "
                "topic dictionary for the site's language and terminology."
            ),
        })

    tracker_hosts = evidence.get("tracker_like_hosts", [])
    third_party_hosts = evidence.get("third_party_hosts", [])

    if tracker_hosts and not topics["advertising_and_tracking"]["mentioned"]:
        findings.append({
            "id": "TRACKING_DISCLOSURE_REVIEW",
            "severity": "medium",
            "confidence": "low",
            "title": "Observed tracking-like requests need policy review",
            "observation": (
                "Some requests matched basic tracking-related URL hints, "
                "but keyword analysis did not detect an advertising or "
                "tracking disclosure in the retrieved policy."
            ),
            "evidence": [
                {"host": host} for host in tracker_hosts[:20]
            ],
            "recommendation": (
                "Manually determine whether these requests involve tracking, "
                "what data they process, and whether the policy describes "
                "the relevant purpose and recipients."
            ),
        })

    if third_party_hosts and not topics["data_sharing"]["mentioned"]:
        findings.append({
            "id": "THIRD_PARTY_DISCLOSURE_REVIEW",
            "severity": "low",
            "confidence": "low",
            "title": "Third-party connections need disclosure review",
            "observation": (
                "Third-party hosts were contacted during the visit, but "
                "the policy keyword check did not detect common data-sharing "
                "language."
            ),
            "evidence": [
                {"host": host} for host in third_party_hosts[:20]
            ],
            "recommendation": (
                "Review the third-party services, the data sent to them, "
                "and the policy's descriptions of recipients and purposes. "
                "A network connection alone does not prove personal data "
                "was shared."
            ),
        })

    return findings


def scan_privacy_policy(url: str) -> dict:
    """
    Analyze a site's likely privacy policy and collect basic visit evidence.

    Use only for sites you are authorized to assess.
    """
    if not _valid_http_url(url):
        raise ValueError("A valid HTTP or HTTPS URL is required.")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        request_urls = []
        third_party_hosts = set()
        tracker_like_hosts = set()

        original_host = (urlparse(url).hostname or "").lower()

        def on_request(request):
            request_urls.append(request.url)
            host = (urlparse(request.url).hostname or "").lower()

            if host and original_host and host != original_host:
                third_party_hosts.add(host)
                if any(hint in request.url.lower() for hint in TRACKING_HINTS):
                    tracker_like_hosts.add(host)

        page.on("request", on_request)

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=25000)
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightTimeoutError:
                pass

            policy_links = _discover_policy_links(page, url)

            try:
                storage = page.evaluate(
                    """() => ({
                        localStorageKeys: Object.keys(localStorage),
                        sessionStorageKeys: Object.keys(sessionStorage)
                    })"""
                )
            except Exception:
                storage = {
                    "localStorageKeys": [],
                    "sessionStorageKeys": [],
                }

            website_evidence = {
                "third_party_hosts": sorted(third_party_hosts),
                "tracker_like_hosts": sorted(tracker_like_hosts),
                "request_count": len(request_urls),
                "storage": storage,
            }

            policy = None
            # Try a few candidates, not every link on the page.
            for candidate in policy_links[:3]:
                # Recheck scope before navigation.
                if not _valid_http_url(candidate["url"]):
                    continue
                if not _same_site(url, candidate["url"]):
                    continue

                result = _fetch_policy_text(browser, candidate["url"])
                if result.get("text"):
                    policy = {
                        "discovered": True,
                        "link_text": candidate["link_text"],
                        "url": result["url"],
                        "http_status": result["http_status"],
                        "text_length": len(result["text"]),
                        "text": result["text"],
                    }
                    break

            if policy is None:
                policy = {
                    "discovered": False,
                    "candidates": policy_links[:3],
                    "url": None,
                    "http_status": None,
                    "text_length": 0,
                    "text": "",
                }

            policy_text = policy["text"]
            topics = _extract_topics(policy_text) if policy_text else {}

            findings = _build_findings(
                policy_found=bool(policy_text),
                policy_text=policy_text,
                topics=topics,
                evidence=website_evidence,
            )

            # Avoid returning the entire policy body by default.
            policy.pop("text", None)

            return {
                "url": url,
                "policy": policy,
                "policy_topics": topics,
                "website_evidence": website_evidence,
                "findings": findings,
                "limitations": [
                    "This is a heuristic technical scan, not a legal compliance assessment.",
                    "Keyword detection can miss equivalent wording and can misclassify context.",
                    "A third-party request does not by itself prove personal data was disclosed.",
                    "Only the initial page and a discovered policy page are inspected.",
                    "Cookie values, request bodies, and full browsing histories are not intentionally returned.",
                    "The current URL checks are not sufficient SSRF protection for a public-facing service.",
                ],
            }
        finally:
            context.close()
            browser.close()
