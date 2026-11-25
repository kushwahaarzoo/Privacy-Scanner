
import re
from urllib.parse import urlparse
from backend.scanner.dark_patterns import analyze_dark_patterns

from playwright.sync_api import (
    sync_playwright,
    TimeoutError as PlaywrightTimeoutError,
)

from backend.scanner.domains import (
    get_hostname,
    is_third_party,
)

from backend.scanner.trackers import detect_trackers

from backend.scanner.storage import (
    scan_browser_storage,
    storage_summary,
)


NAVIGATION_TIMEOUT_MS = 30_000
OBSERVATION_MS = 4_000

# Deliberately conservative phrases.
# Button text matching is heuristic, not guaranteed.
BUTTON_PATTERNS = {
    "reject": [
        r"reject all",
        r"decline all",
        r"deny all",
        r"reject optional",
        r"decline optional",
        r"necessary only",
        r"essential only",
        r"only necessary",
        r"only essential",
        r"refuse all",
    ],
    "accept": [
        r"accept all",
        r"allow all",
        r"agree to all",
        r"consent to all",
        r"accept cookies",
        r"allow cookies",
    ],
}


def validate_consent_url(url: str) -> None:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must use HTTP or HTTPS.")

    if not parsed.hostname:
        raise ValueError("A valid hostname is required.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")


def wait_for_observation(page) -> None:
    """
    Give delayed scripts and requests a short window to run.
    This is not proof that all website activity has finished.
    """
    try:
        page.wait_for_load_state(
            "networkidle",
            timeout=5_000,
        )
    except PlaywrightTimeoutError:
        pass

    page.wait_for_timeout(OBSERVATION_MS)


def find_consent_button(page, action: str):
    """
    Look for a visible, enabled button/link/input whose accessible
    name or text matches a conservative consent phrase.

    Does not click generic 'OK', 'Continue', or 'Manage settings'.
    """
    patterns = BUTTON_PATTERNS[action]

    candidates = page.locator(
        "button, [role='button'], a, input[type='button'], "
        "input[type='submit']"
    )

    try:
        count = min(candidates.count(), 300)
    except Exception:
        return None

    for index in range(count):
        candidate = candidates.nth(index)

        try:
            if not candidate.is_visible() or not candidate.is_enabled():
                continue

            text = (
                candidate.get_attribute("aria-label")
                or candidate.inner_text(timeout=500)
                or candidate.get_attribute("value")
                or ""
            ).strip()

            if not text or len(text) > 180:
                continue

            normalized = re.sub(r"\s+", " ", text).strip().lower()

            for pattern in patterns:
                if re.search(pattern, normalized):
                    return {
                        "locator": candidate,
                        "text": text,
                    }

        except Exception:
            continue

    return None


def cookie_snapshot(context) -> list:
    """
    Return cookie metadata, excluding cookie values because they may
    contain session identifiers or other sensitive data.
    """
    result = []

    for cookie in context.cookies():
        result.append({
            "name": cookie.get("name"),
            "domain": cookie.get("domain"),
            "path": cookie.get("path"),
            "secure": cookie.get("secure", False),
            "http_only": cookie.get("httpOnly", False),
            "same_site": cookie.get("sameSite"),
            "expires": cookie.get("expires"),
        })

    return result


def cookie_keys(cookies: list) -> set:
    return {
        (
            item.get("name"),
            item.get("domain"),
            item.get("path"),
        )
        for item in cookies
    }


def collect_scenario(browser, url: str, action: str) -> dict:
    """
    Run one independent scenario.

    action:
      - "none": don't interact with consent UI
      - "reject": attempt to reject optional consent
      - "accept": attempt to accept all consent
    """
    context = browser.new_context(
        ignore_https_errors=False,
    )

    page = context.new_page()
    requests = []

    # Capture requests across pages in this context, including popups.
    context.on(
        "request",
        lambda request: requests.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
        }),
    )

    response_status = None
    button_result = {
        "attempted": action != "none",
        "found": False,
        "clicked": False,
        "text": None,
    }
    navigation_error = None

    try:
        try:
            response = page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=NAVIGATION_TIMEOUT_MS,
            )

            if response:
                response_status = response.status

        except Exception as exc:
            # A failed navigation can still leave useful partial evidence.
            navigation_error = type(exc).__name__

            if not page.url or page.url == "about:blank":
                raise

        wait_for_observation(page)

        pre_action_cookies = cookie_snapshot(context)
        pre_action_request_count = len(requests)

        if action in {"reject", "accept"}:
            match = find_consent_button(page, action)

            if match:
                button_result["found"] = True
                button_result["text"] = match["text"]

                try:
                    match["locator"].click(timeout=3_000)
                    button_result["clicked"] = True
                    wait_for_observation(page)
                except Exception:
                    # Keep the failed click visible in the result.
                    pass

        post_action_cookies = cookie_snapshot(context)

        try:
            storage = scan_browser_storage(page)
            storage_stats = storage_summary(storage)
        except Exception:
            storage = None
            storage_stats = None

        final_url = page.url

        third_party_requests = [
            item for item in requests
            if is_third_party(item["url"], final_url)
        ]

        tracker_items = detect_trackers(requests)

        return {
            "scenario": action,
            "final_url": final_url,
            "http_status": response_status,
            "navigation_error": navigation_error,
            "consent_button": button_result,
            "request_count": len(requests),
            "requests_before_action": pre_action_request_count,
            "third_party_request_count": len(third_party_requests),
            "third_party_domains": sorted({
                get_hostname(item["url"])
                for item in third_party_requests
                if get_hostname(item["url"])
            }),
            "tracker_count": len(tracker_items),
            "trackers": tracker_items,
            "cookies_before_action": pre_action_cookies,
            "cookies_after_action": post_action_cookies,
            "cookie_count_before_action": len(pre_action_cookies),
            "cookie_count_after_action": len(post_action_cookies),
            "storage_summary": storage_stats,
            "requests": requests,
        }

    finally:
        context.close()


def compare_scenarios(scenarios: dict) -> dict:
    baseline = scenarios["none"]
    rejected = scenarios["reject"]
    accepted = scenarios["accept"]

    baseline_trackers = {
        tracker["domain"]
        for tracker in baseline["trackers"]
    }
    rejected_trackers = {
        tracker["domain"]
        for tracker in rejected["trackers"]
    }
    accepted_trackers = {
        tracker["domain"]
        for tracker in accepted["trackers"]
    }

    baseline_cookies = cookie_keys(
        baseline["cookies_after_action"]
    )
    rejected_cookies = cookie_keys(
        rejected["cookies_after_action"]
    )
    accepted_cookies = cookie_keys(
        accepted["cookies_after_action"]
    )

    # These are observed differences, not automatic legal conclusions.
    findings = []

    if baseline_trackers:
        findings.append({
            "severity": "review",
            "code": "KNOWN_TRACKERS_BEFORE_CHOICE",
            "message": (
                "Known tracker domains were observed before "
                "any consent interaction."
            ),
            "evidence": sorted(baseline_trackers),
        })

    if rejected["consent_button"]["clicked"]:
        remaining = baseline_trackers & rejected_trackers

        if remaining:
            findings.append({
                "severity": "review",
                "code": "TRACKERS_AFTER_REJECT",
                "message": (
                    "Known tracker domains observed in the baseline "
                    "were also observed after the reject action."
                ),
                "evidence": sorted(remaining),
            })

    if not rejected["consent_button"]["clicked"]:
        findings.append({
            "severity": "info",
            "code": "REJECT_ACTION_NOT_CONFIRMED",
            "message": (
                "The scanner could not confirm a successful reject "
                "button click. The rejection scenario is inconclusive."
            ),
            "evidence": [],
        })

    if not accepted["consent_button"]["clicked"]:
        findings.append({
            "severity": "info",
            "code": "ACCEPT_ACTION_NOT_CONFIRMED",
            "message": (
                "The scanner could not confirm a successful accept "
                "button click. The acceptance scenario is inconclusive."
            ),
            "evidence": [],
        })

    return {
        "tracker_domains": {
            "before_choice": sorted(baseline_trackers),
            "after_reject": sorted(rejected_trackers),
            "after_accept": sorted(accepted_trackers),
        },
        "tracker_counts": {
            "before_choice": len(baseline_trackers),
            "after_reject": len(rejected_trackers),
            "after_accept": len(accepted_trackers),
        },
        "cookie_counts": {
            "before_choice": len(baseline_cookies),
            "after_reject": len(rejected_cookies),
            "after_accept": len(accepted_cookies),
        },
        "cookie_changes": {
            "after_reject_added": [
                list(item)
                for item in sorted(rejected_cookies - baseline_cookies)
            ],
            "after_reject_removed": [
                list(item)
                for item in sorted(baseline_cookies - rejected_cookies)
            ],
            "after_accept_added": [
                list(item)
                for item in sorted(accepted_cookies - baseline_cookies)
            ],
            "after_accept_removed": [
                list(item)
                for item in sorted(baseline_cookies - accepted_cookies)
            ],
        },
        "findings": findings,
        "limitations": [
            "For now leaving empty I can write some later if I want to add some limitations to the scan",
        ],
    }


def scan_consent_behavior(url: str) -> dict:
    validate_consent_url(url)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)

        try:
            scenarios = {
                "none": collect_scenario(browser, url, "none"),
                "reject": collect_scenario(browser, url, "reject"),
                "accept": collect_scenario(browser, url, "accept"),
            }

            return {
                "input_url": url,
                "test_type": "automated_consent_behavior",
                "scenarios": scenarios,
                "comparison": compare_scenarios(scenarios),
            }

        finally:
            browser.close()
