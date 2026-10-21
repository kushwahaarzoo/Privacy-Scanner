
"""
Level 4: GPC and Do Not Track signal testing.
"""

from playwright.sync_api import sync_playwright

from backend.scanner.fingerprinting import (
    FINGERPRINT_INIT_SCRIPT,
    collect_fingerprinting_signals,
)

from backend.scanner.trackers import detect_trackers

from backend.scanner.domains import get_hostname, is_third_party


SIGNAL_OVERRIDE_SCRIPT = r"""
(() => {
    const settings = window.__privacyScannerSettings || {};

    try {
        Object.defineProperty(navigator, "globalPrivacyControl", {
            configurable: true,
            get: () => Boolean(settings.gpc)
        });
    } catch (_) {}

    try {
        Object.defineProperty(navigator, "doNotTrack", {
            configurable: true,
            get: () => settings.dnt ? "1" : null
        });
    } catch (_) {}
})();
"""


def run_signal_scenario(browser, url: str, gpc: bool, dnt: bool) -> dict:
    headers = {}

    if gpc:
        headers["Sec-GPC"] = "1"

    if dnt:
        headers["DNT"] = "1"

    context = browser.new_context(
        ignore_https_errors=False,
        extra_http_headers=headers,
    )

    # Install before the website's scripts run.

    settings_script = """
    window.__privacyScannerSettings = {
        gpc: %s,
        dnt: %s
    };
    """ % (
        "true" if gpc else "false",
        "true" if dnt else "false",
    )

    context.add_init_script(
        script=(
            settings_script
            + SIGNAL_OVERRIDE_SCRIPT
            + FINGERPRINT_INIT_SCRIPT
        )
    )


    context.add_init_script(script=SIGNAL_OVERRIDE_SCRIPT)
    context.add_init_script(script=FINGERPRINT_INIT_SCRIPT)

    requests = []

    context.on(
        "request",
        lambda request: requests.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
        }),
    )

    page = context.new_page()
    navigation_error = None
    status = None

    try:
        try:
            response = page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=30_000,
            )

            if response:
                status = response.status

        except Exception as exc:
            navigation_error = type(exc).__name__

            if not page.url or page.url == "about:blank":
                raise

        try:
            page.wait_for_load_state(
                "networkidle",
                timeout=5_000,
            )
        except Exception:
            pass

        page.wait_for_timeout(2_000)

        # Read browser signals from the page itself.
        try:
            browser_values = page.evaluate("""
                () => ({
                    globalPrivacyControl:
                        typeof navigator.globalPrivacyControl === "boolean"
                            ? navigator.globalPrivacyControl
                            : null,
                    doNotTrack:
                        navigator.doNotTrack ?? null
                })
            """)
        except Exception:
            browser_values = {
                "globalPrivacyControl": None,
                "doNotTrack": None,
            }

        fingerprinting = collect_fingerprinting_signals(page)

        final_url = page.url

        third_party_domains = sorted({
            get_hostname(item["url"])
            for item in requests
            if get_hostname(item["url"])
            and is_third_party(item["url"], final_url)
        })

        trackers = detect_trackers(requests)

        return {
            "requested_signals": {
                "gpc": gpc,
                "dnt": dnt,
            },
            "http_request_headers_configured": {
                "Sec-GPC": "1" if gpc else None,
                "DNT": "1" if dnt else None,
            },
            "browser_values": browser_values,
            "navigation": {
                "final_url": final_url,
                "http_status": status,
                "error": navigation_error,
            },
            "request_count": len(requests),
            "third_party_domains": third_party_domains,
            "trackers": trackers,
            "fingerprinting": fingerprinting,
            "requests": requests,
        }

    finally:
        context.close()


def compare_signal_scenarios(baseline: dict, signals_on: dict) -> dict:
    baseline_trackers = {
        item["domain"]
        for item in baseline["trackers"]
    }

    signals_trackers = {
        item["domain"]
        for item in signals_on["trackers"]
    }

    baseline_domains = set(baseline["third_party_domains"])
    signals_domains = set(signals_on["third_party_domains"])

    return {
        "baseline_tracker_domains": sorted(baseline_trackers),
        "signals_on_tracker_domains": sorted(signals_trackers),
        "trackers_only_in_baseline": sorted(
            baseline_trackers - signals_trackers
        ),
        "trackers_only_with_signals": sorted(
            signals_trackers - baseline_trackers
        ),
        "third_party_domains_only_in_baseline": sorted(
            baseline_domains - signals_domains
        ),
        "third_party_domains_only_with_signals": sorted(
            signals_domains - baseline_domains
        ),
        "interpretation": (
            "Differences are observational only. Separate visits can "
            "vary because of timing, randomness, server state, consent, "
            "geography, and other factors. They do not prove that a site "
            "honored or ignored a privacy signal."
        ),
    }


def scan_privacy_signals(url: str) -> dict:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)

        try:
            baseline = run_signal_scenario(
                browser,
                url,
                gpc=False,
                dnt=False,
            )

            signals_on = run_signal_scenario(
                browser,
                url,
                gpc=True,
                dnt=True,
            )

            return {
                "test_type": "gpc_dnt_comparison",
                "input_url": url,
                "baseline": baseline,
                "signals_on": signals_on,
                "comparison": compare_signal_scenarios(
                    baseline,
                    signals_on,
                ),
                "limitations": [
                    "The browser signals are simulated for testing, not user preferences.",
                    "The configured HTTP headers are not proof that every request carried them.",
                    "A domain difference across visits is not proof of causation.",
                    "DNT is a deprecated, voluntary signal.",
                ],
            }

        finally:
            browser.close()
