from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from backend.scanner.domains import (
    classify_domains,
)

from backend.scanner.cookies import (
    analyze_cookies,
    cookie_summary,
)

from backend.scanner.trackers import (
    detect_trackers,
    tracker_summary,
)

from backend.scanner.storage import (
    scan_browser_storage,
    storage_summary,
)


SCREENSHOT_DIR = (
    Path(__file__).resolve()
    .parent
    .parent
    / "screenshots"
)

SCREENSHOT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


def scan_website(url: str) -> dict:
    """
    Level 2 website privacy scan.
    """

    validate_url(url)

    with sync_playwright() as playwright:

        browser = playwright.chromium.launch(
            headless=True
        )

        context = browser.new_context(
            ignore_https_errors=False
        )

        page = context.new_page()

        requests = []

        def handle_request(request):

            requests.append(
                {
                    "method": request.method,

                    "url": request.url,

                    "resource_type":
                        request.resource_type,
                }
            )

        page.on(
            "request",
            handle_request,
        )

        try:

            response = page.goto(
                url,
                wait_until="networkidle",
                timeout=30000,
            )

            status_code = (
                response.status
                if response
                else None
            )

            final_url = page.url

            title = page.title()

            raw_cookies = context.cookies()

            analyzed_cookies = analyze_cookies(
                raw_cookies,
                final_url,
            )

            cookies_stats = cookie_summary(
                analyzed_cookies
            )

            domain_results = classify_domains(
                requests,
                final_url,
            )

            trackers = detect_trackers(
                requests
            )

            trackers_stats = tracker_summary(
                trackers
            )

            storage = scan_browser_storage(
                page
            )

            storage_stats = storage_summary(
                storage
            )

            screenshot_name = (
                "latest.png"
            )

            screenshot_path = (
                SCREENSHOT_DIR
                / screenshot_name
            )

            page.screenshot(
                path=str(
                    screenshot_path
                ),

                full_page=True,
            )

            return {

                "scan_info": {

                    "input_url": url,

                    "final_url": final_url,

                    "status_code":
                        status_code,

                    "title": title,
                },

                "cookies": {

                    "summary":
                        cookies_stats,

                    "items":
                        analyzed_cookies,
                },

                "domains":
                    domain_results,

                "trackers": {

                    "summary":
                        trackers_stats,

                    "items":
                        trackers,
                },

                "storage": {

                    "summary":
                        storage_stats,

                    "items":
                        storage,
                },

                "network": {

                    "total_requests":
                        len(requests),

                    "requests":
                        requests,
                },

                "screenshot":
                    str(
                        screenshot_path
                    ),
            }

        finally:

            browser.close()


def validate_url(url: str):
    """
    Basic URL validation.

    Full SSRF protection will be
    added before production deployment.
    """

    parsed_url = urlparse(url)

    if parsed_url.scheme not in {
        "http",
        "https",
    }:

        raise ValueError(
            "URL must start with "
            "http:// or https://"
        )

    if not parsed_url.hostname:

        raise ValueError(
            "Invalid URL"
        )