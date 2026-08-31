import json
from pathlib import Path

from backend.scanner.domains import (
    get_hostname,
    get_registered_domain,
)


DATA_DIR = Path(__file__).resolve().parent.parent / "data"

TRACKER_DATABASE_PATH = (
    DATA_DIR / "trackers.json"
)


def load_tracker_database() -> dict:
    """
    Load the local tracker database.
    """

    if not TRACKER_DATABASE_PATH.exists():
        return {}

    with open(
        TRACKER_DATABASE_PATH,
        "r",
        encoding="utf-8",
    ) as file:

        return json.load(file)


TRACKER_DATABASE = load_tracker_database()


def find_tracker(hostname: str):
    """
    Find a tracker by hostname.

    Checks:
        exact hostname
        registered domain
        parent domain matching
    """

    hostname = hostname.lower().rstrip(".")

    if hostname in TRACKER_DATABASE:

        return {
            "matched_domain": hostname,
            **TRACKER_DATABASE[hostname],
        }

    registered_domain = get_registered_domain(
        hostname
    )

    if registered_domain in TRACKER_DATABASE:

        return {
            "matched_domain": registered_domain,
            **TRACKER_DATABASE[registered_domain],
        }

    for domain, tracker in TRACKER_DATABASE.items():

        if (
            hostname == domain
            or hostname.endswith("." + domain)
        ):

            return {
                "matched_domain": domain,
                **tracker,
            }

    return None


def detect_trackers(requests: list) -> list:
    """
    Detect known trackers from network requests.
    """

    detected = {}

    for request in requests:

        request_url = request.get("url", "")

        hostname = get_hostname(request_url)

        if not hostname:
            continue

        tracker = find_tracker(hostname)

        if tracker:

            key = (
                tracker["matched_domain"],
                tracker["name"],
            )

            if key not in detected:

                detected[key] = {
                    "name": tracker["name"],

                    "company": tracker["company"],

                    "category": tracker["category"],

                    "domain": tracker[
                        "matched_domain"
                    ],

                    "requests": [],
                }

            detected[key]["requests"].append(
                request_url
            )

    return list(detected.values())


def tracker_summary(trackers: list) -> dict:
    """
    Generate tracker statistics.
    """

    categories = {}

    total_requests = 0

    for tracker in trackers:

        category = tracker["category"]

        categories[category] = (
            categories.get(category, 0) + 1
        )

        total_requests += len(
            tracker["requests"]
        )

    return {
        "total_trackers": len(trackers),

        "tracker_requests": total_requests,

        "categories": categories,
    }