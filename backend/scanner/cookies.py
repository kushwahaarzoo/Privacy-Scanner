from backend.scanner.domains import get_registered_domain


TRACKER_COOKIE_PATTERNS = {
    "_ga": "analytics",
    "_gid": "analytics",
    "_gat": "analytics",

    "_fbp": "advertising",

    "_gcl_": "advertising",

    "_hj": "analytics",

    "hubspot": "analytics",

    "clarity": "analytics",

    "_uet": "advertising",
}


def classify_cookie_category(cookie_name: str) -> str:
    """
    Basic cookie category classification.

    This is heuristic-based.
    Level 3/4 can later use a larger tracker database.
    """

    name = cookie_name.lower()

    for pattern, category in TRACKER_COOKIE_PATTERNS.items():

        if pattern.lower() in name:
            return category

    session_keywords = [
        "session",
        "csrf",
        "auth",
        "token",
        "login",
        "sid",
    ]

    for keyword in session_keywords:

        if keyword in name:
            return "essential"

    return "unknown"


def analyze_cookie(cookie: dict, page_url: str) -> dict:
    """
    Analyze one Playwright cookie object.
    """

    page_domain = get_registered_domain(page_url)

    cookie_domain_raw = (
        cookie.get("domain")
        or ""
    ).lstrip(".")

    cookie_domain = get_registered_domain(
        cookie_domain_raw
    )

    is_third_party = (
        bool(cookie_domain)
        and bool(page_domain)
        and cookie_domain != page_domain
    )

    same_site = cookie.get("sameSite")

    return {
        "name": cookie.get("name"),

        "domain": cookie.get("domain"),

        "path": cookie.get("path"),

        "secure": cookie.get("secure", False),

        "http_only": cookie.get("httpOnly", False),

        "same_site": same_site,

        "expires": cookie.get("expires"),

        "is_third_party": is_third_party,

        "party": (
            "third-party"
            if is_third_party
            else "first-party"
        ),

        "category": classify_cookie_category(
            cookie.get("name", "")
        ),
    }


def analyze_cookies(
    cookies: list,
    page_url: str,
) -> list:
    """
    Analyze all cookies.
    """

    return [
        analyze_cookie(cookie, page_url)
        for cookie in cookies
    ]


def cookie_summary(cookies: list) -> dict:
    """
    Generate a summary of analyzed cookies.
    """

    summary = {
        "total": len(cookies),

        "first_party": 0,

        "third_party": 0,

        "secure": 0,

        "http_only": 0,

        "categories": {
            "essential": 0,
            "analytics": 0,
            "advertising": 0,
            "unknown": 0,
        },
    }

    for cookie in cookies:

        if cookie["party"] == "third-party":
            summary["third_party"] += 1
        else:
            summary["first_party"] += 1

        if cookie["secure"]:
            summary["secure"] += 1

        if cookie["http_only"]:
            summary["http_only"] += 1

        category = cookie["category"]

        if category not in summary["categories"]:
            summary["categories"][category] = 0

        summary["categories"][category] += 1

    return summary