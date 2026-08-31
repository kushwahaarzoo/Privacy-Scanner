from urllib.parse import urlparse

import tldextract


# Use the bundled suffix snapshot.
# This avoids making network requests during normal scans.
extractor = tldextract.TLDExtract(suffix_list_urls=None)


def get_hostname(url: str) -> str:
    """
    Extract the hostname from a URL.
    """

    try:
        hostname = urlparse(url).hostname

        if hostname:
            return hostname.lower().rstrip(".")

    except Exception:
        pass

    return ""


def get_registered_domain(hostname_or_url: str) -> str:
    """
    Return the registrable domain.

    Examples:
        https://cdn.example.com -> example.com
        https://a.example.co.uk -> example.co.uk
    """

    if not hostname_or_url:
        return ""

    value = hostname_or_url

    if "://" in value:
        value = get_hostname(value)

    if not value:
        return ""

    extracted = extractor(value)

    if not extracted.domain:
        return value.lower()

    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return extracted.domain


def is_third_party(resource_url: str, page_url: str) -> bool:
    """
    Determine whether a resource belongs to a third party.

    Comparison is based on the registered domain.
    """

    resource_hostname = get_hostname(resource_url)
    page_hostname = get_hostname(page_url)

    if not resource_hostname or not page_hostname:
        return False

    resource_domain = get_registered_domain(resource_hostname)
    page_domain = get_registered_domain(page_hostname)

    if not resource_domain or not page_domain:
        return False

    return resource_domain != page_domain


def classify_domains(requests: list, page_url: str) -> dict:
    """
    Classify all network request domains.
    """

    first_party = set()
    third_party = set()

    for request in requests:

        request_url = request.get("url", "")

        hostname = get_hostname(request_url)

        if not hostname:
            continue

        registered_domain = get_registered_domain(hostname)

        if not registered_domain:
            continue

        if is_third_party(request_url, page_url):
            third_party.add(registered_domain)
        else:
            first_party.add(registered_domain)

    return {
        "first_party_domains": sorted(first_party),
        "third_party_domains": sorted(third_party),
    }