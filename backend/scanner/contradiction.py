def find_contradictions(claims: dict, observed: dict) -> list:
    """
    observed = {
      "trackers": [...],            # from detect_trackers
      "third_party_domains": [...],
      "pii_leaks": [...],           # from scan_pii_leaks
      "trackers_before_consent": [...],
      "trackers_after_reject": [...],
      "gpc_trackers_remaining": [...],
    }
    """
    out = []

    def val(key):
        c = claims.get(key)
        return c.get("value") if isinstance(c, dict) else None

    def quote(key):
        c = claims.get(key)
        return c.get("quote") if isinstance(c, dict) else None

    ad_trackers = [t for t in observed["trackers"]
                   if t["category"] in ("advertising", "marketing")]

    if val("uses_advertising_trackers") is False and ad_trackers:
        out.append({
            "id": "CLAIM_NO_ADS_BUT_AD_TRACKERS",
            "severity": "high",
            "claim": quote("uses_advertising_trackers"),
            "evidence": [t["name"] for t in ad_trackers],
        })

    if val("shares_with_third_parties") is False and observed["third_party_domains"]:
        out.append({
            "id": "CLAIM_NO_SHARING_BUT_THIRD_PARTY_TRAFFIC",
            "severity": "medium",
            "claim": quote("shares_with_third_parties"),
            "evidence": observed["third_party_domains"][:15],
        })

    if val("sells_personal_data") is False and observed["pii_leaks"]:
        tp = [l for l in observed["pii_leaks"] if l["third_party"]]
        if tp:
            out.append({
                "id": "CLAIM_NO_SALE_BUT_PII_TO_THIRD_PARTY",
                "severity": "high",
                "claim": quote("sells_personal_data"),
                "evidence": [f'{l["destination"]} ({l["encoding"]})' for l in tp],
            })

    if val("honors_gpc_or_dnt") is True and observed["gpc_trackers_remaining"]:
        out.append({
            "id": "CLAIM_HONORS_GPC_BUT_TRACKERS_REMAIN",
            "severity": "high",
            "claim": quote("honors_gpc_or_dnt"),
            "evidence": observed["gpc_trackers_remaining"],
        })

    if val("consent_mechanism_described") is True and observed["trackers_before_consent"]:
        out.append({
            "id": "CONSENT_DESCRIBED_BUT_TRACKING_PRE_CONSENT",
            "severity": "high",
            "claim": quote("consent_mechanism_described"),
            "evidence": observed["trackers_before_consent"],
        })

    undisclosed = [
        t["name"] for t in observed["trackers"]
        if not any(t["name"].lower() in n.lower() or n.lower() in t["name"].lower()
                   for n in claims.get("named_third_parties", []))
    ]
    if undisclosed:
        out.append({
            "id": "TRACKERS_NOT_NAMED_IN_POLICY",
            "severity": "low",
            "claim": None,
            "evidence": undisclosed,
        })

    return out