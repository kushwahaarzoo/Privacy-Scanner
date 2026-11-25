SEVERITY_POINTS = {"high": 15, "medium": 7, "low": 2, "review": 4, "info": 0}

LAW_MAP = {
    "TRACKERS_AFTER_REJECT": ["GDPR Art. 7", "ePrivacy Art. 5(3)", "DPDP Act 2023 s.6"],
    "KNOWN_TRACKERS_BEFORE_CHOICE": ["GDPR Art. 6/7", "ePrivacy Art. 5(3)"],
    "NO_FIRST_LAYER_REJECT": ["GDPR Art. 7(3)", "EDPB dark-pattern guidelines"],
    "PRECHECKED_BOXES": ["GDPR Recital 32", "CJEU Planet49"],
    "CLAIM_NO_SALE_BUT_PII_TO_THIRD_PARTY": ["CCPA 1798.120", "GDPR Art. 5(1)(a)", "FTC Act s.5"],
    "CLAIM_HONORS_GPC_BUT_TRACKERS_REMAIN": ["CCPA regs 7025", "FTC Act s.5"],
    "CLAIM_NO_ADS_BUT_AD_TRACKERS": ["GDPR Art. 5(1)(a)", "FTC Act s.5"],
}


def risk_score(findings: list) -> dict:
    pts = sum(SEVERITY_POINTS.get(f.get("severity", "info"), 0) for f in findings)
    score = max(0, 100 - pts)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    for f in findings:
        f["regulations"] = LAW_MAP.get(f.get("id") or f.get("code"), [])
    return {"score": score, "grade": grade, "findings": findings}

LAW_MAP.update({
    "TRACKER_COOKIES_BEFORE_CHOICE": ["GDPR Art. 7", "ePrivacy Art. 5(3)", "DPDP Act 2023 s.6"],
    "TRACKER_COOKIES_AFTER_REJECT": ["GDPR Art. 7(3)", "ePrivacy Art. 5(3)", "DPDP Act 2023 s.6"],
})
for _code in ("CANVAS", "WEBGL", "AUDIO", "FONT_CHECK", "NAVIGATOR_PROPERTY", "SCREEN_PROPERTY"):
    LAW_MAP[f"API_SIGNAL_{_code}"] = ["ePrivacy Art. 5(3)", "GDPR Recital 30"]