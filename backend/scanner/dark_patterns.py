JS_BUTTONS = r"""
() => {
  const lum = c => {
    const m = c.match(/\d+(\.\d+)?/g); if (!m) return 0;
    const [r,g,b] = m.slice(0,3).map(x => {
      x = x/255; return x <= 0.03928 ? x/12.92 : Math.pow((x+0.055)/1.055, 2.4);
    });
    return 0.2126*r + 0.7152*g + 0.0722*b;
  };
  const out = [];
  document.querySelectorAll("button,[role=button],a,input[type=button]").forEach(el => {
    const r = el.getBoundingClientRect();
    if (r.width < 5 || r.height < 5) return;
    const s = getComputedStyle(el);
    if (s.visibility === "hidden" || s.display === "none") return;
    const text = (el.innerText || el.value || el.getAttribute("aria-label") || "").trim();
    if (!text || text.length > 80) return;
    const l1 = lum(s.color), l2 = lum(s.backgroundColor);
    const contrast = (Math.max(l1,l2)+0.05)/(Math.min(l1,l2)+0.05);
    out.push({text, area: r.width*r.height, fontSize: parseFloat(s.fontSize),
              contrast, bg: s.backgroundColor, top: r.top});
  });
  const prechecked = [...document.querySelectorAll("input[type=checkbox]:checked")]
      .map(e => (e.name || e.id || "checkbox")).slice(0, 20);
  return {buttons: out, prechecked};
}
"""

ACCEPT = ("accept", "allow all", "agree", "got it", "i understand")
REJECT = ("reject", "decline", "deny", "necessary only", "essential only", "refuse")
MANAGE = ("manage", "settings", "preferences", "customize", "options")


def _pick(buttons, words):
    c = [b for b in buttons if any(w in b["text"].lower() for w in words)]
    return max(c, key=lambda b: b["area"]) if c else None


def analyze_dark_patterns(page) -> dict:
    data = page.evaluate(JS_BUTTONS)
    btns = data["buttons"]
    accept, reject, manage = _pick(btns, ACCEPT), _pick(btns, REJECT), _pick(btns, MANAGE)

    findings = []
    if accept and not reject:
        findings.append({
            "id": "NO_FIRST_LAYER_REJECT",
            "severity": "high",
            "detail": "Accept is on the first layer; no reject button found "
                      "(rejecting needs extra clicks)." + (
                          f" Only '{manage['text']}' offered." if manage else ""),
        })
    if accept and reject:
        ratio = accept["area"] / max(reject["area"], 1)
        if ratio > 1.5:
            findings.append({"id": "ACCEPT_VISUALLY_DOMINANT", "severity": "medium",
                             "detail": f"Accept button is {ratio:.1f}x larger than reject."})
        if accept["contrast"] - reject["contrast"] > 2:
            findings.append({"id": "REJECT_LOW_CONTRAST", "severity": "medium",
                             "detail": f"Contrast accept={accept['contrast']:.1f} "
                                       f"vs reject={reject['contrast']:.1f}."})
    if data["prechecked"]:
        findings.append({"id": "PRECHECKED_BOXES", "severity": "high",
                         "detail": f"Pre-ticked consent boxes: {data['prechecked']}"})

    return {
        "accept": accept, "reject": reject, "manage": manage,
        "findings": findings,
        "limitations": ["Heuristic text matching; banners inside iframes may be missed."],
    }