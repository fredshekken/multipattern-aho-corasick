r"""
Re-runs the example messages and rules that the paper states, so each claim can be
checked against the current engine. Put this file in viber_bot\ and run:

    python verify_paper_claims.py

It works offline (shortened links are not contacted).
"""
from pathlib import Path

import _bootstrap  # noqa: F401
from baseline_aho_corasick import BaselineAhoCorasick
from enhanced_aho_corasick import EnhancedAhoCorasick

PATTERNS = str(Path(__file__).resolve().parent.parent / "enhanced_aho" / "default_patterns.txt")
enhanced = EnhancedAhoCorasick.from_pattern_file(PATTERNS, url_trace=False, resolve_shorteners=False)
baseline = BaselineAhoCorasick.from_pattern_file(PATTERNS)


def shown_as(tier, groups):
    """Display rule of the extension (keep the same as content.js)."""
    if tier <= 1:
        return "nothing"
    if tier == 2:
        return "collapsed note" if len(groups) >= 2 else "nothing"
    if groups == ["url_risk"]:
        return "collapsed note"
    if len(groups) >= 2:
        return "RED BANNER"
    return "nothing"


def show(title, message):
    a = enhanced.assess_message(message)
    base = sorted({m["pattern"] for m in baseline.search(message)})
    print(f"\n=== {title}\n    {message}")
    print(f"    baseline keywords : {base}")
    print(f"    enhanced          : Tier {a['action_tier']} ({a['severity']}), S = {a['global_risk']:.3f}")
    print(f"    evidence groups   : {a['evidence_groups']}")
    print(f"    extension shows   : {shown_as(a['action_tier'], a['evidence_groups'])}")
    for d in a["detections"]:
        s = d.get("score_breakdown", {})
        print(f"      {d['match_type']:13s} {str(s.get('pattern')):20s} base={s.get('token_score')} "
              f"proximity={s.get('proximity_delta')} penalty={s.get('penalty')} "
              f"url=x{s.get('url_multiplier')} ({s.get('url_segment')}) risk={d['risk_score']}")


show("Figure 4.1 / 4.2", "Ver1fy your @cc0unt s@ l1nk n@ ito upang maiwasan ang deactivation: http://secure-bank-ph.com")
show("Figure 4.3 / 4.4 (expect Tier 0)", "Paalala at babala: Ang opisyal na customer support ay hindi hihingi ng inyong account password.")
show("Figure 4.5 / 4.6 and Table 4.5 row 1 (shortener)", "Paalala mula sa GCash: i-verify ang iyong account ngayon sa bit.ly/gcash-update")
show("Table 4.5 row 2 (subdomain)", "Paalala: Na-block ang inyong gcash account, mag-login agad sa gcash.security-portal.com")
show("Table 4.5 row 3 (path)", "Babala: Paki-kumpirma ang detalye bago mag-login sa portal-verify.com/gcash/login")
show("Table 4.5 row 4 (official domain)", "Official advisory: Mangyaring i-verify ang inyong transaksyon sa gcash.com")

print("\n=== Phonetic map (what the engine really maps)")
print("    engine map:", enhanced.phonetic_map)
for word in ["berify", "vlocked", "jcash", "gkash", "kash", "klick"]:
    found = [d["score_breakdown"].get("pattern") for d in enhanced.enhanced_search(word)]
    print(f"    {word:8s} -> {enhanced._normalize(word):8s} detected: {found}")

print("\n=== Scanning check (a repeated word before a phrase pattern)")
for message in ["account account suspended", "click click here"]:
    found = [(d["match_type"], d["score_breakdown"].get("pattern")) for d in enhanced.enhanced_search(message)]
    print(f"    {message!r:28s} -> {found}")

print("\n=== Constants")
print("    thresholds exact/fuzzy/affix/anomaly:", enhanced.exact_threshold, enhanced.fuzzy_threshold,
      enhanced.affix_threshold, enhanced.anomaly_threshold)
print("    tier cutoffs:", enhanced.LOW_MODERATE_CUTOFF, enhanced.MODERATE_HIGH_CUTOFF, enhanced.HIGH_CRITICAL_CUTOFF)
print("    URL multipliers:", enhanced.SEGMENT_RISK)
print("    lookalike check on:", enhanced.flag_lookalike_domains, "| engine-side gate min_evidence:", enhanced.min_evidence)