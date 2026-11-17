r"""
Builds Table 4.5 (URL risk with resolved destinations) from LIVE shortened links.

Needs internet: the shortened links are resolved for real. Run from viber_bot:

    python build_table_4_5.py

It prints the table and saves it as table_4_5.csv (open it in Excel or Sheets).
Edit TEST_MESSAGES below to change the examples.
"""
import csv

import _bootstrap  # noqa: F401
from compare_engines import DEFAULT_PATTERN_FILE
from enhanced_aho_corasick import EnhancedAhoCorasick

TEST_MESSAGES = [
    # Shortened link from the paper's original example
    "Paalala mula sa GCash: i-verify ang iyong account ngayon sa bit.ly/gcash-update",
    # Same sentence, only the shortened link changes, so any difference in S comes
    # from where the link leads:
    #   official BPI site / lookalike of BPI / ordinary site with no risk signal
    "Paalala mula sa BPI: i-verify ang iyong account ngayon sa https://bit.ly/4kEZYxJ",
    "Paalala mula sa BPI: i-verify ang iyong account ngayon sa https://bit.ly/4yGX271",
    "Paalala mula sa BPI: i-verify ang iyong account ngayon sa https://bit.ly/4zq0cMA",
    # Direct links (no shortener)
    "Paalala: Na-block ang inyong gcash account, mag-login agad sa gcash.security-portal.com",
    "Babala: Paki-kumpirma ang detalye bago mag-login sa portal-verify.com/gcash/login",
    "Official advisory: Mangyaring i-verify ang inyong transaksyon sa gcash.com",
]

CLASS_NAMES = {
    "shortener": "Unresolved shortened link",
    "lookalike": "Lookalike domain",
    "subdomain": "Brand in subdomain",
    "path": "Keyword in path",
    "query": "Keyword in query",
    "sld": "Brand owns the domain",
    "none": "No risk signal",
}


def classification(info):
    if info.get("is_whitelisted"):
        return "Official (whitelisted)"
    return CLASS_NAMES.get(info.get("segment"), info.get("segment"))


def resolved_destination(info):
    if "expanded_url" not in info:
        return "(not a shortened link)"
    if info.get("unmasked_url"):
        return info["unmasked_url"]
    return "(could not be resolved)"


def shown_as(tier, groups):
    """Display rule of the browser extension (same as content.js)."""
    if tier <= 1:
        return "Nothing"
    if tier == 2:
        return "Collapsed note" if len(groups) >= 2 else "Nothing"
    if groups == ["url_risk"]:
        return "Collapsed note"
    return "Red banner" if len(groups) >= 2 else "Nothing"


def main():
    engine = EnhancedAhoCorasick.from_pattern_file(DEFAULT_PATTERN_FILE, url_trace=False)
    rows = []
    for message in TEST_MESSAGES:
        url_info = engine._analyze_url(message)   # resolves the link (cached for the next call)
        result = engine.assess_message(message)
        tokens = []
        for d in result["detections"]:
            name = d["score_breakdown"].get("pattern")
            if name and name not in tokens:
                tokens.append(name)
        rows.append({
            "Test Input": message,
            "Resolved Destination": resolved_destination(url_info),
            "URL Classification": classification(url_info),
            "Detected Token": ", ".join(tokens) or "(none)",
            "URL Multiplier": f"{url_info['multiplier']}x",
            "Resulting Risk": f"S = {result['global_risk']:.3f} (Tier {result['action_tier']})",
            "Extension Shows": shown_as(result["action_tier"], result["evidence_groups"]),
        })

    for r in rows:
        print("\n" + r["Test Input"])
        for key in list(r)[1:]:
            print(f"  {key:22s}: {r[key]}")

    with open("table_4_5.csv", "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("\nSaved: table_4_5.csv")
    if any(r["Resolved Destination"] == "(could not be resolved)" for r in rows):
        print("Note: if every shortened link shows '(could not be resolved)', check the internet connection.")


if __name__ == "__main__":
    main()