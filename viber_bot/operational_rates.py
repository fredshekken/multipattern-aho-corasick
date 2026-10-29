r"""
What the USER sees, measured on a labeled dataset (the "warning performance" table).

compare_engines.py counts a message as flagged when the engine detects anything
at any tier (detection performance, Table 4.1). This script instead applies the
extension's display rules, so the numbers match what a user would actually see:

    Tier 0, Tier 1                          -> silent
    Tier 2 with < TIER2_MIN_EVIDENCE groups -> silent
    Tier 2 with >= TIER2_MIN_EVIDENCE groups-> collapsed note
    Tier 2 with ONE group listed in --tier2-allow-single -> collapsed note (optional)
    Tier 3 with url_risk as the ONLY group  -> collapsed note
    Tier 3 otherwise                        -> red banner
    (optional) --banner-min-evidence N: a red banner needs >= N groups; a Tier 3 message
    with fewer follows the Tier 2 visibility rule above instead.

Keep these rules identical to phish_smoke_test/extension/content.js.

Usage (from the viber_bot folder):
    python operational_rates.py --csv uploaded_datasets\da24fda71670_philippine_sms_cleaned.csv ^
        --text-col text --label-col label --positive-label 1 ^
        --pattern-file ..\enhanced_aho\default_patterns.txt --no-resolve-shorteners
The lookalike-domain check is ON by default; add --no-lookalike-domains to turn it off.
"""
import argparse
from collections import Counter

import _bootstrap  # noqa: F401
from compare_engines import load_csv
from enhanced_aho_corasick import EnhancedAhoCorasick


def display_mode(tier, groups, tier2_min_evidence, allow_single=(), banner_min_evidence=1):
    if tier <= 1:
        return "silent"
    if tier == 2:
        if len(groups) >= tier2_min_evidence:
            return "collapsed"
        if len(groups) == 1 and groups[0] in allow_single:
            return "collapsed"
        return "silent"
    # Tier 3
    if list(groups) == ["url_risk"]:
        return "collapsed"
    if len(groups) >= banner_min_evidence:
        return "banner"
    # Not enough corroboration for a red banner: apply the same visibility rule as Tier 2
    if len(groups) >= tier2_min_evidence:
        return "collapsed"
    if len(groups) == 1 and groups[0] in allow_single:
        return "collapsed"
    return "silent"


def rate(n, total):
    return f"{n / total * 100:.2f}%" if total else "n/a"


def confusion(rows, shown):
    tp = sum(1 for y, m in rows if y and m in shown)
    fn = sum(1 for y, m in rows if y and m not in shown)
    fp = sum(1 for y, m in rows if not y and m in shown)
    tn = sum(1 for y, m in rows if not y and m not in shown)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return tp, fp, tn, fn, p, r, f1, (fp / (fp + tn) if fp + tn else 0.0), (tp + tn) / len(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--text-col", default="text")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--positive-label", default="1")
    ap.add_argument("--pattern-file", required=True)
    ap.add_argument("--max-text-chars", type=int, default=None)
    ap.add_argument("--tier2-min-evidence", type=int, default=2)
    ap.add_argument("--banner-min-evidence", type=int, default=1,
                    help="Red banner needs at least this many evidence groups (default 1 = no extra rule)")
    ap.add_argument("--tier2-allow-single", default="",
                    help="Comma-separated evidence groups that may show a note ALONE, e.g. urgency_threat")
    ap.add_argument("--examples", type=int, default=0,
                    help="Print N legitimate messages that would get a red banner (to see why)")
    ap.add_argument("--no-resolve-shorteners", action="store_true")
    ap.add_argument("--no-lookalike-domains", action="store_true",
                    help="Turn OFF the lookalike-domain check. It is ON by default.")
    ap.add_argument("--flag-lookalike-domains", action="store_true", help=argparse.SUPPRESS)  # old option, now the default
    args = ap.parse_args()

    allow_single = tuple(g.strip() for g in args.tier2_allow_single.split(",") if g.strip())
    data = load_csv(args.csv, args.text_col, args.label_col, args.positive_label, args.max_text_chars)
    engine = EnhancedAhoCorasick.from_pattern_file(
        args.pattern_file,
        resolve_shorteners=not args.no_resolve_shorteners,
        flag_lookalike_domains=not args.no_lookalike_domains,
        url_trace=False,
    )
    print(f"Loaded {len(data)} rows")
    print("Lookalike-domain check:", "OFF" if args.no_lookalike_domains else "ON")
    print("Shortener resolution:", "OFF (offline run)" if args.no_resolve_shorteners else "ON (live network)")

    rows = []        # (is_phishing, display_mode)
    tiers = {True: Counter(), False: Counter()}
    tier2_groups = {True: Counter(), False: Counter()}
    tier3_groups = {True: Counter(), False: Counter()}
    banner_examples = []   # legitimate messages that would get a red banner
    for text, is_phishing in data:
        a = engine.assess_message(text)
        tiers[is_phishing][a["action_tier"]] += 1
        if a["action_tier"] == 2:
            tier2_groups[is_phishing][tuple(sorted(a["evidence_groups"]))] += 1
        if a["action_tier"] == 3:
            tier3_groups[is_phishing][tuple(sorted(a["evidence_groups"]))] += 1
        mode = display_mode(a["action_tier"], a["evidence_groups"], args.tier2_min_evidence, allow_single,
                            args.banner_min_evidence)
        rows.append((is_phishing, mode))
        if args.examples and not is_phishing and mode == "banner" and len(banner_examples) < args.examples:
            words = []
            for d in a["detections"]:
                b = d.get("score_breakdown", {})
                w = b.get("matched_text") or b.get("pattern")
                if w and w not in words:
                    words.append(w)
            banner_examples.append((text, a["global_risk"], a["evidence_groups"], words[:5]))

    n_pos = sum(1 for y, _ in rows if y)
    n_neg = len(rows) - n_pos
    print(f"\nPhishing: {n_pos}   Legitimate: {n_neg}   (Tier 2 needs >= {args.tier2_min_evidence} evidence groups"
          + (f", or a single: {', '.join(allow_single)}" if allow_single else "")
          + f"; red banner needs >= {args.banner_min_evidence} groups)")

    print("\n=== ENGINE TIERS (before display rules) ===")
    print(f"{'':22s}{'Legitimate':>18s}{'Phishing':>18s}")
    for t, label in [(0, "Tier 0 (no detection)"), (1, "Tier 1 (low)"), (2, "Tier 2 (moderate)"), (3, "Tier 3 (high/critical)")]:
        print(f"{label:22s}{tiers[False][t]:>8d} ({rate(tiers[False][t], n_neg):>7s}){tiers[True][t]:>8d} ({rate(tiers[True][t], n_pos):>7s})")

    print("\n=== WHAT THE USER SEES ===")
    counts = {True: Counter(m for y, m in rows if y), False: Counter(m for y, m in rows if not y)}
    print(f"{'':22s}{'Legitimate':>18s}{'Phishing':>18s}")
    for mode, label in [("silent", "Silent (nothing shown)"), ("collapsed", "Collapsed note"), ("banner", "Red banner")]:
        print(f"{label:22s}{counts[False][mode]:>8d} ({rate(counts[False][mode], n_neg):>7s}){counts[True][mode]:>8d} ({rate(counts[True][mode], n_pos):>7s})")

    print("\n=== TIER 2 BY EVIDENCE (which kinds of evidence the Tier 2 messages have) ===")
    combos = set(tier2_groups[True]) | set(tier2_groups[False])
    combos = sorted(combos, key=lambda c: -(tier2_groups[True][c] + tier2_groups[False][c]))
    print(f"{'evidence groups':64s}{'Legit':>7s}{'Phish':>7s}{'Phish share':>13s}")
    for c in combos[:15]:
        lg, ph = tier2_groups[False][c], tier2_groups[True][c]
        print(f"{(' + '.join(c) or '(none)'):64s}{lg:>7d}{ph:>7d}{ph / (lg + ph) * 100:>12.1f}%")

    print("\n=== TIER 3 BY EVIDENCE ===")
    combos3 = set(tier3_groups[True]) | set(tier3_groups[False])
    combos3 = sorted(combos3, key=lambda c: -(tier3_groups[True][c] + tier3_groups[False][c]))
    print(f"{'evidence groups':64s}{'Legit':>7s}{'Phish':>7s}{'Phish share':>13s}")
    for c in combos3[:15]:
        lg, ph = tier3_groups[False][c], tier3_groups[True][c]
        print(f"{(' + '.join(c) or '(none)'):64s}{lg:>7d}{ph:>7d}{ph / (lg + ph) * 100:>12.1f}%")

    print("\n=== CONFUSION MATRICES BY WHAT IS SHOWN ===")
    print(f"{'rule':34s}{'TP':>6s}{'FP':>6s}{'TN':>6s}{'FN':>6s}  {'Acc':>7s}{'Prec':>8s}{'Recall':>8s}{'F1':>8s}{'FPR':>8s}")
    for name, shown in [("Any note or banner is shown", {"collapsed", "banner"}), ("Red banner only", {"banner"})]:
        tp, fp, tn, fn, p, r, f1, fpr, acc = confusion(rows, shown)
        print(f"{name:34s}{tp:>6d}{fp:>6d}{tn:>6d}{fn:>6d}  {acc:>7.4f}{p:>8.4f}{r:>8.4f}{f1:>8.4f}{fpr:>8.4f}")
    print_examples(banner_examples)


def print_examples(examples):
    if not examples:
        return
    print("\n=== LEGITIMATE MESSAGES THAT WOULD GET A RED BANNER ===")
    for text, score, groups, words in examples:
        snippet = " ".join(text.split())[:150]
        print(f"S={score:.2f} groups={groups} matched={words}\n    {snippet!r}")


if __name__ == "__main__":
    main()