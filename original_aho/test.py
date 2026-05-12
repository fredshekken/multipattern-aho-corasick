"""
Test Data for Aho-Corasick SOP Simulations
==========================================
Each SOP has its own test case demonstrating the algorithm's limitation.
Inputs are modeled after realistic Filipino phishing message patterns.
"""

from ahocorasick import AhoCorasickDFA
from visualizer import visualize_trie


# ============================================================
#  SHARED UTILITY
# ============================================================

def run_simulation(label: str, patterns: list[str], test_cases: list[str]):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  Dictionary Patterns: {patterns}")

    ac = AhoCorasickDFA(patterns)
    print_trie(ac)
    # Pass the last test case (canonical/baseline) as the stepping input
    demo_text = test_cases[-1] if test_cases else ""
    visualize_trie(ac, title=label, input_text=demo_text)

    for text in test_cases:
        print(f"\n  INPUT : \"{text}\"")
        matches = ac.search(text)
        if matches:
            for m in matches:
                print(f"  [!] ALERT : Found '{m['pattern']}' at index {m['start_index']}–{m['end_index']}")
        else:
            print("  [✓] No threats detected.")

    return ac


def print_trie(ac: AhoCorasickDFA):
    """Print a readable text representation of the trie structure."""
    structure = ac.get_trie_structure()
    print(f"\n  --- TRIE STRUCTURE ({structure['states_count']} states) ---")
    print(f"  {'STATE':<8} {'LABEL':<15} {'TRANSITIONS':<35} {'FAIL':<8} {'OUTPUT'}")
    print(f"  {'-'*80}")
    for node in structure["nodes"]:
        sid = node["id"]
        transitions = {
            e["char"]: e["to"]
            for e in structure["edges"]
            if e["from"] == sid
        }
        trans_str = ", ".join(f"'{c}'→{t}" for c, t in sorted(transitions.items()))
        out_str = str(node["matched_patterns"]) if node["is_output"] else "-"
        print(f"  {sid:<8} {node['label']:<15} {trans_str:<35} {node['fail_link']:<8} {out_str}")

    print(f"\n  --- FAILURE LINKS ---")
    for node in structure["nodes"]:
        if node["id"] != 0:
            print(f"  fail[{node['id']}] ({node['label']:<12}) → State {node['fail_link']}")


# ============================================================
#  SOP 1 — Character Obfuscation and Case/Unicode Inconsistency
#  Problem: Exact-match logic fails on leetspeak, symbol
#           substitution, and Unicode homoglyphs.
#
#  Input 1: All keywords obfuscated — ZERO alerts expected
#  Input 2: All keywords obfuscated in urgent scam tone — ZERO alerts
#  Input 3: All keywords canonical — ALL THREE alerts (baseline)
# ============================================================

SOP1_PATTERNS = ["gcash", "blocked", "verify"]

SOP1_TESTS = [
    # Obfuscated: G-C@sh (symbol sub), na-bl0cked (leetspeak),
    # e-berify (phonetic + morphological prefix) — WON'T trigger
    "ALERTO: Ang iyong G-C@sh ay na-bl0cked. Paki-berify ang iyong impormasyon.",

    # Obfuscated with urgent scam tone — WON'T trigger
    "G-C@SH ALERTO: Ang iyong account ay na-bl0cked. Mag-e-berify na kayo agad.",

    # Fully canonical keywords in realistic scam message — WILL trigger
    "GCASH ALERT: Ang iyong gcash account ay blocked. I-verify mo agad.",
]


# ============================================================
#  SOP 2 — False Positives due to Context-Free Matching
#  Problem: Algorithm flags safe messages containing phishing
#           keywords with no regard for surrounding context.
#
#  Input 1: Safe casual report — SHOULD NOT alert, but WILL
#  Input 2: Safe personal request — SHOULD NOT alert, but WILL
#  Input 3: Actual phishing message — SHOULD alert, and WILL
# ============================================================

SOP2_PATTERNS = ["gcash", "login", "account", "password", "update"]

SOP2_TESTS = [
    # SAFE: User reporting they already secured their own account
    "Nag-update na ako ng password ko sa gcash kanina, okay na.",

    # SAFE: Casual request between friends, no malicious intent
    "Pwede mo i-login sa aking account? Need ko lang i-check yung balance.",

    # ACTUAL phishing — urgent, impersonates GCash support
    "URGENT: Na-suspend ang iyong gcash account. Mag-login ka agad at i-update ang iyong password para ma-recover.",
]


# ============================================================
#  SOP 3 — Phonetic and Linguistic Inflexibility
#  Problem: Fixed trie cannot recognize phonetic substitutions
#           or Tagalog morphological affixes on keywords.
#
#  Input 1: Phonetic variants only — ZERO alerts expected
#  Input 2: Morphological + phonetic variants — ZERO alerts
#  Input 3: Canonical keywords in Taglish — ALL alerts (baseline)
# ============================================================

SOP3_PATTERNS = ["gcash", "blocked", "verify", "click", "link"]

SOP3_TESTS = [
    # Phonetic: gkash (k/c natural Filipino spelling), berify (b/v phonological
    # confusion native to Filipino English) — WON'T trigger
    "GCASH ALERTO: Na-hold ang iyong gkash. Mag-berify agad para ma-recover.",

    # Morphological + phonetic: i-berify (Tagalog verbal affix + b/v confusion),
    # mag-klik (natural Filipino verbal form of click) — WON'T trigger
    "Kailangan mo i-berify ang iyong account. Mag-klik ka na.",

    # Canonical Taglish scam message — WILL trigger (baseline)
    "GCASH ALERT: Ang iyong gcash account ay blocked. I-click ang link para ma-verify.",
]


# ============================================================
#  SOP 4 — Flat URL Stream / No Structural Position Awareness
#  Problem: Algorithm treats the entire URL as a flat character
#           stream, producing identical match output regardless
#           of whether a brand keyword appears in a legitimate
#           SLD position or a phishing subdomain/path position.
#
#  Input 1: Legitimate URL — brand in SLD (SAFE)
#           SHOULD NOT alert, but WILL (false positive)
#  Input 2: Phishing URL — brand in subdomain (DANGEROUS)
#           SHOULD alert, and WILL — but for the WRONG reason
#           (same output as Input 1, no positional distinction)
#  Input 3: Phishing URL — brand in path (DANGEROUS)
#           SHOULD alert, and WILL — but again indistinguishable
#           from a legitimate match (baseline)
# ============================================================

SOP4_PATTERNS = ["gcash", "paypal", "bpi", "login", "verify"]

SOP4_TESTS = [
    # LEGITIMATE: brand "gcash" is the actual registered SLD
    # Algorithm sees: g-c-a-s-h-.-c-o-m-/-d-a-s-h-b-o-a-r-d
    # Output: match found — but this is SAFE, brand is in SLD
    # SHOULD NOT alert, but WILL (false positive)
    "https://gcash.com/dashboard",

    # PHISHING: brand "gcash" is embedded in the SUBDOMAIN
    # Algorithm sees flat stream:
    # g-c-a-s-h-.-v-e-r-i-f-y-.-m-a-l-i-c-i-o-u-s-.-c-o-m-/-l-o-g-i-n
    # Output: SAME match as Input 1 — no positional distinction
    # Algorithm cannot tell brand is in subdomain, not SLD
    "https://gcash.verify.malicious.com/login",

    # PHISHING: brand "paypal" is embedded in the PATH
    # Algorithm sees flat stream:
    # f-a-k-e-b-a-n-k-.-c-o-m-/-p-a-y-p-a-l-/-s-e-c-u-r-e-/-l-o-g-i-n
    # Output: SAME match structure — brand in path indistinguishable
    # from brand in SLD under flat stream processing (baseline)
    "https://fakebank.com/paypal/secure/login",
]


# ============================================================
#  MAIN — Run All Simulations
# ============================================================

if __name__ == "__main__":
    print("\n" + "X"*60)
    print("  AHO-CORASICK ALGORITHM — SOP SIMULATION")
    print("  Demonstrating Structural Limitations")
    print("X"*60)

    run_simulation("SOP 1 — Character Obfuscation", SOP1_PATTERNS, SOP1_TESTS)
    run_simulation("SOP 2 — False Positives / Context-Free Matching", SOP2_PATTERNS, SOP2_TESTS)
    run_simulation("SOP 3 — Phonetic & Linguistic Inflexibility", SOP3_PATTERNS, SOP3_TESTS)
    run_simulation("SOP 4 — Flat URL Stream / No Structural Position Awareness", SOP4_PATTERNS, SOP4_TESTS)

    print(f"\n{'='*60}")
    print("  END OF SIMULATION")
    print(f"{'='*60}\n")