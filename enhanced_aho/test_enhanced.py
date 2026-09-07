"""
Test Cases for the Enhanced Aho-Corasick Engine
================================================
Each test demonstrates one of the enhancement objectives (O1-O4) working
as intended, kept separate from enhanced_aho_corasick.py so that file
contains only the algorithm itself. Mirrors the structure of
original_aho/test.py, which does the same for the baseline algorithm.
"""

from enhanced_aho_corasick import EnhancedAhoCorasick


# ============================================================
#  SHARED UTILITY
# ============================================================

def run_test(label: str, scanner: EnhancedAhoCorasick, message: str):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  INPUT: \"{message}\"")

    detections = scanner.enhanced_search(message)
    if not detections:
        print("  [✓] No threats detected.")
        return detections

    for f in detections:
        print(f"  [!] [{f['risk_score']}] [{f['match_type']}] {f['alert']}")
        print(f"      Context: ...{f['context']}...")
    return detections


# ============================================================
#  Shared scanner + dictionary used across O1-O4 demonstrations
# ============================================================

PATTERNS = ["gcash", "blocked", "login"]


def build_scanner():
    return EnhancedAhoCorasick(PATTERNS, max_errors=1)


# ============================================================
#  O1 — Normalization Layer + Bit-Parallel Fuzzy Matching
# ============================================================

def test_o1_normalization_and_trie(scanner):
    msg = "Urgent: Your G-C@sh account is vlocked! Verify here: http://bit.ly/fake-link"
    run_test("O1 — Normalization + Trie (symbol substitution)", scanner, msg)


def test_o1_fuzzy_bitap_layer(scanner):
    msg = "Urgent: Your gczsh account is blxcked! Verify here: http://bit.ly/fake-link"
    run_test("O1 — Fuzzy (Bitap) layer (residual substitution obfuscation)", scanner, msg)


def test_o1_fuzzy_word_boundary_guard(scanner):
    """
    Regression test for the "otp" / "https" false-positive bug.

    A 3-char pattern like "otp" is only 1 substitution away from "ttp",
    the substring found inside "https". Without a word-boundary check on
    the Bitap fuzzy layer, this coincidental mid-word match could cross
    the alert threshold when boosters (e.g. "click", "verify", "urgent")
    appear nearby — flagging a message that never contained "otp" at all.
    """
    otp_scanner = EnhancedAhoCorasick(["otp"], max_errors=1)

    # Should NOT trigger: "https" is not "otp", regardless of nearby boosters
    msg_false_positive = "please click this https link to verify urgent"
    detections = run_test(
        "O1 — Fuzzy word-boundary guard (https must NOT trigger 'otp')",
        otp_scanner, msg_false_positive
    )
    assert not detections, "REGRESSION: 'https' incorrectly matched 'otp'"

    # Should still trigger: genuine standalone word, 1 substitution from "otp"
    msg_true_fuzzy = "Pakibigay ang otq mo agad, urgent!"
    detections = run_test(
        "O1 — Fuzzy word-boundary guard (standalone 'otq' SHOULD trigger)",
        otp_scanner, msg_true_fuzzy
    )
    assert any(d["match_type"] == "fuzzy" for d in detections), \
        "REGRESSION: genuine fuzzy variant 'otq' was not detected"


# ============================================================
#  O2 — Proximity-Based Weighting (IDW)
# ============================================================

def test_o2_boosters_increase_score(scanner):
    msg = "AGAD! I-verify ang iyong gcash account. Mag-login na ngayon bago ma-block!"
    run_test("O2 — Multiple close boosters (high IDW score)", scanner, msg)


def test_o2_neutralizers_suppress_score(scanner):
    msg = "Official GCash customer support hotline. Login to our authorized service portal."
    run_test("O2 — Neutralizers present (suppressed score)", scanner, msg)


# ============================================================
#  O3 — Phonetic Mapping + Morphological Affix Stripping
# ============================================================

def test_o3_prefixed_affix_forms(scanner):
    msg = "Agad mag-login at i-verify ang iyong account. I-gcash na ngayon!"
    run_test("O3 — Affix-stripped detection (mag-login, i-gcash)", scanner, msg)


def test_o3_suffixed_affix_forms(scanner):
    """
    "gcashin" = "gcash" + Filipino object-focus suffix "-in".

    Regression coverage: "gcashin" also happens to end in "-hin", one of
    the other recognized suffixes. Greedily stripping the longest matching
    suffix first would take "-hin" instead of "-in", incorrectly turning
    "gcashin" into "gcas" instead of "gcash". The fix prefers whichever
    suffix candidate the trie actually recognizes.
    """
    msg = "URGENT! I-verify mo agad ang gcashin mo, baka ma-suspend!"
    detections = run_test("O3 — Suffix-stripped detection ('gcashin' -> 'gcash')", scanner, msg)
    assert any(d["match_type"] == "affix" and "gcash" in d["alert"] for d in detections), \
        "REGRESSION: 'gcashin' was not recognized as 'gcash' + suffix"


# ============================================================
#  O4 — Delimiter-Driven URL Segmentation + Segment-Bound Risk
# ============================================================

def test_o4_brand_in_subdomain(scanner):
    msg = "Verify here: https://gcash.verify-now.com/login"
    run_test("O4 — Brand in subdomain (HIGH risk, spoofing)", scanner, msg)


def test_o4_brand_in_sld(scanner):
    msg = "Visit https://gcash.com/help for assistance."
    run_test("O4 — Brand in SLD (LOW risk, legitimate)", scanner, msg)


def test_o4_url_shortener(scanner):
    msg = "Urgent: Click here to verify your gcash: https://bit.ly/xK92p"
    run_test("O4 — URL shortener (HIGHEST risk)", scanner, msg)


def test_o4_brand_in_path(scanner):
    msg = "Urgent: https://verify-now.com/gcash/confirm your account"
    run_test("O4 — Brand in path (MEDIUM risk)", scanner, msg)


# ============================================================
#  MAIN — Run All Tests
# ============================================================

if __name__ == "__main__":
    print("\n" + "X"*60)
    print("  ENHANCED AHO-CORASICK — OBJECTIVE-BY-OBJECTIVE TEST SUITE")
    print("X"*60)

    scanner = build_scanner()

    test_o1_normalization_and_trie(scanner)
    test_o1_fuzzy_bitap_layer(scanner)
    test_o1_fuzzy_word_boundary_guard(scanner)

    test_o2_boosters_increase_score(scanner)
    test_o2_neutralizers_suppress_score(scanner)

    test_o3_prefixed_affix_forms(scanner)
    test_o3_suffixed_affix_forms(scanner)

    test_o4_brand_in_subdomain(scanner)
    test_o4_brand_in_sld(scanner)
    test_o4_url_shortener(scanner)
    test_o4_brand_in_path(scanner)

    print(f"\n{'='*60}")
    print("  ALL TESTS COMPLETED (see assertions above for pass/fail)")
    print(f"{'='*60}\n")