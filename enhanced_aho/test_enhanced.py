"""
Test Cases for the Enhanced Aho-Corasick Engine
================================================
Each test demonstrates one of the enhancement objectives (O1-O4) working
as intended, kept separate from enhanced_aho_corasick.py so that file
contains only the algorithm itself. Mirrors the structure of
original_aho/test.py, which does the same for the baseline algorithm.
"""

import logging
import ssl
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    with patch.object(scanner, "_unshorten_url", return_value="http://bit.ly/fake-link"):
        run_test("O1 — Normalization + Trie (symbol substitution)", scanner, msg)


def test_o1_fuzzy_bitap_layer(scanner):
    msg = "Urgent: Your gczsh account is blxcked! Verify here: http://bit.ly/fake-link"
    with patch.object(scanner, "_unshorten_url", return_value="http://bit.ly/fake-link"):
        run_test("O1 — Fuzzy (Bitap) layer (residual substitution obfuscation)", scanner, msg)


def test_o1_fuzzy_word_boundary_guard():
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


def test_o4_url_analysis_uses_original_url_text():
    scanner = build_scanner()
    result = scanner._analyze_url("https://viber.com/help")

    assert result["is_whitelisted"]
    assert result["segment"] == "sld"


def test_o4_url_shortener(scanner):
    msg = "Urgent: Click here to verify your gcash: https://bit.ly/xK92p"
    with patch.object(scanner, "_unshorten_url", return_value="https://bit.ly/xk92p"):
        run_test("O4 — URL shortener (HIGHEST risk)", scanner, msg)


def test_o4_shortener_resolves_whitelisted_destination():
    patterns = EnhancedAhoCorasick.parse_pattern_groups(
        (Path(__file__).with_name("default_patterns.txt")).read_text(encoding="utf-8")
    )
    scanner = EnhancedAhoCorasick(patterns)
    expanded_url = "https://www.bpi.com.ph/cybersecurity"
    log_output = StringIO()
    handler = logging.StreamHandler(log_output)
    logger = logging.getLogger(EnhancedAhoCorasick.__module__)
    previous_level = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    try:
        with patch.object(scanner, "_unshorten_url", return_value=expanded_url) as unshorten:
            result = scanner.assess_message("https://bit.ly/actualbpisece")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        handler.close()

    assert unshorten.call_count == 1
    assert expanded_url in log_output.getvalue()
    assert "classified as whitelisted" in log_output.getvalue()
    assert result["action_tier"] == 0
    assert not result["detections"]


def test_o4_unresolved_shorteners_remain_unverified():
    scanner = build_scanner()

    for url in ("https://bit.ly/4yGX271", "https://bit.ly/12Tst"):
        with patch.object(scanner, "_unshorten_url", return_value=url):
            result = scanner._analyze_url(url)

        assert not result["is_whitelisted"]
        assert result["segment"] == "shortener"
        assert result["multiplier"] == scanner.SEGMENT_RISK["shortener"]


def test_o4_shortener_request_uses_verified_certifi_tls():
    patterns = EnhancedAhoCorasick.parse_pattern_groups(
        Path(__file__).with_name("default_patterns.txt").read_text(encoding="utf-8")
    )
    scanner = EnhancedAhoCorasick(patterns)
    response = MagicMock()
    response.__enter__.return_value = response
    response.geturl.return_value = "https://bit.ly/actualbpisece"
    response.read.return_value = (
        b'<a href="https://www.bpi.com.ph/personal/bank/digital-banking/online/cybersecurity">'
        b'bpi.com.ph/personal/bank/digital-banking/online/cybersecurity</a>'
    )

    with patch("enhanced_aho_corasick.urlopen", return_value=response) as mocked_urlopen:
        result = scanner.assess_message("https://bit.ly/actualbpisece")

    assert result["action_tier"] == 0
    assert not result["detections"]
    context = mocked_urlopen.call_args.kwargs["context"]
    request = mocked_urlopen.call_args.args[0]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.get_ca_certs()
    assert request.get_method() == "GET"
    response.read.assert_called_once_with(256 * 1024)


def test_o4_preview_reveals_unverified_destination_as_risky():
    scanner = build_scanner()
    preview_destinations = {
        "https://bit.ly/4yGX271": "https://bpi-security-update.com/login",
        "https://bit.ly/12Tst": "http://vmsvedaweb.com/gayatri/",
    }

    for short_url, destination in preview_destinations.items():
        response = MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = short_url
        response.read.return_value = (
            f'<a href="{destination}">{destination.removeprefix("https://").removeprefix("http://")}</a>'
        ).encode("utf-8")

        with patch("enhanced_aho_corasick.urlopen", return_value=response):
            result = scanner._analyze_url(short_url)

        assert result["expanded_url"] == destination
        assert not result["is_whitelisted"]
        assert result["segment"] == "shortener"
        assert result["multiplier"] == scanner.SEGMENT_RISK["shortener"]


def test_o4_shortener_keeps_risk_for_unverified_destination():
    scanner = build_scanner()
    expanded_url = "https://unverified.example/login"

    with patch.object(scanner, "_unshorten_url", return_value=expanded_url):
        result = scanner._analyze_url("https://bit.ly/unverified")

    assert not result["is_whitelisted"]
    assert result["segment"] == "shortener"
    assert result["multiplier"] == scanner.SEGMENT_RISK["shortener"]
    assert result["expanded_url"] == expanded_url


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
    test_o1_fuzzy_word_boundary_guard()

    test_o2_boosters_increase_score(scanner)
    test_o2_neutralizers_suppress_score(scanner)

    test_o3_prefixed_affix_forms(scanner)
    test_o3_suffixed_affix_forms(scanner)

    test_o4_brand_in_subdomain(scanner)
    test_o4_brand_in_sld(scanner)
    test_o4_url_analysis_uses_original_url_text()
    test_o4_url_shortener(scanner)
    test_o4_shortener_resolves_whitelisted_destination()
    test_o4_shortener_keeps_risk_for_unverified_destination()
    test_o4_brand_in_path(scanner)

    print(f"\n{'='*60}")
    print("  ALL TESTS COMPLETED (see assertions above for pass/fail)")
    print(f"{'='*60}\n")