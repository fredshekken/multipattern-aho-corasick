"""
Test Cases for the Enhanced Aho-Corasick Engine
================================================
Each test demonstrates one of the enhancement objectives (O1-O4) working
as intended, kept separate from enhanced_aho_corasick.py so that file
contains only the algorithm itself. Mirrors the structure of
original_aho/test.py, which does the same for the baseline algorithm.
"""

import socket
import ssl
from contextlib import redirect_stdout
from email.message import Message
from io import StringIO
from pathlib import Path
from urllib.error import HTTPError, URLError
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
    terminal_output = StringIO()
    with redirect_stdout(terminal_output):
        with patch.object(scanner, "_unshorten_url", return_value=expanded_url) as unshorten:
            result = scanner.assess_message(
                "https://bit.ly/actualbpisece\n"
                "www.bpi.com.ph\n"
                "Cybersecurity\n"
                "Know how we keep you safe and how you can protect yourself."
            )

    assert unshorten.call_count == 1
    assert expanded_url in terminal_output.getvalue()
    assert "Whitelisted: True" in terminal_output.getvalue()
    assert "verified legitimate" in terminal_output.getvalue()
    assert result["action_tier"] == 0
    assert not result["detections"]


def test_o4_trusted_shortener_preview_does_not_hide_suspicious_message_text():
    patterns = EnhancedAhoCorasick.parse_pattern_groups(
        Path(__file__).with_name("default_patterns.txt").read_text(encoding="utf-8")
    )
    scanner = EnhancedAhoCorasick(patterns)
    expanded_url = "https://www.bpi.com.ph/personal/bank/digital-banking/online/cybersecurity"
    message = (
        "Urgent: verify your gcash account now!\n"
        "https://bit.ly/actualbpiseceu\n"
        "www.bpi.com.ph\n"
        "Cybersecurity"
    )

    with patch.object(scanner, "_unshorten_url", return_value=expanded_url):
        result = scanner.assess_message(message)

    assert result["action_tier"] >= 2
    assert result["detections"]


def test_o4_unresolved_shorteners_remain_unverified():
    scanner = build_scanner()
    preview_destinations = {
        "https://bit.ly/4yGX271": "https://bpi-security-update.com/login",
        "https://bit.ly/12Tst": "http://vmsvedaweb.com/gayatri/",
    }

    expected_tier = {
        "https://bit.ly/4yGX271": 3,   # lookalike destination: R = 2.0
        "https://bit.ly/12Tst": 0,     # unknown site with no risk signal: normal link
    }

    for url, destination in preview_destinations.items():
        with patch.object(scanner, "_unshorten_url", return_value=destination):
            assessment = scanner.assess_message(url)

        assert assessment["action_tier"] == expected_tier[url]
        if expected_tier[url] == 3:
            assert "url_risk" in assessment["evidence_groups"]
            assert any(
                detection["match_type"] == "url_shortener"
                and detection["score_breakdown"]["matched_text"] == destination
                for detection in assessment["detections"]
            )
        else:
            assert not assessment["detections"]


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

    with patch("enhanced_aho_corasick.build_opener") as mocked_build_opener:
        mocked_opener = mocked_build_opener.return_value
        mocked_opener.open.return_value = response
        result = scanner.assess_message("https://bit.ly/actualbpisece")

    assert result["action_tier"] == 0
    assert not result["detections"]
    https_handler = mocked_build_opener.call_args.args[0]
    context = https_handler._context
    request = mocked_opener.open.call_args.args[0]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.get_ca_certs()
    assert request.get_method() == "GET"
    response.read.assert_called_once_with(256 * 1024)


def test_o4_shortener_captures_redirect_without_requesting_destination():
    scanner = build_scanner()
    redirect_headers = Message()
    redirect_headers["Location"] = "https://dead-destination.example/login"
    redirect = HTTPError(
        "https://tinyurl.com/fakebp1",
        302,
        "Found",
        redirect_headers,
        None,
    )

    with patch("enhanced_aho_corasick.build_opener") as mocked_build_opener:
        mocked_opener = mocked_build_opener.return_value
        mocked_opener.open.side_effect = redirect
        result = scanner._unshorten_url("https://tinyurl.com/fakebp1")

    assert result == "https://dead-destination.example/login"
    mocked_opener.open.assert_called_once()
    request = mocked_opener.open.call_args.args[0]
    assert request.full_url == "https://tinyurl.com/fakebp1"
    assert mocked_build_opener.call_count == 1


def test_o4_captured_trusted_redirect_remains_clean():
    scanner = EnhancedAhoCorasick(
        EnhancedAhoCorasick.parse_pattern_groups(
            Path(__file__).with_name("default_patterns.txt").read_text(encoding="utf-8")
        )
    )
    redirect_headers = Message()
    redirect_headers["Location"] = (
        "https://www.bpi.com.ph/personal/bank/digital-banking/online/cybersecurity"
    )
    redirect = HTTPError(
        "https://tinyurl.com/actualbpisece",
        302,
        "Found",
        redirect_headers,
        None,
    )

    with patch("enhanced_aho_corasick.build_opener") as mocked_build_opener:
        mocked_opener = mocked_build_opener.return_value
        mocked_opener.open.side_effect = redirect
        result = scanner.assess_message("https://tinyurl.com/actualbpisece")

    assert result["action_tier"] == 0
    assert not result["detections"]
    mocked_opener.open.assert_called_once()
    assert mocked_opener.open.call_args.args[0].full_url == "https://tinyurl.com/actualbpisece"


def test_o4_tinyurl_viglink_redirect_unwraps_to_trusted_bpi():
    scanner = EnhancedAhoCorasick(
        EnhancedAhoCorasick.parse_pattern_groups(
            Path(__file__).with_name("default_patterns.txt").read_text(encoding="utf-8")
        )
    )
    tracking_url = (
        "https://redirect.viglink.com/?u="
        "http%3A%2F%2Fonline.bpi.com.ph%2F"
        "&key=example&source=TinyURL"
    )
    terminal_output = StringIO()

    with redirect_stdout(terminal_output), patch.object(
        scanner,
        "_unshorten_url",
        return_value=tracking_url,
    ):
        result = scanner.assess_message("https://tinyurl.com/bpireal2")

    assert result["action_tier"] == 0
    assert result["is_clean"]
    assert not result["detections"]
    output = terminal_output.getvalue()
    assert (
        "Successfully unmasked: https://tinyurl.com/bpireal2 -> "
        "http://online.bpi.com.ph/"
    ) in output
    assert "Resolved root: bpi.com.ph | Whitelisted: True" in output


def test_o4_viglink_redirect_to_untrusted_domain_stays_risky():
    scanner = build_scanner()
    tracking_url = (
        "https://redirect.viglink.com/?u="
        "https%3A%2F%2Fphishing.example%2Flogin"
    )

    with patch.object(scanner, "_unshorten_url", return_value=tracking_url):
        result = scanner._analyze_url("https://tinyurl.com/fakebp1")

    assert result["expanded_url"] == "https://phishing.example/login"
    assert not result["is_whitelisted"]
    # The revealed destination is analyzed like any other URL: "login" in the path
    assert result["segment"] == "path"
    assert result["multiplier"] == scanner.SEGMENT_RISK["path"]
    assert result["destination_risky"]


def test_o4_shortener_retries_transient_dns_failure():
    scanner = build_scanner()
    response = MagicMock()
    response.__enter__.return_value = response
    response.geturl.return_value = "https://unverified.example/login"

    with (
        patch("enhanced_aho_corasick.build_opener") as mocked_build_opener,
        patch("enhanced_aho_corasick.time.sleep") as mocked_sleep,
    ):
        mocked_opener = mocked_build_opener.return_value
        mocked_opener.open.side_effect = [
            URLError(socket.gaierror(11002, "getaddrinfo failed")),
            response,
        ]
        result = scanner._unshorten_url("https://tinyurl.com/fakebp1")

    assert result == "https://unverified.example/login"
    assert mocked_opener.open.call_count == 2
    mocked_sleep.assert_called_once_with(0.25)


def test_o4_shortener_returns_unresolved_after_retry_limit():
    scanner = build_scanner()
    dns_error = URLError(socket.gaierror(11002, "getaddrinfo failed"))

    with (
        patch("enhanced_aho_corasick.build_opener") as mocked_build_opener,
        patch("enhanced_aho_corasick.time.sleep") as mocked_sleep,
    ):
        mocked_opener = mocked_build_opener.return_value
        mocked_opener.open.side_effect = dns_error
        result = scanner._unshorten_url("https://tinyurl.com/fakebp1")

    assert result == "https://tinyurl.com/fakebp1"
    assert mocked_opener.open.call_count == 3
    assert mocked_sleep.call_count == 2


def test_o4_shortener_does_not_retry_http_403():
    scanner = build_scanner()
    forbidden = HTTPError(
        "https://tinyurl.com/sbreal",
        403,
        "Forbidden",
        Message(),
        None,
    )

    with (
        patch("enhanced_aho_corasick.build_opener") as mocked_build_opener,
        patch("enhanced_aho_corasick.time.sleep") as mocked_sleep,
    ):
        mocked_opener = mocked_build_opener.return_value
        mocked_opener.open.side_effect = forbidden
        result = scanner._unshorten_url("https://tinyurl.com/sbreal")

    assert result == "https://tinyurl.com/sbreal"
    mocked_opener.open.assert_called_once()
    mocked_sleep.assert_not_called()


def test_o4_preview_reveals_unverified_destination_as_risky():
    scanner = build_scanner()
    preview_destinations = {
        "https://bit.ly/4yGX271": "https://bpi-security-update.com/login",
        "https://bit.ly/12Tst": "http://vmsvedaweb.com/gayatri/",
    }
    terminal_output = StringIO()
    # Destination classified like any other URL (not "any non-whitelisted = 2.5x")
    expected_segment = {
        "https://bit.ly/4yGX271": "path",   # "login" in the path (this test scanner has no brand list)
        "https://bit.ly/12Tst": "none",     # unknown site with no risk signal
    }

    with redirect_stdout(terminal_output):
        for short_url, destination in preview_destinations.items():
            response = MagicMock()
            response.__enter__.return_value = response
            response.geturl.return_value = short_url
            response.read.return_value = (
                f'<a href="{destination}">{destination.removeprefix("https://").removeprefix("http://")}</a>'
            ).encode("utf-8")

            with patch("enhanced_aho_corasick.build_opener") as mocked_build_opener:
                mocked_build_opener.return_value.open.return_value = response
                result = scanner._analyze_url(short_url)

            assert result["expanded_url"] == destination
            assert not result["is_whitelisted"]
            assert result["segment"] == expected_segment[short_url]
            assert result["multiplier"] == scanner.SEGMENT_RISK[expected_segment[short_url]]

    captured_output = terminal_output.getvalue()
    assert "Successfully unmasked: https://bit.ly/4yGX271" in captured_output
    assert "Resolved root: bpi-security-update.com | Whitelisted: False" in captured_output
    assert "Successfully unmasked: https://bit.ly/12Tst" in captured_output
    assert "Resolved root: vmsvedaweb.com | Whitelisted: False" in captured_output


def test_o4_shortener_keeps_risk_for_unverified_destination():
    scanner = build_scanner()
    expanded_url = "https://unverified.example/login"

    with patch.object(scanner, "_unshorten_url", return_value=expanded_url):
        result = scanner._analyze_url("https://bit.ly/unverified")

    assert not result["is_whitelisted"]
    assert result["segment"] == "path"
    assert result["multiplier"] == scanner.SEGMENT_RISK["path"]
    assert result["expanded_url"] == expanded_url


def test_o4_brand_in_path(scanner):
    msg = "Urgent: https://verify-now.com/gcash/confirm your account"
    run_test("O4 — Brand in path (MEDIUM risk)", scanner, msg)


# ============================================================
#  O4 -- URL analysis: worst URL decides, ports, lookup limit,
#        cache, offline switch
# ============================================================

def build_quiet_scanner(**kwargs):
    return EnhancedAhoCorasick(PATTERNS, max_errors=1, url_trace=False, **kwargs)


def _same_url(url, *args, **kwargs):
    """Stand-in resolver: the shortened link could not be resolved."""
    return url


def test_o4_worst_url_decides_when_whitelisted_link_comes_first():
    scanner = build_quiet_scanner()
    with patch.object(scanner, "_unshorten_url", side_effect=_same_url):
        shortener_after = scanner._analyze_url(
            "See https://gcash.com/help then https://bit.ly/abc123"
        )
        spoof_after = scanner._analyze_url(
            "See https://gcash.com/help then https://gcash.com.verify-now.xyz/login"
        )
    assert shortener_after["segment"] == "shortener"
    assert not shortener_after["is_whitelisted"]
    assert spoof_after["segment"] == "subdomain"
    assert not spoof_after["is_whitelisted"]
    print("  [OK] A whitelisted link first does not hide a shortener or spoof after it.")


def test_o4_all_whitelisted_links_stay_clean():
    scanner = build_quiet_scanner()
    result = scanner._analyze_url("https://gcash.com/help and https://www.bpi.com.ph/security")
    assert result["is_whitelisted"]
    assert result["multiplier"] == scanner.SEGMENT_RISK["whitelisted"]
    print("  [OK] Several whitelisted links remain clean.")


def test_o4_port_number_does_not_break_whitelist():
    scanner = build_quiet_scanner()
    official = scanner._analyze_url("https://gcash.com:8443/help")
    spoof = scanner._analyze_url("https://gcash.com.verify-now.xyz:8443/login")
    assert official["is_whitelisted"]
    assert spoof["segment"] == "subdomain" and not spoof["is_whitelisted"]
    print("  [OK] A port number neither breaks the whitelist nor hides a spoof.")


def test_o4_userinfo_trick_is_not_whitelisted():
    scanner = build_quiet_scanner()
    result = scanner._analyze_url("https://gcash.com@evil-site.xyz/login")
    assert not result["is_whitelisted"]
    print("  [OK] gcash.com@evil-site.xyz is not treated as the official domain.")


def test_o4_shortener_lookup_limit_keeps_extra_links_risky():
    scanner = build_quiet_scanner()
    text = " ".join(f"https://bit.ly/link{i}" for i in range(6))
    with patch.object(scanner, "_unshorten_url", side_effect=_same_url) as unshorten:
        result = scanner._analyze_url(text)
    assert unshorten.call_count == scanner.MAX_SHORTENER_LOOKUPS
    assert result["segment"] == "shortener" and result["shortener_untrusted"]
    print(f"  [OK] At most {scanner.MAX_SHORTENER_LOOKUPS} lookups per message; the rest stay risky.")


def test_o4_extra_shorteners_cannot_hide_behind_trusted_ones():
    scanner = build_quiet_scanner()
    text = " ".join(f"https://bit.ly/trusted{i}" for i in range(4))
    with patch.object(scanner, "_unshorten_url", return_value="https://www.bpi.com.ph/x"):
        result = scanner._analyze_url(text)
    # three links resolve to a trusted bank; the fourth is beyond the limit and stays risky
    assert result["segment"] == "shortener" and result["shortener_untrusted"]
    print("  [OK] A shortener past the lookup limit still counts as risky.")


def test_o4_shortener_resolution_is_cached():
    scanner = build_quiet_scanner()
    url = "https://bit.ly/cacheme"
    with patch.object(scanner, "_unshorten_url", return_value="https://www.bpi.com.ph/x") as unshorten:
        scanner._analyze_url(url)
        scanner._analyze_url("again " + url)
        assert unshorten.call_count == 1
        # simulate an expired cache entry: the link is looked up again
        value, _ = scanner._shortener_cache[url]
        scanner._shortener_cache[url] = (value, 0)
        scanner._analyze_url(url)
        assert unshorten.call_count == 2
    print("  [OK] A resolved link is looked up once, and again after the entry expires.")


def test_o4_shortener_resolution_can_be_switched_off():
    scanner = build_quiet_scanner(resolve_shorteners=False)
    with patch.object(scanner, "_unshorten_url") as unshorten:
        result = scanner._analyze_url("https://bit.ly/abc123")
    unshorten.assert_not_called()
    assert result["segment"] == "shortener" and result["shortener_untrusted"]
    print("  [OK] With resolution off, no shortener is contacted and it stays risky.")


def test_o4_url_trace_can_be_silenced():
    scanner = build_quiet_scanner()
    output = StringIO()
    with redirect_stdout(output):
        with patch.object(scanner, "_unshorten_url", side_effect=_same_url):
            scanner._analyze_url("https://bit.ly/abc123")
    assert output.getvalue() == ""
    print("  [OK] url_trace=False prints nothing.")


def test_o4_message_contacts_shortener_only_once():
    scanner = build_quiet_scanner()
    with patch.object(scanner, "_unshorten_url", side_effect=_same_url) as unshorten:
        scanner.assess_message("Verify your gcash account now https://bit.ly/onlyonce")
    assert unshorten.call_count == 1
    print("  [OK] assess_message contacts a shortened link only once.")



# ============================================================
#  O4 -- Lookalike domains (optional flag) and whitelist coverage
# ============================================================

def build_lookalike_scanner(flag=True):
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_patterns.txt")
    return EnhancedAhoCorasick.from_pattern_file(
        path, url_trace=False, flag_lookalike_domains=flag
    )


def build_default_scanner():
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_patterns.txt")
    return EnhancedAhoCorasick.from_pattern_file(path, url_trace=False)


def test_o4_lookalike_check_is_on_by_default():
    scanner = build_default_scanner()
    assert scanner.flag_lookalike_domains is True
    result = scanner._analyze_url("https://gcash-verify.xyz/login")
    assert result["segment"] == "lookalike"
    print("  [OK] The lookalike-domain check is on by default.")


def test_o4_lookalike_check_can_be_switched_off():
    scanner = build_lookalike_scanner(flag=False)
    result = scanner._analyze_url("https://gcash-verify.xyz/login")
    assert result["segment"] != "lookalike"
    print("  [OK] With the check switched off, the older behavior is kept.")


def test_o4_lookalike_flag_escalates_brand_in_unverified_domain():
    scanner = build_lookalike_scanner()
    for url in ["https://gcash-verify.xyz/login", "https://notgcash.com/login",
                "https://gcash-verify.com.ph/login", "https://bdo-verify.xyz/x",
                "https://grab-promo.xyz/x"]:
        result = scanner._analyze_url(url)
        assert result["segment"] == "lookalike", (url, result)
        assert result["multiplier"] == scanner.SEGMENT_RISK["subdomain"]
        assert not result["is_whitelisted"]
    print("  [OK] Brand names inside unverified domains are flagged as lookalikes.")


def test_o4_lookalike_flag_keeps_verified_domains_clean():
    scanner = build_lookalike_scanner()
    for url in ["https://gcash.com/help", "https://www.bpi.com.ph/security",
                "https://paypal.com/help", "https://amazon.com/help",
                "https://whatsapp.com/help", "https://paypal.me/someone",
                "https://lazada.com/help"]:
        result = scanner._analyze_url(url)
        assert result["is_whitelisted"], (url, result)
    print("  [OK] Verified brand domains stay clean, including PayPal, Amazon, WhatsApp.")


def test_o4_lookalike_flag_ignores_generic_words_and_short_substrings():
    scanner = build_lookalike_scanner()
    for url in ["https://accountmanager.com", "https://mybank.com", "https://loginhelp.com",
                "https://abdomen.com", "https://grabbing-deals.com"]:
        result = scanner._analyze_url(url)
        assert result["segment"] != "lookalike", (url, result)
    print("  [OK] Generic words and short-name substrings are not treated as brand spoofing.")


def test_o4_lookalike_counts_as_url_risk_evidence():
    scanner = build_lookalike_scanner()
    result = scanner.assess_message("verify your account https://gcash-verify.xyz/login")
    assert "url_risk" in result["evidence_groups"]
    print("  [OK] A lookalike domain is reported as URL risk evidence.")


def test_o4_whitelist_covers_all_named_brands():
    scanner = build_lookalike_scanner(flag=False)
    for url in ["https://paypal.com/x", "https://amazon.com/x", "https://whatsapp.com/x"]:
        assert scanner._analyze_url(url)["is_whitelisted"], url
    print("  [OK] PayPal, Amazon, and WhatsApp are whitelisted.")


# ============================================================
#  O1 -- Failure links and DFA transition flattening
# ============================================================

def test_o1_scan_follows_failure_links():
    scanner = EnhancedAhoCorasick(["account suspended", "click here", "account", "click"],
                                  max_errors=1, url_trace=False)
    for text, phrase in [("account account suspended", "account suspended"),
                         ("click click here", "click here")]:
        found = {d["score_breakdown"]["pattern"] for d in scanner.enhanced_search(text)
                 if d["match_type"] == "exact"}
        assert phrase in found, (text, found)
    print("  [OK] A mismatch follows the failure link instead of restarting the scan.")


def test_o1_flattened_dfa_matches_brute_force():
    import random
    scanner = build_default_scanner()
    norm = [scanner._normalize(p) for p in scanner.patterns]

    def dfa(text):
        found, state = set(), 0
        for i, char in enumerate(text):
            state = scanner.delta[state].get(char, 0)
            if scanner.out[state]:
                for j in range(len(norm)):
                    if scanner.out[state] & (1 << j):
                        found.add((j, i))
        return found

    def brute(text):
        found = set()
        for j, p in enumerate(norm):
            start = text.find(p)
            while start != -1:
                found.add((j, start + len(p) - 1))
                start = text.find(p, start + 1)
        return found

    rng = random.Random(7)
    pieces = norm + [" ", "a", "x", "-", "ng", "sa"]
    for _ in range(500):
        text = scanner._normalize("".join(
            rng.choice(pieces) + rng.choice(["", " ", "a"]) for _ in range(rng.randint(1, 9))))
        assert dfa(text) == brute(text), text
    print("  [OK] The flattened DFA finds exactly the same matches as a brute-force search.")


def test_o3_affix_root_must_be_an_exact_trie_path():
    scanner = build_default_scanner()
    assert scanner._trie_recognizes("verify")
    assert not scanner._trie_recognizes("xverify")
    assert not scanner._trie_recognizes("ggcash")
    print("  [OK] A stripped root counts only if the whole root is a keyword path.")


# ============================================================
#  O4 -- Resolved destinations are analyzed, not auto-flagged
# ============================================================

def test_o4_resolved_safe_destination_is_a_normal_link():
    scanner = build_quiet_scanner()
    with patch.object(scanner, "_unshorten_url", return_value="https://www.youtube.com/watch?v=1"):
        info = scanner._analyze_url("https://bit.ly/video")
        result = scanner.assess_message("check this out https://bit.ly/video")
    assert info["segment"] == "none" and info["multiplier"] == scanner.SEGMENT_RISK["none"]
    assert not info["destination_risky"]
    assert result["action_tier"] == 0 and not result["detections"]
    print("  [OK] A resolved destination with no risk signal is treated as a normal link.")


def test_o4_resolved_risky_destination_is_its_own_detection():
    scanner = build_default_scanner()  # full dictionary, includes the brand list
    with patch.object(scanner, "_unshorten_url", return_value="https://bpi-security-update.com/x"):
        result = scanner.assess_message("https://bit.ly/abc")
    links = [d for d in result["detections"] if d["match_type"] == "url_shortener"]
    assert len(links) == 1
    assert links[0]["score_breakdown"]["pattern"] == "SHORTENED_LINK_DESTINATION"
    # R = destination multiplier (lookalike = 2.0)
    assert links[0]["risk_score"] == scanner.SEGMENT_RISK["lookalike"]
    assert "url_risk" in result["evidence_groups"]
    print("  [OK] A risky revealed destination adds one detection with R = its multiplier.")


def test_o4_unresolved_shortener_keeps_fixed_risk():
    scanner = build_quiet_scanner()
    with patch.object(scanner, "_unshorten_url", side_effect=_same_url):
        result = scanner.assess_message("https://bit.ly/unknown")
    links = [d for d in result["detections"] if d["match_type"] == "url_shortener"]
    assert links[0]["score_breakdown"]["pattern"] == "UNVERIFIED_SHORTENER"
    assert links[0]["risk_score"] == scanner.SEGMENT_RISK["shortener"]
    print("  [OK] A link that cannot be resolved keeps the fixed 2.5 risk.")


def test_o4_destination_that_is_still_a_shortener_is_unresolved():
    scanner = build_quiet_scanner()
    with patch.object(scanner, "_unshorten_url", return_value="https://bit.ly/xk92p"):
        info = scanner._analyze_url("https://bit.ly/xK92p")
    assert info["segment"] == "shortener" and info["shortener_untrusted"]
    assert info["multiplier"] == scanner.SEGMENT_RISK["shortener"]
    print("  [OK] A 'destination' that is still a shortened link counts as unresolved.")


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
    test_o1_scan_follows_failure_links()
    test_o1_flattened_dfa_matches_brute_force()
    test_o3_affix_root_must_be_an_exact_trie_path()

    test_o2_boosters_increase_score(scanner)
    test_o2_neutralizers_suppress_score(scanner)

    test_o3_prefixed_affix_forms(scanner)
    test_o3_suffixed_affix_forms(scanner)

    test_o4_brand_in_subdomain(scanner)
    test_o4_brand_in_sld(scanner)
    test_o4_url_analysis_uses_original_url_text()
    test_o4_url_shortener(scanner)
    test_o4_shortener_resolves_whitelisted_destination()
    test_o4_trusted_shortener_preview_does_not_hide_suspicious_message_text()
    test_o4_shortener_keeps_risk_for_unverified_destination()
    test_o4_unresolved_shorteners_remain_unverified()
    test_o4_shortener_request_uses_verified_certifi_tls()
    test_o4_shortener_captures_redirect_without_requesting_destination()
    test_o4_captured_trusted_redirect_remains_clean()
    test_o4_tinyurl_viglink_redirect_unwraps_to_trusted_bpi()
    test_o4_viglink_redirect_to_untrusted_domain_stays_risky()
    test_o4_shortener_retries_transient_dns_failure()
    test_o4_shortener_returns_unresolved_after_retry_limit()
    test_o4_shortener_does_not_retry_http_403()
    test_o4_preview_reveals_unverified_destination_as_risky()
    test_o4_worst_url_decides_when_whitelisted_link_comes_first()
    test_o4_all_whitelisted_links_stay_clean()
    test_o4_port_number_does_not_break_whitelist()
    test_o4_userinfo_trick_is_not_whitelisted()
    test_o4_shortener_lookup_limit_keeps_extra_links_risky()
    test_o4_extra_shorteners_cannot_hide_behind_trusted_ones()
    test_o4_shortener_resolution_is_cached()
    test_o4_shortener_resolution_can_be_switched_off()
    test_o4_url_trace_can_be_silenced()
    test_o4_message_contacts_shortener_only_once()
    test_o4_resolved_safe_destination_is_a_normal_link()
    test_o4_resolved_risky_destination_is_its_own_detection()
    test_o4_unresolved_shortener_keeps_fixed_risk()
    test_o4_destination_that_is_still_a_shortener_is_unresolved()
    test_o4_lookalike_check_is_on_by_default()
    test_o4_lookalike_check_can_be_switched_off()
    test_o4_lookalike_flag_escalates_brand_in_unverified_domain()
    test_o4_lookalike_flag_keeps_verified_domains_clean()
    test_o4_lookalike_flag_ignores_generic_words_and_short_substrings()
    test_o4_lookalike_counts_as_url_risk_evidence()
    test_o4_whitelist_covers_all_named_brands()
    test_o4_brand_in_path(scanner)

    print(f"\n{'='*60}")
    print("  ALL TESTS COMPLETED (see assertions above for pass/fail)")
    print(f"{'='*60}\n")