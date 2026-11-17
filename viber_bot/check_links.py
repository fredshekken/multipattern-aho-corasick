r"""
Shows where shortened links point, using the same resolver as the engine.
The destination websites are NOT visited; only the shortener is asked.
Needs internet. Run from viber_bot:

    python check_links.py
    python check_links.py https://bit.ly/abc https://tinyurl.com/xyz
"""
import sys

import _bootstrap  # noqa: F401
from compare_engines import DEFAULT_PATTERN_FILE
from enhanced_aho_corasick import EnhancedAhoCorasick

DEFAULT_LINKS = [
    "bit.ly/gcash-update",
    "https://bit.ly/actualbpisece",
    "https://bit.ly/actualbpiseceu",
    "https://tinyurl.com/actualbpisece",
    "https://bit.ly/4yGX271",
    "https://bit.ly/12Tst",
]

engine = EnhancedAhoCorasick.from_pattern_file(DEFAULT_PATTERN_FILE, url_trace=False)
for link in sys.argv[1:] or DEFAULT_LINKS:
    info = engine._analyze_url(link)
    destination = info.get("unmasked_url") or "(could not be resolved)"
    print(f"{link}\n    -> {destination}\n    classification: {info['segment']} ({info['multiplier']}x)"
          f"{', whitelisted' if info.get('is_whitelisted') else ''}")