"""
Baseline adapter — wraps the user's OWN `ahocorasick.py` (class
AhoCorasickDFA), unmodified, so the "before" side of every comparison in
this project is the literal code already in the repository's
`original_aho/ahocorasick.py` — the same class that generated Figures
1.1-1.8 and Tables 1.1-1.3 in Chapter 1 — not a separate reimplementation.

This file adds only two things ON TOP of AhoCorasickDFA, neither of which
touches its internals:
  1. `from_pattern_file()` — reads the same categorized pattern-file format
     the enhanced engine uses, so both engines can be built from one shared
     dictionary source (see default_patterns.txt).
  2. `assess_message()` — a thin interface-compatibility wrapper so
     server.py / compare_engines.py can call either engine the same way.
     It does not add scoring, tiers, or any detection behavior — it just
     reshapes AhoCorasickDFA.search()'s existing output.
"""

from pathlib import Path

import _bootstrap  # noqa: F401 — sets up sys.path for enhanced_aho/ and original_aho/
from ahocorasick import AhoCorasickDFA


class BaselineAhoCorasick(AhoCorasickDFA):
    @classmethod
    def from_pattern_file(cls, pattern_file):
        """Reads the categorized pattern file format (same as the enhanced
        engine) and builds the UNMODIFIED AhoCorasickDFA from it."""
        file_path = Path(pattern_file)
        patterns = []
        if file_path.exists():
            for line in file_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("["):
                    continue
                patterns.append(line)
        return cls(patterns)

    def assess_message(self, text):
        """
        Interface-compatible wrapper only — no detection logic added here.
        AhoCorasickDFA has no concept of severity or action tiers (that is
        precisely what this thesis's Objective 2 adds), so every match is
        surfaced identically, mapped to a flat Tier 2 so the Viber bot has
        *something* uniform to do with it. This is a deployment-layer
        convenience, not a claim that the baseline algorithm has tiers.
        """
        matches = self.search(text)
        for m in matches:
            m["alert"] = f"ALERT: Found '{m['pattern']}' at index {m['start_index']}-{m['end_index']}"
        return {
            "detections": matches,
            "action_tier": 2 if matches else 0,
            "is_clean": len(matches) == 0,
        }
