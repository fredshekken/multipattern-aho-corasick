import re
from collections import deque
from pathlib import Path


class EnhancedAhoCorasick:
    """
    Main engine class combining standard Aho-Corasick with four algorithmic layers:
    1. Text Normalization & Bitap Fuzzy Matching (Objective 1)
    2. Inverse Distance Weighting (IDW) Context Proximity (Objective 2)
    3. Taglish Morphological Affix Stripping & Phonetic Map (Objective 3)
    4. Delimiter-Driven Structural URL Segmentation (Objective 4)
    Plus a fallback heuristic anomaly scorer for unseen zero-day messages.
    """

    def __init__(self, patterns, max_errors=1, anomaly_threshold=0.45,
                 exact_threshold=1.2, fuzzy_threshold=1.2, affix_threshold=1.05):
        """
        WHERE IT ENTERS THE ALGO:
        This is the constructor. It runs once when the engine starts.
        It saves all decision boundaries (thresholds), parses the dictionary,
        and sets up the trie and failure links.
        """
        # --- Parameter Values Explained ---
        # max_errors = 1: k limit for Bitap. We allow at most 1 typo/leetspeak deviation.
        # anomaly_threshold = 0.45: Cutoff for messages without dictionary hits (empirically calibrated).
        # exact_threshold = 1.2: Exact trie base score is 1.25. Needs 1.2 to trigger an alert.
        # fuzzy_threshold = 1.2: Base cutoff before subtracting error penalties for Bitap.
        # affix_threshold = 1.05: Lower cutoff because stripped roots carry a 0.15 uncertainty penalty.
        self.max_errors = max_errors
        self.anomaly_threshold = anomaly_threshold
        self.exact_threshold = exact_threshold
        self.fuzzy_threshold = fuzzy_threshold
        self.affix_threshold = affix_threshold

        # Parse and flatten the incoming dictionary into a single pattern list
        self.pattern_groups = self._normalize_pattern_groups(patterns)
        self.patterns = [
            pattern
            for group_patterns in self.pattern_groups.values()
            for pattern in group_patterns
        ]

        # =========================================================================
        # Objective 1: Character Normalization (Leetspeak Obfuscation)
        # SOP Solved: SOP 1 (Detecting obfuscated keywords that evade exact DFA matching)
        #
        # Relevant Terms:
        # Leetspeak - Replacing standard alphabetic letters with numbers or symbols
        #             (e.g., @ for a, 0 for o, 1 for i).
        # Normalization - Mapping visually deceptive characters back to standard
        #                 ASCII characters before trie traversal.
        #
        # Relevant References:
        # - Warki et al. (2025)
        # =========================================================================
        self.norm_map = {
            '@': 'a', '0': 'o', '1': 'i', '3': 'e', '$': 's', '4': 'a', '5': 's'
        }

        # =========================================================================
        # Objective 3: Taglish Phonetic Mapping & Morphological Affixes
        # SOP Solved: SOP 3 (Handling Philippine code-switched informal morphology)
        #
        # Relevant Terms:
        # Phonetic Variation - Dialectal or colloquial consonant swaps in Taglish text
        #                      (e.g., v -> b, f -> p, j -> g).
        # Derivational Affixes - Filipino prefixes/suffixes attached to loanwords
        #                        (e.g., "i-verify", "na-block", "mag-login").
        # Shadowing - When a shorter affix wrongly eats part of a word before a
        #             longer affix gets tested. Prevented by sorting longest-first.
        #
        # Relevant References:
        # - Schachter & Otanes (1972), Tagalog Reference Grammar
        # =========================================================================
        self.phonetic_map = {
            'v': 'b',   # "vlocked" -> "blocked"
            'f': 'p',   # "pake" -> "fake"
            'j': 'g',   # "jcash" -> "gcash"
        }

        # Prefixes sorted longest-first to prevent short prefixes from shadowing long ones
        self.prefixes = sorted(
            ['magpa', 'nakaka', 'pinaka', 'nag', 'mag', 'pag',
             'na', 'ma', 'pa', 'i', 'ka', 'in'],
            key=len, reverse=True
        )
        # Suffixes evaluated against the trie to avoid over-truncating root stems
        self.suffixes = sorted(['-in', '-an', '-han', '-hin'], key=len, reverse=True)

        # Build the core Aho-Corasick deterministic finite automaton (DFA)
        self.goto = [{}]
        self.fail = [0]
        self.out = [0]
        self.states_count = 1
        self._build_enhanced_machine()

        # Cache normalized pattern representations so Bitap doesn't re-normalize them every scan
        self.norm_patterns = [self._normalize(p) for p in self.patterns]

        # =========================================================================
        # Objective 2: Proximity-Based Context Weighting (Inverse Distance Weighting)
        # SOP Solved: SOP 2 (Context-free false positive reduction in natural dialogue)
        #
        # Relevant Terms:
        # Booster - Urgent or threatening terms that increase the phishing score
        #           when found near a keyword.
        # Neutralizer - Legitimate service or help-desk terms that decrease the score
        #               to suppress false alarms in casual or official messages.
        # Window - The character radius (+/- 50 chars) inspected around each match.
        #
        # Relevant References:
        # - Blancaflor et al. (2024)
        # =========================================================================
        self.boosters = [
            # English
            "urgent", "click", "verify", "blocked", "login", "confirm",
            "suspend", "limited", "action", "immediately", "warning", "alert",
            # Taglish
            "i-verify", "i-click", "na-block", "kumpirmahin", "agad",
            "panganib", "mag-login", "ibigay", "ipadala", "ipasok"
        ]
        self.neutralizers = [
            # English
            "official", "help", "customer", "support", "hotline",
            "representative", "authorized", "service", "policy",
            # Taglish
            "opisyal", "tulong", "serbisyo", "awtorisado", "lehitimo"
        ]

        # Dictionary-independent terms used strictly by Layer 5 (Fallback Anomaly Scorer)
        self.anomaly_urgency_terms = {
            "urgent", "asap", "immediately", "deadline",
            "last chance", "act now", "expire", "expiring"
        }
        self.anomaly_action_terms = {
            "click", "tap", "verify", "confirm", "login", "sign in", "reset"
        }
        self.anomaly_sensitive_terms = {
            "password", "pin", "otp", "security code", "wallet",
            "bank account", "payment details", "transfer funds",
            "credentials", "credit card", "gift card"
        }
        self.anomaly_benign_terms = {
            "official", "help", "customer", "support", "hotline",
            "representative", "authorized", "service", "policy",
            "newsletter", "receipt", "invoice", "schedule", "meeting"
        }

        # Internal regression suite to verify accuracy during development
        self.validation_positive_samples = [
            "Urgent: verify your account now.",
            "Please click here to confirm your password reset.",
            "Your G-C@sh account is blocked, update payment details immediately.",
            "Claim your prize now and send the code to restore access."
        ]
        self.validation_negative_samples = [
            "Team meeting moved to 3 PM tomorrow.",
            "Here is the project status update and weekly schedule.",
            "Official customer support hotline and service hours.",
            "Please review the receipt and invoice for the office order."
        ]

    # -------------------------------------------------------------------------
    # DICTIONARY UTILITIES (File Loading, Grouping, and Maintenance)
    # -------------------------------------------------------------------------

    @staticmethod
    def parse_pattern_groups(pattern_text):
        """
        WHERE IT ENTERS:
        Called when reading default_patterns.txt.
        Parses text headers like [category: brand_terms] into a clean Python dictionary.
        """
        groups = {}
        current_group = "general"

        for raw_line in pattern_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            lowered = line.lower()
            if lowered.startswith("# category:"):
                current_group = line.split(":", 1)[1].strip() or "general"
                groups.setdefault(current_group, [])
                continue

            if line.startswith("[") and line.endswith("]"):
                header = line[1:-1].strip()
                if header.lower().startswith("category:"):
                    current_group = header.split(":", 1)[1].strip() or "general"
                else:
                    current_group = header or "general"
                groups.setdefault(current_group, [])
                continue

            if line.startswith("#"):
                continue

            groups.setdefault(current_group, []).append(line)

        return groups

    @staticmethod
    def format_pattern_groups(pattern_groups):
        """
        WHERE IT ENTERS:
        Called when persisting patterns back to a .txt file on disk.
        Converts the python dictionary back into formatted text sections.
        """
        lines = ["# Categorized phishing ruleset", "# One pattern per line within each category", ""]
        for category, patterns in pattern_groups.items():
            lines.append(f"[category: {category}]")
            lines.extend(patterns)
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    @classmethod
    def from_pattern_file(cls, pattern_file, max_errors=1, anomaly_threshold=0.45,
                           exact_threshold=1.2, fuzzy_threshold=1.2, affix_threshold=1.05):
        """
        WHERE IT ENTERS:
        Alternative factory constructor used by server.py to instantiate the engine
        directly from the path of default_patterns.txt.
        """
        file_path = Path(pattern_file)
        if file_path.exists():
            pattern_text = file_path.read_text(encoding="utf-8")
            patterns = cls.parse_pattern_groups(pattern_text)
        else:
            patterns = {}

        return cls(patterns, max_errors=max_errors, anomaly_threshold=anomaly_threshold,
                   exact_threshold=exact_threshold, fuzzy_threshold=fuzzy_threshold,
                   affix_threshold=affix_threshold)

    def _normalize_pattern_groups(self, patterns):
        """Deduplicates and cleans keyword strings across pattern categories."""
        if isinstance(patterns, dict):
            groups = {}
            for category, items in patterns.items():
                cleaned = []
                seen = set()
                for pattern in items:
                    candidate = str(pattern).strip()
                    if not candidate or candidate.startswith("#"):
                        continue
                    key = candidate.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    cleaned.append(candidate)
                groups[str(category).strip() or "general"] = cleaned
            return groups

        return {"general": [str(pattern).strip() for pattern in patterns if str(pattern).strip()]}

    def _reset_automaton(self):
        """Wipes trie states, failure pointers, and pattern output tables."""
        self.goto = [{}]
        self.fail = [0]
        self.out = [0]
        self.states_count = 1

    def _rebuild_from_patterns(self):
        """Re-runs trie construction and failure BFS whenever rules change."""
        self._reset_automaton()
        self._build_enhanced_machine()
        self.norm_patterns = [self._normalize(p) for p in self.patterns]

    def set_patterns(self, patterns):
        """Replaces pattern list and rebuilds the automaton graph."""
        self.pattern_groups = self._normalize_pattern_groups(patterns)
        self.patterns = [
            pattern
            for group_patterns in self.pattern_groups.values()
            for pattern in group_patterns
        ]
        self._rebuild_from_patterns()

    def set_pattern_groups(self, pattern_groups):
        """Replaces pattern categories and triggers automaton reconstruction."""
        self.set_patterns(pattern_groups)

    def add_patterns(self, patterns, category="general"):
        """Appends new patterns dynamically and refreshes the automaton."""
        updated_groups = {group: list(items) for group, items in self.pattern_groups.items()}
        target_group = str(category).strip() or "general"
        updated_groups.setdefault(target_group, [])

        existing = {pattern.lower() for pattern in self.patterns}
        for pattern in patterns:
            candidate = str(pattern).strip()
            if not candidate:
                continue
            lowered = candidate.lower()
            if lowered in existing:
                continue
            existing.add(lowered)
            updated_groups[target_group].append(candidate)

        self.set_pattern_groups(updated_groups)

    def save_patterns(self, pattern_file):
        """Writes current rule groups to default_patterns.txt."""
        file_path = Path(pattern_file)
        file_path.write_text(self.format_pattern_groups(self.pattern_groups), encoding="utf-8")

    # -------------------------------------------------------------------------
    # PRE-PROCESSING & AUTOMATON SETUP (Objectives 1 & 3)
    # -------------------------------------------------------------------------

    def _normalize(self, text):
        """
        WHERE IT ENTERS:
        Every piece of text runs through here before entering any trie or Bitap check.
        It strips visual leetspeak and normalizes Filipino sound substitutions.
        """
        text = text.lower()
        # Step 1: Leetspeak symbol substitution (Objective 1)
        for char, norm in self.norm_map.items():
            text = text.replace(char, norm)
        # Step 2: Phonetic normalization for Taglish (Objective 3)
        for char, norm in self.phonetic_map.items():
            text = text.replace(char, norm)
        return text

    def _build_enhanced_machine(self):
        """
        WHERE IT ENTERS:
        Runs at engine startup.
        Converts the list of keywords into a stateful Aho-Corasick trie graph with failure links.
        """
        # Step 1: Normalized Trie Construction
        # Builds paths in memory for every character of every keyword
        for i, pattern in enumerate(self.patterns):
            curr = 0
            norm_pattern = self._normalize(pattern)
            for char in norm_pattern:
                if char not in self.goto[curr]:
                    self.goto[curr][char] = self.states_count
                    self.goto.append({})
                    self.fail.append(0)
                    self.out.append(0)
                    self.states_count += 1
                curr = self.goto[curr][char]
            # Bitwise flag marking that pattern i ends at state curr
            self.out[curr] |= (1 << i)

        # Step 2: Breadth-First Search (BFS) Failure Links
        # Allows fallback to matching suffixes in O(1) without restarting the scan
        queue = deque()
        for char, next_state in self.goto[0].items():
            queue.append(next_state)

        while queue:
            r = queue.popleft()
            for char, s in self.goto[r].items():
                f = self.fail[r]
                while char not in self.goto[f] and f != 0:
                    f = self.fail[f]
                self.fail[s] = self.goto[f].get(char, 0)
                # Inherit matched patterns from fallback state
                self.out[s] |= self.out[self.fail[s]]
                queue.append(s)

    # -------------------------------------------------------------------------
    # Objective 1: Bitap (Shift-Or) Fuzzy Matching & Boundary Guard
    # SOP Solved: SOP 1 (Detecting fuzzy obfuscations bypassing exact DFA)
    #
    # Relevant Terms:
    # Bit-Parallelism - Using CPU bitwise operations (AND, OR, shift) to simulate
    #                   nondeterministic finite automaton (NFA) state sets in parallel.
    # Hamming Distance (k) - Number of character substitutions allowed between
    #                        pattern and input.
    # Word Boundary - Ensuring a match isn't an accidental substring inside an
    #                 unrelated word (e.g., prevents "otp" from matching inside "https").
    #
    # Relevant References:
    # - Baeza-Yates & Gonnet (1992), Communications of the ACM
    # -------------------------------------------------------------------------

    def _bitap_search(self, text, pattern, k):
        """
        WHERE IT ENTERS:
        Executes in Layer 2 of enhanced_search.
        Searches text for a pattern allowing up to k substitutions using bitwise masks.
        """
        m = len(pattern)
        # Limit to 63 chars so masks fit within 64-bit integer registers
        if m == 0 or m > 63:
            return []

        # Build character bitmask: 0 bit indicates character match, 1 indicates mismatch
        char_mask = {}
        for i, c in enumerate(pattern):
            if c not in char_mask:
                char_mask[c] = ~0  # All 1s = no character matches yet
            char_mask[c] &= ~(1 << i)  # Clear bit i: character matches at position i

        # Initialize state bitmasks for each error count (0 to k)
        D = [~0] * (k + 1)
        matches = []

        # Iterate through every character in the incoming message
        for j, c in enumerate(text):
            cm = char_mask.get(c, ~0)
            prev_D = D[:]

            # Exact match level (e = 0)
            D[0] = ((prev_D[0] << 1) | cm) & ((1 << m) - 1)

            # Fuzzy match levels (e = 1 to k)
            for e in range(1, k + 1):
                substitution = (prev_D[e - 1] << 1)
                shift        = ((prev_D[e] << 1) | cm)
                D[e] = (substitution & shift) & ((1 << m) - 1)

            # If the (m-1)th bit is 0, the full pattern matched at position j
            for e in range(k + 1):
                if not (D[e] & (1 << (m - 1))):
                    matches.append((j, e))
                    break  # Keep lowest error count found at this character

        return matches

    @staticmethod
    def _is_word_bounded(text, start_idx, end_idx):
        """
        WHERE IT ENTERS:
        Filters matches in Layer 1 and Layer 2.
        Verifies that a detected keyword is bounded by non-word characters (\\W)
        or edges, avoiding false positives on unrelated words.
        """
        left_ok = start_idx == 0 or not re.match(r'\w', text[start_idx - 1])
        right_ok = end_idx == len(text) - 1 or not re.match(r'\w', text[end_idx + 1])
        return left_ok and right_ok

    # -------------------------------------------------------------------------
    # Objective 2: Context-Aware Proximity Scoring (IDW)
    # SOP Solved: SOP 2 (Context-free matching producing false positives)
    #
    # Relevant Terms:
    # Inverse Distance Weighting (IDW) - Weighting formula: weight = 1 / (distance + 1).
    #                                    Terms closer to the keyword influence score more.
    # Proximity Delta - Final clamped adjustment score between -1.0 and +1.0.
    #
    # Relevant References:
    # - Shepard (1968), 23rd ACM National Conference
    # -------------------------------------------------------------------------

    def _proximity_score(self, text, match_index, window=50):
        """
        WHERE IT ENTERS:
        Called by all three pattern-matching layers (Exact, Fuzzy, Affix).
        Scans +/- 50 characters around the detected keyword to calculate risk adjustments.
        """
        context = text[max(0, match_index - window):min(len(text), match_index + window)].lower()
        context_start = max(0, match_index - window)

        proximity_delta = 0.0

        # Add weight for booster terms (closer terms add more risk)
        for term in self.boosters:
            pos = context.find(term)
            while pos != -1:
                abs_pos = context_start + pos
                distance = abs(abs_pos - match_index)
                proximity_delta += 1 / (distance + 1)
                pos = context.find(term, pos + 1)

        # Subtract weight for neutralizer terms (closer terms subtract more risk)
        for term in self.neutralizers:
            pos = context.find(term)
            while pos != -1:
                abs_pos = context_start + pos
                distance = abs(abs_pos - match_index)
                proximity_delta -= 1 / (distance + 1)
                pos = context.find(term, pos + 1)

        # Clamp between -1.0 and +1.0 so repetitive words don't overpower the score
        return max(-1.0, min(1.0, proximity_delta))

    # -------------------------------------------------------------------------
    # Objective 3: Tagalog Morphological Affix Stripping
    # SOP Solved: SOP 3 (Taglish informal morphology evading dictionary lookup)
    #
    # Relevant Terms:
    # Stemming / Root Extraction - Removing verbal prefixes/suffixes to reveal the
    #                              core root keyword (e.g., "i-verify" -> "verify").
    # Trie Validation - Checking candidate roots against the trie to ensure we don't
    #                   over-truncate valid words.
    #
    # Relevant References:
    # - Schachter & Otanes (1972), Tagalog Reference Grammar
    # -------------------------------------------------------------------------

    def _strip_affixes(self, word):
        """
        WHERE IT ENTERS:
        Used by Layer 3 (_affix_search).
        Tries removing Tagalog prefixes and suffixes to find an underlying keyword.
        """
        word = word.lower().replace('-', '')  # Normalize hyphens (e.g., "i-gcash" -> "igcash")

        # Step 1: Strip prefixes using longest-match first
        root = word
        for prefix in self.prefixes:
            if word.startswith(prefix) and len(word) > len(prefix) + 2:
                root = word[len(prefix):]
                break

        # Step 2: Strip suffixes and test candidate roots against the trie
        candidates = []
        for suffix in self.suffixes:
            clean_suffix = suffix.lstrip('-')
            if root.endswith(clean_suffix) and len(root) - len(clean_suffix) >= 4:
                candidates.append(root[:-len(clean_suffix)])

        if candidates:
            # Pick the candidate root recognized by the trie
            for candidate in candidates:
                if self._trie_recognizes(candidate):
                    return candidate
            root = candidates[0]  # Fallback to longest stripped suffix

        return root

    def _trie_recognizes(self, word):
        """
        WHERE IT ENTERS:
        Helper for _strip_affixes.
        Follows transitions in the trie to check if a word is an active keyword.
        """
        curr = 0
        for char in self._normalize(word):
            curr = self.goto[curr].get(char, 0)
            if curr == 0 and char not in self.goto[0]:
                return False
        return self.out[curr] > 0

    def _affix_search(self, text, original_text):
        """
        WHERE IT ENTERS:
        Executes as Layer 3 of enhanced_search.
        Splits text into words, strips affixes from each, and checks if roots match patterns.
        """
        matches = []
        tokens = re.finditer(r'[\w](?:[\w\-]*[\w])?', text)

        for token_match in tokens:
            token = token_match.group()
            word_pos = token_match.start()

            stripped = self._strip_affixes(token)
            # Skip if no affixes were stripped (Layer 1 and Layer 2 already handle un-affixed words)
            if stripped == token.lower().replace('-', ''):
                continue

            norm_root = self._normalize(stripped)

            # Traverse trie using the stripped root
            curr = 0
            for char in norm_root:
                curr = self.goto[curr].get(char, 0)
                if curr == 0 and char not in self.goto[0]:
                    break
            else:
                if self.out[curr] > 0:
                    for j in range(len(self.patterns)):
                        if self.out[curr] & (1 << j):
                            matches.append((j, token, stripped, word_pos))

        return matches

    # -------------------------------------------------------------------------
    # FALLBACK LAYER: Heuristic Anomaly Detection
    # SOP Solved: Catches zero-day threats containing no known dictionary keywords.
    # -------------------------------------------------------------------------

    def _anomaly_score(self, text):
        """
        WHERE IT ENTERS:
        Executes in Layer 4 of enhanced_search ONLY IF Layers 1-3 found zero keyword hits.
        Aggregates threat signals based on language patterns, links, and digits.
        """
        normalized = self._normalize(text)
        lowered = text.lower()
        signals = []
        score = 0.0

        def bump(amount, label):
            nonlocal score
            score = min(1.0, score + amount)
            signals.append(label)

        # Urgency language: +0.22 (e.g., "act now", "immediately")
        if any(term in normalized for term in self.anomaly_urgency_terms):
            bump(0.22, "urgency language")

        # Action requests: +0.20 (e.g., "click", "login")
        if any(term in normalized for term in self.anomaly_action_terms):
            bump(0.20, "action request")

        # Credential or financial terms: +0.28 (e.g., "otp", "password")
        if any(term in normalized for term in self.anomaly_sensitive_terms):
            bump(0.28, "credential or payment language")

        # Benign administrative terms: -0.18 (e.g., "support", "meeting")
        if any(term in normalized for term in self.anomaly_benign_terms):
            score = max(0.0, score - 0.18)
            signals.append("benign context")

        # Embedded link presence: +0.18
        url_like = re.search(r'(?i)\b(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?', normalized)
        if url_like:
            bump(0.18, "URL-like text")

        # Obfuscated tokens with mixed characters/numbers: +0.12
        obfuscated_tokens = re.findall(r'\b[a-z]+[0-9@$]+[a-z]+\b', lowered)
        if obfuscated_tokens:
            bump(0.12, "obfuscated spelling")

        # Heavy digit density (>= 8% numbers): +0.08
        digit_ratio = sum(char.isdigit() for char in text) / max(len(text), 1)
        if digit_ratio >= 0.08:
            bump(0.08, "digit-heavy content")

        return round(score, 3), signals[:4]

    def run_validation_suite(self, anomaly_threshold=None):
        """Runs a regression test on positive and negative samples to ensure stability."""
        if anomaly_threshold is None:
            anomaly_threshold = self.anomaly_threshold

        cases = []

        for sample in self.validation_positive_samples:
            detections = self.enhanced_search(sample, anomaly_threshold=anomaly_threshold)
            cases.append({
                "sample": sample,
                "expected": "positive",
                "detected": bool(detections),
                "max_risk": max((item["risk_score"] for item in detections), default=0.0),
            })

        for sample in self.validation_negative_samples:
            detections = self.enhanced_search(sample, anomaly_threshold=anomaly_threshold)
            cases.append({
                "sample": sample,
                "expected": "negative",
                "detected": bool(detections),
                "max_risk": max((item["risk_score"] for item in detections), default=0.0),
            })

        true_positive = sum(1 for case in cases if case["expected"] == "positive" and case["detected"])
        false_negative = sum(1 for case in cases if case["expected"] == "positive" and not case["detected"])
        true_negative = sum(1 for case in cases if case["expected"] == "negative" and not case["detected"])
        false_positive = sum(1 for case in cases if case["expected"] == "negative" and case["detected"])

        return {
            "cases": cases,
            "summary": {
                "true_positive": true_positive,
                "false_negative": false_negative,
                "true_negative": true_negative,
                "false_positive": false_positive,
            }
        }

    # =========================================================================
    # Objective 4: Delimiter-Driven Structural URL Segmentation
    # SOP Solved: SOP 4 (Distinguishing brand spoofing from authentic domain paths)
    #
    # Relevant Terms:
    # URL Segmentation - Breaking a URL into subdomains, SLD, TLD, path, and query
    #                    using standard delimiters (://, ., /, ?).
    # Second-Level Domain (SLD) - The actual registered domain (e.g., "gcash" in gcash.com).
    # Spoofing Subdomain - Deceptive prefix added by attackers (e.g., "gcash.scam-domain.com").
    # URL Shortener - Redirection service hiding the destination (e.g., bit.ly).
    #
    # Relevant References:
    # - Zhang et al. (2007) CANTINA
    # - Garera et al. (2007)
    # =========================================================================

    # Known shorteners that receive highest risk weighting
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
        'rb.gy', 'cutt.ly', 'shorturl.at', 'is.gd', 'buff.ly'
    }

    # Segment multipliers based on where a brand keyword appears
    SEGMENT_RISK = {
        'shortener': 2.5,   # Shorteners mask destinations: 2.5x multiplier
        'subdomain':  2.0,  # Brand in subdomain indicates spoofing: 2.0x multiplier
        'path':       1.5,  # Brand in path/folder: 1.5x multiplier
        'query':      1.5,  # Brand in query parameter: 1.5x multiplier
        'sld':        1.0,  # Brand in registered domain (likely legitimate): 1.0x (no escalation)
        'none':       1.0,  # Match is regular text outside any URL: 1.0x
    }

    def _segment_url(self, url):
        """
        WHERE IT ENTERS:
        Used by _analyze_url.
        Splits a raw URL string into structural pieces using standard delimiters.
        """
        # Step 1: Strip protocol (http:// or https://)
        scheme_match = re.match(r'https?://', url, re.IGNORECASE)
        rest = url[scheme_match.end():] if scheme_match else url

        # Step 2: Extract query parameters (?) and path (/)
        path = ''
        query = ''
        if '?' in rest:
            rest, query = rest.split('?', 1)
        if '/' in rest:
            rest, path = rest.split('/', 1)

        # Step 3: Split hostname on delimiter '.'
        host_parts = rest.split('.')

        # Extract SLD, TLD, and any preceding subdomains
        if len(host_parts) >= 2:
            tld = host_parts[-1]
            sld = host_parts[-2]
            subdomains = host_parts[:-2]
        else:
            tld = host_parts[0] if host_parts else ''
            sld = ''
            subdomains = []

        return {
            'subdomains': subdomains,
            'sld':        sld,
            'tld':        tld,
            'path':       path,
            'query':      query,
        }

    def _analyze_url(self, text, index):
        """
        WHERE IT ENTERS:
        Called at the start of enhanced_search.
        Locates any URLs in the message, segments them, and calculates the risk multiplier.
        """
        normalized_text = self._normalize(text)
        url_pattern = r'(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?'
        norm_patterns = self.norm_patterns

        for m in re.finditer(url_pattern, normalized_text, re.IGNORECASE):
            url = m.group()
            segments = self._segment_url(url)

            # Check if domain matches known URL shortener list
            full_host = '.'.join(
                segments['subdomains'] + [segments['sld'], segments['tld']]
            ).lower()
            if any(s in full_host for s in self.URL_SHORTENERS):
                return {"multiplier": self.SEGMENT_RISK['shortener'], "segment": "shortener"}

            # Check where pattern keywords fall inside URL components
            for norm_p in norm_patterns:
                # Subdomain: Brand spoofing attempt
                if any(norm_p in self._normalize(sub) for sub in segments['subdomains']):
                    return {"multiplier": self.SEGMENT_RISK['subdomain'], "segment": "subdomain"}

                # Path or Query: Moderate risk
                if norm_p in self._normalize(segments['path']):
                    return {"multiplier": self.SEGMENT_RISK['path'], "segment": "path"}
                if norm_p in self._normalize(segments['query']):
                    return {"multiplier": self.SEGMENT_RISK['query'], "segment": "query"}

                # SLD: Brand owns the domain
                if norm_p in self._normalize(segments['sld']):
                    return {"multiplier": self.SEGMENT_RISK['sld'], "segment": "sld"}

        return {"multiplier": self.SEGMENT_RISK['none'], "segment": "none"}

    # -------------------------------------------------------------------------
    # MASTER SCAN FUNCTION: Coordinates All Detection Layers
    # -------------------------------------------------------------------------

    def enhanced_search(self, text, anomaly_threshold=None):
        """
        WHERE IT ENTERS:
        The main scanning entrypoint. Called by server.py and calibrate_thresholds.py.
        Runs incoming text across Layers 1-4, calculates unified risk scores,
        and falls back to Layer 5 if no patterns match.
        """
        clean_text = self._normalize(text)
        results = []
        reported = set()  # Tracks (pattern_index, position) to avoid duplicate alerts

        if anomaly_threshold is None:
            anomaly_threshold = self.anomaly_threshold

        # Precompute URL multiplier once for the entire message (Objective 4)
        url_info = self._analyze_url(text, 0)
        url_risk = url_info["multiplier"]

        # ---------------------------------------------------------------------
        # Layer 1: Aho-Corasick Exact Trie Match (Post-Normalization)
        # ---------------------------------------------------------------------
        curr = 0
        for i, char in enumerate(clean_text):
            curr = self.goto[curr].get(char, 0)
            if self.out[curr] > 0:
                for j in range(len(self.patterns)):
                    if self.out[curr] & (1 << j):
                        key = (j, i)
                        if key in reported:
                            continue
                        reported.add(key)

                        pattern = self.patterns[j]
                        start_idx = i - len(pattern) + 1

                        # Word boundary guard: Reject matches inside unrelated tokens
                        if not self._is_word_bounded(clean_text, start_idx, i):
                            continue

                        context_window = text[max(0, i - 20):min(len(text), i + 20)].lower()

                        # Scoring formula: Base(1.25) + IDW Proximity Delta * URL Multiplier
                        score = 1.25
                        fuzzy_penalty = 0.0
                        proximity_delta = self._proximity_score(text, i)
                        score += proximity_delta

                        final_risk = (score - fuzzy_penalty) * url_risk

                        if final_risk >= self.exact_threshold:
                            results.append({
                                "alert": f"CRITICAL: '{pattern}' detected!",
                                "risk_score": round(final_risk, 3),
                                "match_type": "exact",
                                "error_count": 0,
                                "context": context_window.strip(),
                                "score_breakdown": {
                                    "match_layer": "exact token (Aho-Corasick)",
                                    "token_score": 1.25,
                                    "pattern": pattern,
                                    "matched_text": clean_text[start_idx:i + 1],
                                    "proximity_delta": round(proximity_delta, 3),
                                    "url_multiplier": url_risk,
                                    "url_segment": url_info["segment"],
                                    "penalty": 0.0,
                                    "final_risk": round(final_risk, 3),
                                },
                            })

        # ---------------------------------------------------------------------
        # Layer 2: Bitap Fuzzy Search (Residual Leetspeak / Typos)
        # ---------------------------------------------------------------------
        for j, (pattern, norm_pattern) in enumerate(zip(self.patterns, self.norm_patterns)):
            bitap_matches = self._bitap_search(clean_text, norm_pattern, self.max_errors)
            for (end_idx, error_count) in bitap_matches:
                if error_count == 0:
                    continue  # Already caught by Layer 1 exact trie match

                start_idx = end_idx - len(norm_pattern) + 1
                if not self._is_word_bounded(clean_text, start_idx, end_idx):
                    continue

                key = (j, end_idx)
                if key in reported:
                    continue
                reported.add(key)

                i = end_idx
                context_window = text[max(0, i - 20):min(len(text), i + 20)].lower()

                # Scoring: Base(1.0) - Error Penalty (0.10 * errors) + Proximity Delta
                score = 1.0
                fuzzy_penalty = error_count * 0.1
                proximity_delta = self._proximity_score(text, i)
                score += proximity_delta

                final_risk = (score - fuzzy_penalty) * url_risk

                # Lower threshold for fuzzy errors
                current_fuzzy_threshold = self.fuzzy_threshold - (error_count * 0.15)
                if final_risk >= current_fuzzy_threshold:
                    results.append({
                        "alert": f"CRITICAL: '{pattern}' detected! (fuzzy match, {error_count} error(s))",
                        "risk_score": round(final_risk, 3),
                        "match_type": "fuzzy",
                        "error_count": error_count,
                        "context": context_window.strip(),
                        "score_breakdown": {
                            "match_layer": "fuzzy token (Bitap)",
                            "token_score": 1.0,
                            "pattern": pattern,
                            "matched_text": clean_text[start_idx:end_idx + 1],
                            "proximity_delta": round(proximity_delta, 3),
                            "url_multiplier": url_risk,
                            "url_segment": url_info["segment"],
                            "penalty": round(fuzzy_penalty, 3),
                            "final_risk": round(final_risk, 3),
                        },
                    })

        # ---------------------------------------------------------------------
        # Layer 3: Affix-Aware Morphological Search (Taglish Affix Stripping)
        # ---------------------------------------------------------------------
        affix_matches = self._affix_search(clean_text, text)
        for (j, token, stripped_root, word_pos) in affix_matches:
            key = (j, word_pos)
            if key in reported:
                continue
            reported.add(key)

            pattern = self.patterns[j]
            context_window = text[max(0, word_pos - 20):min(len(text), word_pos + 20)].lower()

            # Scoring: Base(1.0) - Affix Uncertainty Penalty (0.15) + Proximity Delta
            score = 1.0
            affix_penalty = 0.15
            proximity_delta = self._proximity_score(text, word_pos)
            score += proximity_delta

            final_risk = (score - affix_penalty) * url_risk

            if final_risk >= self.affix_threshold:
                results.append({
                    "alert": f"CRITICAL: '{pattern}' detected! (affix match: '{token}' -> root '{stripped_root}')",
                    "risk_score": round(final_risk, 3),
                    "match_type": "affix",
                    "error_count": 0,
                    "context": context_window.strip(),
                    "score_breakdown": {
                        "match_layer": "affix token",
                        "token_score": 1.0,
                        "pattern": pattern,
                        "matched_text": token,
                        "root": stripped_root,
                        "proximity_delta": round(proximity_delta, 3),
                        "url_multiplier": url_risk,
                        "url_segment": url_info["segment"],
                        "penalty": affix_penalty,
                        "final_risk": round(final_risk, 3),
                    },
                })

        # ---------------------------------------------------------------------
        # Layer 4: Fallback Heuristic Anomaly Layer (Zero-Day Detection)
        # ---------------------------------------------------------------------
        # Triggers only if Layers 1, 2, and 3 find zero matching keywords
        if not results:
            anomaly_score, anomaly_signals = self._anomaly_score(text)
            if anomaly_score >= anomaly_threshold:
                context_window = text[:120].lower().strip()
                results.append({
                    "alert": "SUSPICIOUS: no known pattern matched, but the message contains phishing-like signals.",
                    "risk_score": round(0.95 + (anomaly_score * 0.4), 3),
                    "match_type": "anomaly",
                    "error_count": 0,
                    "context": context_window,
                    "signals": anomaly_signals,
                    "score_breakdown": {
                        "match_layer": "anomaly heuristic",
                        "token_score": 0.0,
                        "pattern": "ANOMALY_HEURISTIC",
                        "matched_text": ", ".join(anomaly_signals),
                        "proximity_delta": 0.0,
                        "url_multiplier": 1.0,
                        "url_segment": "none",
                        "penalty": 0.0,
                        "anomaly_score": anomaly_score,
                        "final_risk": round(0.95 + (anomaly_score * 0.4), 3),
                    },
                })

        return results

    # -------------------------------------------------------------------------
    # DECISION TIERING & SEVERITY THRESHOLDS
    # Maps computed risk scores to system response tiers (informational, warning, block).
    # -------------------------------------------------------------------------
    LOW_MODERATE_CUTOFF = 1.142   # Empirically derived floor for moderate threat alerts
    MODERATE_HIGH_CUTOFF = 1.5    # Requires corroborating context or risky URL placement
    HIGH_CRITICAL_CUTOFF = 2.5    # Hard block: Brand spoofing in URL or strong threat clustering

    def assess_message(self, text):
        """
        WHERE IT ENTERS:
        Called by the Viber bot hook and the Live Simulation UI endpoint.
        Converts list of risk detections into a final action tier (Tier 0 to Tier 3).
        """
        detections = self.enhanced_search(text)
        max_risk = max((item["risk_score"] for item in detections), default=0.0)

        # Tier 0: No threat detected
        if not detections:
            severity, action_tier = "none", 0
        # Tier 3: Critical risk (hard warning / block)
        elif max_risk >= self.HIGH_CRITICAL_CUTOFF:
            severity, action_tier = "critical", 3
        # Tier 3: High risk
        elif max_risk >= self.MODERATE_HIGH_CUTOFF:
            severity, action_tier = "high", 3
        # Tier 2: Moderate risk (advisory banner)
        elif max_risk >= self.LOW_MODERATE_CUTOFF:
            severity, action_tier = "moderate", 2
        # Tier 1: Low risk (isolated term, informational only)
        else:
            severity, action_tier = "low", 1

        return {
            "detections": detections,
            "severity": severity,
            "action_tier": action_tier,
            "is_clean": not detections,
        }