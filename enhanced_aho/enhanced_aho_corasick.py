import re
from collections import deque
from pathlib import Path


class EnhancedAhoCorasick:
    def __init__(self, patterns, max_errors=1, anomaly_threshold=0.45,
                 exact_threshold=1.2, fuzzy_threshold=1.2, affix_threshold=1.05):
        self.max_errors = max_errors  # k for Bitap fuzzy threshold
        self.anomaly_threshold = anomaly_threshold
        self.exact_threshold = exact_threshold
        self.fuzzy_threshold = fuzzy_threshold
        self.affix_threshold = affix_threshold

        self.pattern_groups = self._normalize_pattern_groups(patterns)
        self.patterns = [
            pattern
            for group_patterns in self.pattern_groups.values()
            for pattern in group_patterns
        ]

        # SOP 1: Normalization Map for Obfuscation
        self.norm_map = {
            '@': 'a', '0': 'o', '1': 'i', '3': 'e', '$': 's', '4': 'a', '5': 's'
        }
        # O3: Expanded Phonetic Map for Taglish Nuances
        # Covers common Filipino informal spelling variants
        # Basis: Schachter & Otanes (1972), Tagalog Reference Grammar
        self.phonetic_map = {
            'v': 'b',   # "vlocked" -> "blocked"
            'f': 'p',   # "pake" -> "fake"
            'j': 'g',   # "jcash" -> "gcash" (j/g substitution, per Section 1.1)
        }

        # O3: Filipino derivational affixes for stripping
        # Ordered TRUE longest-first (sorted by character length descending) to
        # prevent a shorter affix from shadowing a longer one that shares the same
        # ending/start, e.g. checking 'in' before 'i' (word "inalis" must try the
        # 2-char "in-" prefix before the 1-char "i-" prefix), and checking 'han'/
        # 'hin' before 'an'/'in' (a word ending in "...han" must not be caught by
        # the shorter "-an" suffix first, which would leave a stray "h" on the root).
        # Basis: Schachter & Otanes (1972), Tagalog Reference Grammar
        self.prefixes = sorted(
            ['magpa', 'nakaka', 'pinaka', 'nag', 'mag', 'pag',
             'na', 'ma', 'pa', 'i', 'ka', 'in'],
            key=len, reverse=True
        )
        # Suffixes: 'clean_suffix = suffix.lstrip("-")' below means a hyphenated
        # entry and its bare counterpart (e.g. '-hin' and 'hin') collapse to the
        # identical string, so only the unique set is kept, sorted longest-first
        # for the same shadowing reason as above.
        self.suffixes = sorted(['-in', '-an', '-han', '-hin'], key=len, reverse=True)

        self.goto = [{}]
        self.fail = [0]
        self.out = [0]
        self.states_count = 1
        self._build_enhanced_machine()

        # Precompute normalized patterns for Bitap layer
        self.norm_patterns = [self._normalize(p) for p in self.patterns]

        # O2: Proximity-based weighting — expanded with Taglish risk terms
        # Boosters: terms that increase phishing likelihood when near a pattern
        self.boosters = [
            # English
            "urgent", "click", "verify", "blocked", "login", "confirm",
            "suspend", "limited", "action", "immediately", "warning", "alert",
            # Taglish
            "i-verify", "i-click", "na-block", "kumpirmahin", "agad",
            "panganib", "mag-login", "ibigay", "ipadala", "ipasok"
        ]
        # Neutralizers: terms that suggest legitimate/safe context
        self.neutralizers = [
            # English
            "official", "help", "customer", "support", "hotline",
            "representative", "authorized", "service", "policy",
            # Taglish
            "opisyal", "tulong", "serbisyo", "awtorisado", "lehitimo"
        ]

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

    @staticmethod
    def parse_pattern_groups(pattern_text):
        """Parse a categorized rule base from text into ordered pattern groups."""
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
        """Render grouped patterns back into a human-editable ruleset file."""
        lines = ["# Categorized phishing ruleset", "# One pattern per line within each category", ""]
        for category, patterns in pattern_groups.items():
            lines.append(f"[category: {category}]")
            lines.extend(patterns)
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    @classmethod
    def from_pattern_file(cls, pattern_file, max_errors=1, anomaly_threshold=0.45,
                           exact_threshold=1.2, fuzzy_threshold=1.2, affix_threshold=1.05):
        """Create a scanner from a categorized pattern file."""
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
        self.goto = [{}]
        self.fail = [0]
        self.out = [0]
        self.states_count = 1

    def _rebuild_from_patterns(self):
        self._reset_automaton()
        self._build_enhanced_machine()
        self.norm_patterns = [self._normalize(p) for p in self.patterns]

    def set_patterns(self, patterns):
        """Replace the current pattern dictionary and rebuild the automaton."""
        self.pattern_groups = self._normalize_pattern_groups(patterns)
        self.patterns = [
            pattern
            for group_patterns in self.pattern_groups.values()
            for pattern in group_patterns
        ]
        self._rebuild_from_patterns()

    def set_pattern_groups(self, pattern_groups):
        """Replace the grouped rule base and rebuild the automaton."""
        self.set_patterns(pattern_groups)

    def add_patterns(self, patterns, category="general"):
        """Add patterns to the current dictionary, avoiding duplicates."""
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
        """Persist the current pattern dictionary to a newline-delimited file."""
        file_path = Path(pattern_file)
        file_path.write_text(self.format_pattern_groups(self.pattern_groups), encoding="utf-8")

    def _normalize(self, text):
        """SOP 1 & 3: Normalizes text by mapping symbols and phonetic variants."""
        text = text.lower()
        for char, norm in self.norm_map.items():
            text = text.replace(char, norm)
        for char, norm in self.phonetic_map.items():
            text = text.replace(char, norm)
        return text

    def _build_enhanced_machine(self):
        # Step 1: Normalized Trie Construction
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
            self.out[curr] |= (1 << i)

        # Step 2: Resilient Failure Links (BFS)
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
                self.out[s] |= self.out[self.fail[s]]
                queue.append(s)

    def _bitap_search(self, text, pattern, k):
        """
        O1: Bit-parallel fuzzy matching using the Bitap (shift-or) algorithm.
        Detects pattern occurrences in text within Hamming distance k.

        Returns a list of (end_index, error_count) for each fuzzy match found.
        This feeds into the transition scoring layer, not as a standalone detector.
        """
        m = len(pattern)
        if m == 0 or m > 63:  # Bitap is practical for short patterns
            return []

        # Build character bitmask table for the pattern
        # Convention: 0-bit = match active, 1-bit = no match (shift-or standard)
        char_mask = {}
        for i, c in enumerate(pattern):
            if c not in char_mask:
                char_mask[c] = ~0  # all 1s = no match for any position
            char_mask[c] &= ~(1 << i)  # clear bit i = this char matches position i

        # Initialize bit-state arrays for 0..k error levels
        # D[e]: all 1s = no active states (1 = inactive, 0 = active)
        D = [~0] * (k + 1)
        matches = []

        for j, c in enumerate(text):
            cm = char_mask.get(c, ~0)  # all 1s if char not in pattern
            prev_D = D[:]

            # e=0: exact match layer (shift-or core)
            D[0] = ((prev_D[0] << 1) | cm) & ((1 << m) - 1)

            # e=1..k: fuzzy layers — substitution only (Hamming distance)
            for e in range(1, k + 1):
                substitution = (prev_D[e - 1] << 1)           # accept any char (substitute)
                shift        = ((prev_D[e] << 1) | cm)        # normal shift-or for this layer
                D[e] = (substitution & shift) & ((1 << m) - 1)

            # Check all error levels — report lowest error count found
            for e in range(k + 1):
                if not (D[e] & (1 << (m - 1))):  # bit (m-1) = 0 means full match
                    matches.append((j, e))
                    break  # only report best (lowest error) match at this position

        return matches

    @staticmethod
    def _is_word_bounded(text, start_idx, end_idx):
        """
        O1 (fuzzy-match safeguard): confirms a Bitap match span
        [start_idx, end_idx] (inclusive) is aligned to word boundaries
        in `text`, not just an arbitrary substring inside a longer token.

        Without this check, short patterns (e.g. "otp", 3 chars) can
        fuzzy-match a coincidental substring of an unrelated word within
        Hamming distance k — e.g. "ttp" inside "https" is only 1
        substitution away from "otp" — producing a false positive that
        has nothing to do with the actual word "https". Restricting
        fuzzy matches to token boundaries (as documented for the O1
        transition-scoring architecture) eliminates this class of error
        while leaving Layer 1's literal substring matching untouched.

        A boundary is any position at the very start/end of the text, or
        any adjacent character that is not a word character (`\\w`).
        """
        left_ok = start_idx == 0 or not re.match(r'\w', text[start_idx - 1])
        right_ok = end_idx == len(text) - 1 or not re.match(r'\w', text[end_idx + 1])
        return left_ok and right_ok

    def _proximity_score(self, text, match_index, window=50):
        """
        O2: Inverse distance weighting (IDW) proximity scoring.

        Scans a character window around the match position and accumulates
        weighted scores for each booster/neutralizer found. Terms closer
        to the match contribute more weight: weight = 1 / (distance + 1).

        Args:
            text:        original (non-normalized) text
            match_index: character index of the detected pattern end
            window:      max chars to scan on each side of match

        Returns:
            proximity_delta — net score adjustment (positive = riskier,
                              negative = more benign)
        """
        context = text[max(0, match_index - window):min(len(text), match_index + window)].lower()
        context_start = max(0, match_index - window)

        proximity_delta = 0.0

        for term in self.boosters:
            pos = context.find(term)
            while pos != -1:
                abs_pos = context_start + pos
                distance = abs(abs_pos - match_index)
                proximity_delta += 1 / (distance + 1)
                pos = context.find(term, pos + 1)

        for term in self.neutralizers:
            pos = context.find(term)
            while pos != -1:
                abs_pos = context_start + pos
                distance = abs(abs_pos - match_index)
                proximity_delta -= 1 / (distance + 1)
                pos = context.find(term, pos + 1)

        # Normalize delta to a bounded [-1.0, +1.0] contribution
        # Clamp so a single very-close booster doesn't dominate the score
        return max(-1.0, min(1.0, proximity_delta))

    def _strip_affixes(self, word):
        """
        O3: Affix-stripping heuristic for Filipino morphology.

        Attempts to extract the root word by removing known Filipino
        derivational prefixes and suffixes. Returns the stripped root,
        or the original word if no affixes matched.

        Handles hyphenated forms (i-gcash, mag-login) and fused forms
        (nagcash, gcashin) common in Taglish informal text.

        Basis: Schachter & Otanes (1972), Tagalog Reference Grammar.
        """
        word = word.lower().replace('-', '')  # normalize hyphens first

        # Try stripping prefixes (longest match first)
        root = word
        for prefix in self.prefixes:
            if word.startswith(prefix) and len(word) > len(prefix) + 2:
                root = word[len(prefix):]
                break  # only strip one prefix layer

        # Try stripping suffixes from the (possibly prefix-stripped) root.
        # Unlike prefixes, the paper does not specify longest-suffix-first —
        # and greedily taking the longest matching suffix can mis-parse a
        # coincidental overlap (e.g. "gcashin" ends in both "-in" and
        # "-hin"; blindly preferring "-hin" strips part of the real root
        # "gcash", leaving "gcas"). Instead, try every suffix that matches
        # and prefer whichever candidate root the trie actually recognizes;
        # only fall back to the longest-match heuristic if none do.
        candidates = []
        for suffix in self.suffixes:
            clean_suffix = suffix.lstrip('-')
            if root.endswith(clean_suffix) and len(root) - len(clean_suffix) >= 4:
                candidates.append(root[:-len(clean_suffix)])

        if candidates:
            for candidate in candidates:
                if self._trie_recognizes(candidate):
                    return candidate
            root = candidates[0]  # fall back: longest suffix stripped first

        return root

    def _trie_recognizes(self, word):
        """Returns True if `word`, once normalized, is a complete path in
        the trie ending on an output (pattern-match) state."""
        curr = 0
        for char in self._normalize(word):
            curr = self.goto[curr].get(char, 0)
            if curr == 0 and char not in self.goto[0]:
                return False
        return self.out[curr] > 0

    def _affix_search(self, text, original_text):
        """
        O3: Layer 3 — Affix-aware pattern search.

        Tokenizes input into words, strips affixes from each token,
        normalizes the stripped root, then checks against the trie.

        Returns list of (pattern_index, token, stripped_root, word_position)
        for each match found that was NOT already caught by layers 1 or 2.
        """
        matches = []
        # Tokenize on whitespace and common punctuation, keep position info
        tokens = re.finditer(r'[\w](?:[\w\-]*[\w])?', text)

        for token_match in tokens:
            token = token_match.group()
            word_pos = token_match.start()

            stripped = self._strip_affixes(token)
            if stripped == token.lower().replace('-', ''):
                continue  # no affix stripped, trie/bitap already handled it

            norm_root = self._normalize(stripped)

            # Run stripped root through trie
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

    def _anomaly_score(self, text):
        """
        Heuristic fallback for messages that do not match a known pattern.

        Returns a tuple of (score, signals) where score is bounded to [0, 1]
        and signals is a list of human-readable reasons for the warning.
        """
        normalized = self._normalize(text)
        lowered = text.lower()
        signals = []
        score = 0.0

        def bump(amount, label):
            nonlocal score
            score = min(1.0, score + amount)
            signals.append(label)

        if any(term in normalized for term in self.anomaly_urgency_terms):
            bump(0.22, "urgency language")

        if any(term in normalized for term in self.anomaly_action_terms):
            bump(0.20, "action request")

        if any(term in normalized for term in self.anomaly_sensitive_terms):
            bump(0.28, "credential or payment language")

        if any(term in normalized for term in self.anomaly_benign_terms):
            score = max(0.0, score - 0.18)
            signals.append("benign context")

        url_like = re.search(r'(?i)\b(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?', normalized)
        if url_like:
            bump(0.18, "URL-like text")

        obfuscated_tokens = re.findall(r'\b[a-z]+[0-9@$]+[a-z]+\b', lowered)
        if obfuscated_tokens:
            bump(0.12, "obfuscated spelling")

        digit_ratio = sum(char.isdigit() for char in text) / max(len(text), 1)
        if digit_ratio >= 0.08:
            bump(0.08, "digit-heavy content")

        return round(score, 3), signals[:4]

    def run_validation_suite(self, anomaly_threshold=None):
        """Run a tiny regression set to track false negatives and false positives."""
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

    # O4: Known URL shorteners — high risk regardless of segment position
    # Basis: Garera et al. (2007), Le et al. (2011)
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
        'rb.gy', 'cutt.ly', 'shorturl.at', 'is.gd', 'buff.ly'
    }

    # O4: Segment-bound risk weights
    # Pattern found in subdomain = highest risk (phishing indicator)
    # Pattern found in SLD       = low risk (may be legitimate registration)
    # Pattern found in path/query = medium risk (manipulation attempt)
    # Basis: Zhang et al. (2007) CANTINA, Garera et al. (2007)
    SEGMENT_RISK = {
        'shortener': 2.5,   # URL shortener — destination unknown
        'subdomain':  2.0,  # brand keyword in subdomain = spoofing
        'path':       1.5,  # brand keyword in path = moderate risk
        'query':      1.5,  # brand keyword in query params = moderate risk
        'sld':        1.0,  # brand keyword in SLD = likely legitimate
        'none':       1.0,  # match not inside any URL
    }

    def _segment_url(self, url):
        """
        O4: Delimiter-driven URL segmentation.

        Parses a URL into its structural components using delimiter
        characters (://, ., /, ?) as segment boundaries.

        Returns a dict with keys: scheme, subdomains, sld, tld, path, query.

        Basis: Zhang et al. (2007), Garera et al. (2007).
        """
        # Strip scheme (http:// or https://)
        scheme_match = re.match(r'https?://', url, re.IGNORECASE)
        rest = url[scheme_match.end():] if scheme_match else url

        # Split path and query
        path = ''
        query = ''
        if '?' in rest:
            rest, query = rest.split('?', 1)
        if '/' in rest:
            rest, path = rest.split('/', 1)

        # Split host into parts on delimiter '.'
        host_parts = rest.split('.')

        # Determine SLD and TLD — last two parts are TLD+SLD
        # anything before that is subdomain
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
        O4: Segment-bound risk evaluation.
fili
        Detects if the match at `index` falls inside a URL, segments
        the URL using delimiter-driven parsing, then returns a risk
        multiplier and segment label based on which structural segment
        contains the detected pattern or where the URL itself appears
        suspicious.

        Basis: Zhang et al. (2007) CANTINA; Garera et al. (2007).
        """
        normalized_text = self._normalize(text)
        url_pattern = r'(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?'
        norm_patterns = self.norm_patterns  # precomputed in __init__, don't rebuild per call

        for m in re.finditer(url_pattern, normalized_text, re.IGNORECASE):
            url = m.group()
            segments = self._segment_url(url)

            # Check if it's a known URL shortener first
            full_host = '.'.join(
                segments['subdomains'] + [segments['sld'], segments['tld']]
            ).lower()
            if any(s in full_host for s in self.URL_SHORTENERS):
                return {"multiplier": self.SEGMENT_RISK['shortener'], "segment": "shortener"}

            # Check each pattern against each segment
            for norm_p in norm_patterns:
                # Subdomain: brand keyword in subdomain = spoofing attempt
                if any(norm_p in self._normalize(sub) for sub in segments['subdomains']):
                    return {"multiplier": self.SEGMENT_RISK['subdomain'], "segment": "subdomain"}

                # Path or query: moderate risk
                if norm_p in self._normalize(segments['path']):
                    return {"multiplier": self.SEGMENT_RISK['path'], "segment": "path"}
                if norm_p in self._normalize(segments['query']):
                    return {"multiplier": self.SEGMENT_RISK['query'], "segment": "query"}

                # SLD: likely legitimate (e.g. gcash.com is the real domain)
                if norm_p in self._normalize(segments['sld']):
                    return {"multiplier": self.SEGMENT_RISK['sld'], "segment": "sld"}

        return {"multiplier": self.SEGMENT_RISK['none'], "segment": "none"}

    def enhanced_search(self, text, anomaly_threshold=None):
        """
        Step 4: Pattern Search with Integrated Bit-Parallel Scoring (SOP 1, 2 & 4).

        Layer 1 — Trie (AC): exact match on normalized text.
        Layer 2 — Bitap: fuzzy match on normalized text for residual deviations.
        Both layers feed into a unified risk score per detection.
        """
        clean_text = self._normalize(text)
        results = []
        reported = set()  # avoid duplicate alerts for same pattern

        if anomaly_threshold is None:
            anomaly_threshold = self.anomaly_threshold

        # O4 perf: _analyze_url's result is the same for every match in a
        # given message (it scans the whole text for URLs regardless of
        # match position), so compute it once per message instead of once
        # per match — avoids O(matches x text_length) blowup on long,
        # keyword-dense text.
        url_info = self._analyze_url(text, 0)
        url_risk = url_info["multiplier"]

        # ── Layer 1: Aho-Corasick trie search (exact, post-normalization) ──
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

                        # O1 word-boundary safeguard (same rule as Layer 2):
                        # reject matches that are a coincidental substring of
                        # a larger, unrelated word (e.g. "bank" inside
                        # "bankruptcy") rather than the actual keyword.
                        if not self._is_word_bounded(clean_text, start_idx, i):
                            continue

                        context_window = text[max(0, i - 20):min(len(text), i + 20)].lower()

                        # Base score: exact match should clear the default UI threshold
                        # O2: proximity delta replaces flat booster/neutralizer logic
                        score = 1.25
                        fuzzy_penalty = 0.0  # 0 errors from trie match
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

        # ── Layer 2: Bitap fuzzy search (catches residual obfuscation) ──
        for j, (pattern, norm_pattern) in enumerate(zip(self.patterns, self.norm_patterns)):
            bitap_matches = self._bitap_search(clean_text, norm_pattern, self.max_errors)
            for (end_idx, error_count) in bitap_matches:
                if error_count == 0:
                    continue  # already caught by trie layer, skip

                # O1 fuzzy-match safeguard: reject matches that don't align
                # to a word boundary (e.g. "ttp" inside "https" matching
                # "otp" at Hamming distance 1 — a coincidental mid-word
                # substring, not an actual obfuscated occurrence of the word).
                start_idx = end_idx - len(norm_pattern) + 1
                if not self._is_word_bounded(clean_text, start_idx, end_idx):
                    continue

                key = (j, end_idx)
                if key in reported:
                    continue
                reported.add(key)

                i = end_idx
                context_window = text[max(0, i - 20):min(len(text), i + 20)].lower()

                # Fuzzy score: small penalty per error — residual obfuscation is still a threat
                # Each error reduces confidence slightly but should not suppress detection
                # O2: proximity delta replaces flat booster/neutralizer logic
                score = 1.0
                fuzzy_penalty = error_count * 0.1
                proximity_delta = self._proximity_score(text, i)
                score += proximity_delta

                final_risk = (score - fuzzy_penalty) * url_risk

                # Fuzzy matches use slightly lower threshold than exact
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

        # ── Layer 3: Affix-aware search (O3) ──
        affix_matches = self._affix_search(clean_text, text)
        for (j, token, stripped_root, word_pos) in affix_matches:
            key = (j, word_pos)
            if key in reported:
                continue
            reported.add(key)

            pattern = self.patterns[j]
            context_window = text[max(0, word_pos - 20):min(len(text), word_pos + 20)].lower()

            # Affix match: slight penalty since root extraction introduces uncertainty
            score = 1.0
            affix_penalty = 0.15
            proximity_delta = self._proximity_score(text, word_pos)
            score += proximity_delta

            final_risk = (score - affix_penalty) * url_risk

            # Affix matches use same threshold as fuzzy — harder detection
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

        # ── Layer 4: Heuristic anomaly fallback (dictionary-independent) ──
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

    # Severity band cutoffs — a hybrid of empirical evidence and design intent.
    #
    # LOW_MODERATE_CUTOFF (1.142) is empirically derived from the score
    # distribution observed across two independent evaluation datasets (see
    # derive_severity_thresholds.py) — confirmed identically on both.
    #
    # MODERATE_HIGH_CUTOFF and HIGH_CRITICAL_CUTOFF (1.5, 2.5) are a design
    # judgment layered on top of that empirical floor, not chased further
    # down the same precision-milestone method. A bare exact-match detection
    # scores 1.25 with zero additional context — deliberately keeping that at
    # "Moderate" rather than "High" requires a message to gather additional
    # corroborating evidence (nearby risk-indicative context via the IDW
    # proximity delta, or a risky URL placement) before it escalates to a
    # stronger single-message action. Chasing the empirical method to its
    # precision-milestone conclusion (~1.22/1.28) compresses Moderate into an
    # unusably thin band, since 1.25 alone would then already qualify as
    # "High" — collapsing the intended graduated response (flag -> warn ->
    # block) into an almost-binary one. Multi-message escalation
    # (conversation_tracker.py) remains a second, independent path to Tier 3
    # for messages that don't individually cross this bar.
    LOW_MODERATE_CUTOFF = 1.142
    MODERATE_HIGH_CUTOFF = 1.5
    HIGH_CRITICAL_CUTOFF = 2.5

    def assess_message(self, text):
        """Return the shared assessment shape used by the Viber integration."""
        detections = self.enhanced_search(text)
        max_risk = max((item["risk_score"] for item in detections), default=0.0)

        if not detections:
            severity, action_tier = "none", 0
        elif max_risk >= self.HIGH_CRITICAL_CUTOFF:
            severity, action_tier = "critical", 3
        elif max_risk >= self.MODERATE_HIGH_CUTOFF:
            severity, action_tier = "high", 3
        elif max_risk >= self.LOW_MODERATE_CUTOFF:
            severity, action_tier = "moderate", 2
        else:
            severity, action_tier = "low", 1

        return {
            "detections": detections,
            "severity": severity,
            "action_tier": action_tier,
            "is_clean": not detections,
        }