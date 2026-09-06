import re
from collections import deque
from pathlib import Path


class EnhancedAhoCorasick:
    # Fuzzy matching (Layer 2, Bitap) is only applied to patterns at least
    # this many characters long. Short patterns (e.g. "otp", "pin") have very
    # few characters of "signal", so an edit-distance-1 window matches an
    # enormous number of coincidental substrings in ordinary text — for
    # example "otp" is 1 substitution away from "ttp", which appears in every
    # single "https://" URL. Below this length, only exact/affix matching is
    # used; fuzzy matching would trade detection sensitivity for a large
    # false-positive cost that isn't worth it for such short strings.
    MIN_FUZZY_PATTERN_LENGTH = 5

    def __init__(self, patterns, max_errors=1, anomaly_threshold=0.45):
        self.max_errors = max_errors  # k for Bitap fuzzy threshold
        self.anomaly_threshold = anomaly_threshold

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
            "urgent", "asap", "immediately", "now", "today", "tonight",
            "before", "deadline", "final", "last chance", "act now"
        }
        self.anomaly_action_terms = {
            "click", "tap", "verify", "confirm", "login", "sign in",
            "update", "reset", "open", "follow", "reply"
        }
        self.anomaly_sensitive_terms = {
            "password", "pin", "otp", "code", "security code", "account",
            "wallet", "bank", "payment", "transfer", "send", "claim",
            "cash", "money", "card", "identity", "credentials", "gift"
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
    def from_pattern_file(cls, pattern_file, max_errors=1, anomaly_threshold=0.45):
        """Create a scanner from a categorized pattern file."""
        file_path = Path(pattern_file)
        if file_path.exists():
            pattern_text = file_path.read_text(encoding="utf-8")
            patterns = cls.parse_pattern_groups(pattern_text)
        else:
            patterns = {}

        return cls(patterns, max_errors=max_errors, anomaly_threshold=anomaly_threshold)

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

        # Try stripping suffixes from the (possibly prefix-stripped) root
        for suffix in self.suffixes:
            clean_suffix = suffix.lstrip('-')
            if root.endswith(clean_suffix) and len(root) - len(clean_suffix) >= 4:
                root = root[:-len(clean_suffix)]
                break  # only strip one suffix layer

        return root

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

        obfuscated_tokens = re.findall(r'\b[a-z]*[0-9@$][a-z0-9@$]*\b', lowered)
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
        multiplier based on which structural segment contains the
        detected pattern or where the URL itself appears suspicious.

        Basis: Zhang et al. (2007) CANTINA; Garera et al. (2007).
        """
        normalized_text = self._normalize(text)
        url_pattern = r'(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?'
        norm_patterns = [self._normalize(p) for p in self.patterns]

        for m in re.finditer(url_pattern, normalized_text, re.IGNORECASE):
            url = m.group()
            segments = self._segment_url(url)

            # Check if it's a known URL shortener first
            full_host = '.'.join(
                segments['subdomains'] + [segments['sld'], segments['tld']]
            ).lower()
            if any(s in full_host for s in self.URL_SHORTENERS):
                return self.SEGMENT_RISK['shortener']

            # Check each pattern against each segment
            for norm_p in norm_patterns:
                # Subdomain: brand keyword in subdomain = spoofing attempt
                if any(norm_p in self._normalize(sub) for sub in segments['subdomains']):
                    return self.SEGMENT_RISK['subdomain']

                # Path or query: moderate risk
                if norm_p in self._normalize(segments['path']):
                    return self.SEGMENT_RISK['path']
                if norm_p in self._normalize(segments['query']):
                    return self.SEGMENT_RISK['query']

                # SLD: likely legitimate (e.g. gcash.com is the real domain)
                if norm_p in self._normalize(segments['sld']):
                    return self.SEGMENT_RISK['sld']

        return self.SEGMENT_RISK['none']

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
                        context_window = text[max(0, i - 20):min(len(text), i + 20)].lower()

                        # Base score: exact match should clear the default UI threshold
                        # O2: proximity delta replaces flat booster/neutralizer logic
                        score = 1.25
                        fuzzy_penalty = 0.0  # 0 errors from trie match
                        proximity_delta = self._proximity_score(text, i)
                        score += proximity_delta

                        url_risk = self._analyze_url(text, i)
                        final_risk = (score - fuzzy_penalty) * url_risk

                        if final_risk >= 1.2:
                            results.append({
                                "alert": f"CRITICAL: '{pattern}' detected!",
                                "risk_score": round(final_risk, 3),
                                "match_type": "exact",
                                "error_count": 0,
                                "context": context_window.strip()
                            })

        # ── Layer 2: Bitap fuzzy search (catches residual obfuscation) ──
        for j, (pattern, norm_pattern) in enumerate(zip(self.patterns, self.norm_patterns)):
            if len(norm_pattern) < self.MIN_FUZZY_PATTERN_LENGTH:
                continue  # too short — see MIN_FUZZY_PATTERN_LENGTH docstring
            bitap_matches = self._bitap_search(clean_text, norm_pattern, self.max_errors)
            for (end_idx, error_count) in bitap_matches:
                if error_count == 0:
                    continue  # already caught by trie layer, skip

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

                url_risk = self._analyze_url(text, i)
                final_risk = (score - fuzzy_penalty) * url_risk

                # Fuzzy matches use slightly lower threshold than exact
                fuzzy_threshold = 1.2 - (error_count * 0.15)
                if final_risk >= fuzzy_threshold:
                    results.append({
                        "alert": f"CRITICAL: '{pattern}' detected! (fuzzy match, {error_count} error(s))",
                        "risk_score": round(final_risk, 3),
                        "match_type": "fuzzy",
                        "error_count": error_count,
                        "context": context_window.strip()
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

            url_risk = self._analyze_url(text, word_pos)
            final_risk = (score - affix_penalty) * url_risk

            # Affix matches use same threshold as fuzzy — harder detection
            if final_risk >= 1.05:
                results.append({
                    "alert": f"CRITICAL: '{pattern}' detected! (affix match: '{token}' -> root '{stripped_root}')",
                    "risk_score": round(final_risk, 3),
                    "match_type": "affix",
                    "error_count": 0,
                    "context": context_window.strip()
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
                })

        return results

    def assess_message(self, text):
        """Return the shared assessment shape used by the Viber integration."""
        detections = self.enhanced_search(text)
        max_risk = max((item["risk_score"] for item in detections), default=0.0)

        if not detections:
            action_tier = 0
        elif max_risk >= 2.5:
            action_tier = 3
        elif max_risk >= 1.5:
            action_tier = 2
        else:
            action_tier = 1

        return {
            "detections": detections,
            "action_tier": action_tier,
            "is_clean": not detections,
        }


if __name__ == "__main__":
    patterns = ["gcash", "blocked", "login"]
    scanner = EnhancedAhoCorasick(patterns, max_errors=1)

    # Test 1: Normalization + trie, single booster
    msg1 = "Urgent: Your G-C@sh account is vlocked! Verify here: http://bit.ly/fake-link"
    print("=== Test 1: Normalization + Trie ===")
    for f in scanner.enhanced_search(msg1):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")

    # Test 2: Residual substitution obfuscation — Bitap fuzzy layer
    msg2 = "Urgent: Your gczsh account is blxcked! Verify here: http://bit.ly/fake-link"
    print("\n=== Test 2: Fuzzy (Bitap) layer ===")
    for f in scanner.enhanced_search(msg2):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")

    # Test 3: Multiple close boosters — IDW should accumulate higher score
    msg3 = "AGAD! I-verify ang iyong gcash account. Mag-login na ngayon bago ma-block!"
    print("\n=== Test 3: O2 — Multiple close boosters (high IDW score) ===")
    for f in scanner.enhanced_search(msg3):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")

    # Test 4: Neutralizers present — IDW should reduce score
    msg4 = "Official GCash customer support hotline. Login to our authorized service portal."
    print("\n=== Test 4: O2 — Neutralizers present (suppressed score) ===")
    for f in scanner.enhanced_search(msg4):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")

    # Test 5: Prefixed affix forms — O3 should strip and detect
    msg5 = "Agad mag-login at i-verify ang iyong account. I-gcash na ngayon!"
    print("\n=== Test 5: O3 — Affix-stripped detection (mag-login, i-gcash) ===")
    for f in scanner.enhanced_search(msg5):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")

    # Test 6: Suffixed affix forms — O3 should strip and detect
    msg6 = "I-blockan ang account mo pag hindi mo gcashin agad!"
    print("\n=== Test 6: O3 — Suffix-stripped detection (blockan, gcashin) ===")
    for f in scanner.enhanced_search(msg6):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")

    # Test 7: Brand keyword in SUBDOMAIN = high risk (spoofing)
    msg7 = "Verify here: https://gcash.verify-now.com/login"
    print("\n=== Test 7: O4 — Brand in subdomain (HIGH risk) ===")
    for f in scanner.enhanced_search(msg7):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")

    # Test 8: Brand keyword in SLD = low risk (legitimate domain)
    msg8 = "Visit https://gcash.com/help for assistance."
    print("\n=== Test 8: O4 — Brand in SLD (LOW risk, legitimate) ===")
    for f in scanner.enhanced_search(msg8):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")

    # Test 9: URL shortener = highest risk
    msg9 = "Urgent: Click here to verify your gcash: https://bit.ly/xK92p"
    print("\n=== Test 9: O4 — URL shortener (HIGHEST risk) ===")
    for f in scanner.enhanced_search(msg9):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")

    # Test 10: Brand keyword in PATH = medium risk
    msg10 = "Urgent: https://verify-now.com/gcash/confirm your account"
    print("\n=== Test 10: O4 — Brand in path (MEDIUM risk) ===")
    for f in scanner.enhanced_search(msg10):
        print(f"[{f['risk_score']}] [{f['match_type']}] {f['alert']} | Context: ...{f['context']}...")