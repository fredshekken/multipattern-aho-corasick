from collections import deque


class AhoCorasickDFA:
    """
    Standard Aho-Corasick Algorithm Implementation
    Based on: Aho & Corasick (1975), "Efficient String Matching: An Aid to Bibliographic Search"
    
    Components:
        - Goto function (Trie structure)
        - Failure links (suffix links via BFS)
        - Output function (bitmask per state)
        - DFA flattening (transition pre-computation)
    """

    def __init__(self, patterns: list[str]):
        self.patterns = patterns
        self.goto = [{}]        # goto[state][char] = next_state
        self.fail = [0]         # fail[state] = failure_link_state
        self.out = [0]          # out[state] = bitmask of matched patterns
        self.states_count = 1
        self._build_trie()
        self._build_failure_links()

    # ------------------------------------------------------------------ #
    #  PHASE 1 — Trie Construction (Goto Function)                        #
    # ------------------------------------------------------------------ #
    def _build_trie(self):
        for i, pattern in enumerate(self.patterns):
            curr = 0
            for char in pattern:
                if char not in self.goto[curr]:
                    self.goto[curr][char] = self.states_count
                    self.goto.append({})
                    self.fail.append(0)
                    self.out.append(0)
                    self.states_count += 1
                curr = self.goto[curr][char]
            self.out[curr] |= (1 << i)  # Mark terminal state via bitmask

    # ------------------------------------------------------------------ #
    #  PHASE 2 — Failure Link Calculation (BFS Traversal)                 #
    # ------------------------------------------------------------------ #
    def _build_failure_links(self):
        queue = deque()
        visited = set()

        # All direct children of root have failure link = root (state 0)
        for char, next_state in self.goto[0].items():
            self.fail[next_state] = 0
            queue.append(next_state)
            visited.add(next_state)

        trie_children = {}
        for state in range(self.states_count):
            trie_children[state] = dict(self.goto[state])

        while queue:
            r = queue.popleft()

            # Process only original trie edges for failure link computation
            for char, s in trie_children[r].items():
                # Trace failure links to find longest proper suffix
                f = self.fail[r]
                while char not in self.goto[f] and f != 0:
                    f = self.fail[f]

                self.fail[s] = self.goto[f].get(char, 0)
                if self.fail[s] == s:
                    self.fail[s] = 0  # Prevent self-loops

                # Output merging: inherit matched patterns from failure state
                self.out[s] |= self.out[self.fail[s]]

                if s not in visited:
                    visited.add(s)
                    queue.append(s)

            # DFA Flattening: inherit missing transitions from failure state
            f_state = self.fail[r]
            for char, next_st in self.goto[f_state].items():
                if char not in self.goto[r]:
                    self.goto[r][char] = next_st

    # ------------------------------------------------------------------ #
    #  PHASE 3 — Pattern Search (Scanning)                                #
    # ------------------------------------------------------------------ #
    def search(self, text: str) -> list[dict]:
        """
        Scan input text and return all matches.
        Returns a list of dicts: {pattern, end_index, start_index}
        """
        curr = 0
        matches = []
        for i, char in enumerate(text):
            curr = self.goto[curr].get(char, 0)
            if self.out[curr] > 0:
                for j in range(len(self.patterns)):
                    if self.out[curr] & (1 << j):
                        w = self.patterns[j]
                        matches.append({
                            "pattern": w,
                            "end_index": i,
                            "start_index": i - len(w) + 1
                        })
        return matches

    # ------------------------------------------------------------------ #
    #  DIAGNOSTIC — Trie Structure Export (for visualization)             #
    # ------------------------------------------------------------------ #
    def get_trie_structure(self) -> dict:
        """
        Export full trie structure for visualization.
        Returns nodes, edges, failure links, and output states.
        """
        nodes = []
        edges = []
        failure_edges = []

        # Reconstruct node labels (path from root)
        labels = [""] * self.states_count
        for state in range(self.states_count):
            for char, next_state in self.goto[state].items():
                if labels[next_state] == "" and next_state != 0:
                    labels[next_state] = labels[state] + char

        for state in range(self.states_count):
            is_output = self.out[state] > 0
            matched = []
            if is_output:
                for j in range(len(self.patterns)):
                    if self.out[state] & (1 << j):
                        matched.append(self.patterns[j])

            nodes.append({
                "id": state,
                "label": labels[state] if labels[state] else "ROOT",
                "is_output": is_output,
                "matched_patterns": matched,
                "fail_link": self.fail[state]
            })

        for state in range(self.states_count):
            for char, next_state in self.goto[state].items():
                edges.append({
                    "from": state,
                    "to": next_state,
                    "char": char
                })

        for state in range(1, self.states_count):
            if self.fail[state] != state:
                failure_edges.append({
                    "from": state,
                    "to": self.fail[state]
                })

        return {
            "nodes": nodes,
            "edges": edges,
            "failure_edges": failure_edges,
            "states_count": self.states_count,
            "patterns": self.patterns
        }
