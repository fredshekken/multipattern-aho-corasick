from collections import deque

class AhoCorasickDFA:
    def __init__(self, words):
        self.words = words
        self.goto = [{}] 
        self.fail = [0]
        self.out = [0]
        self.states_count = 1
        self._build_machine()

    def _build_machine(self):
        # Phase 1: Build the Trie
        for i, word in enumerate(self.words):
            curr = 0
            for char in word:
                if char not in self.goto[curr]:
                    self.goto[curr][char] = self.states_count
                    self.goto.append({})
                    self.fail.append(0)
                    self.out.append(0)
                    self.states_count += 1
                curr = self.goto[curr][char]
            self.out[curr] |= (1 << i)

        # Phase 2: Compute Failure Links and Flatten Transitions (DFA)
        queue = deque()
        visited = set()
        for char, next_state in self.goto[0].items():
            queue.append(next_state)
            visited.add(next_state)
        # ...existing code...

        while queue:
            r = queue.popleft()
            # Optimization: Pre-compute transitions from failure links
            f_state = self.fail[r]
            for char, next_st in self.goto[f_state].items():
                if char not in self.goto[r]:
                    self.goto[r][char] = next_st

            for char, s in self.goto[r].items():
                if s >= self.states_count: continue # Skip the pre-computed shortcuts

                f = self.fail[r]
                while char not in self.goto[f] and f != 0:
                    f = self.fail[f]
                self.fail[s] = self.goto[f].get(char, 0)
                self.out[s] |= self.out[self.fail[s]]
                if s not in visited:
                    queue.append(s)
                    visited.add(s)
            # ...existing code...

    def search(self, text):
        print(f"\nScanning: \"{text}\"")
        curr = 0
        found = False
        for i, char in enumerate(text):
            curr = self.goto[curr].get(char, 0)
            if self.out[curr] > 0:
                for j in range(len(self.words)):
                    if self.out[curr] & (1 << j):
                        w = self.words[j]
                        print(f"  [!] ALERT: Found '{w}' at index {i - len(w) + 1}")
                        found = True
        if not found:
            print("  [✓] No threats detected.")
            
if __name__ == "__main__":
    patterns = ["gcash", "blocked", "verify"]
    scanner = AhoCorasickDFA(patterns)
    
    test_text = "Hi ma yung jikash account ko nablock, di ko ma e-berify"
    
    print("--- SOP 1 PROOF ---")
    scanner.search(test_text)