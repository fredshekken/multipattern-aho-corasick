# Enhanced Aho-Corasick Algorithm Pseudocode

## Multi-Pattern String Matching Framework with Fuzzy Matching, Proximity Scoring, Morphological Analysis, and URL Risk Assessment

Based on Aho-Corasick (1975) with enhancements for phishing detection in code-mixed (Taglish) informal text.

---

## Step 0: Text Normalization (Foundation for all layers)
**Problem: Obfuscation via symbol substitution and phonetic variants**

Initialize two normalization maps:
- **SOP 1 — Symbol Normalization Map**: `{@ → a, 0 → o, 1 → i, 3 → e, $ → s, 4 → a, 5 → s}`
  - Origin: Common obfuscation patterns in phishing (e.g., "G-C@sh" → "G-cash")
  
- **O3 — Phonetic Map (Taglish nuances)**: `{v → b, f → p}`
  - Origin: Schachter & Otanes (1972), Tagalog Reference Grammar
  - Handles Filipino informal spelling variants (e.g., "vlocked" → "blocked")

**Normalization Function:**
```
FUNCTION normalize(text)
  text ← lowercase(text)
  FOR each character mapping in symbol_map DO
    text ← replace(text, symbol, norm_char)
  END FOR
  FOR each character mapping in phonetic_map DO
    text ← replace(text, phonetic_char, replacement)
  END FOR
  RETURN text
END FUNCTION
```

---

## Step 1: Enhanced Trie Construction (Goto Function + Normalization)

**Objective: Build a deterministic finite automaton on normalized text to handle obfuscation-resistant matching**

Initialize the root state (State 0) with an empty transition map.

FOR each pattern $P_i$ in the dictionary:
  - Normalize the pattern: $P_i^{norm} ← \text{normalize}(P_i)$
    - **Origin (SOP 1)**: Ensures patterns match obfuscated variants without explicit enumeration
  
  - Start at the root state $(curr ← 0)$
  
  - FOR each character $c$ in $P_i^{norm}$:
    - IF a transition for $c$ does not exist:
      - Create a new state and update the goto map
      - **Problem No. 1**: Handling overlapping patterns requires deterministic state allocation
    
    - Move $curr$ to the next state
  
  - Mark the final state as an output state by setting the $i$-th bit in the out map

---

## Step 2: Resilient Failure Link Calculation (BFS Traversal)

**Objective: Compute failure links to ensure no pattern is missed due to partial overlaps or encoding variants**

Initialize a queue and add all immediate children of the root.

WHILE the queue is not empty:
  - Remove the current state $r$
  
  - FOR each character $a$ leading to a child state $s$:
    - Find the longest proper suffix that is also a prefix in the Trie by tracing the failure link of the parent:
      - $f ← \text{fail}[r]$
      - **Problem No. 3**: Failure links must account for normalized character equivalences
      - WHILE $a \notin \text{goto}[f]$ AND $f \neq 0$:
        - $f ← \text{fail}[f]$  (backtrack via failure link)
      
      - Set $\text{fail}[s] ← \text{goto}[f][a]$ (or 0 if no transition from root)
    
    - Merge output patterns of $\text{fail}[s]$ into $\text{out}[s]$ to ensure interior pattern detection
      - **Problem No. 4**: Interior patterns must be detected even if entry into the state is via a different path
      - $\text{out}[s] ← \text{out}[s] \cup \text{out}[\text{fail}[s]]$ (bitwise OR for pattern bitmasks)
    
    - Enqueue $s$ for processing

---

## Step 3: Multi-Layer Pattern Matching (Unified Risk Scoring)

**Objective: Detect patterns at four levels of abstraction, each with separate confidence scoring**

---

### Layer 1: Aho-Corasick Trie Search (Exact Match on Normalized Text)

**Purpose**: Catch exact pattern matches after symbol/phonetic normalization

Initialize $curr ← 0$

FOR each character position $i$ in $\text{normalize}(\text{input\_text})$:
  - Read character $c$ at position $i$
  
  - Transition: $curr ← \text{goto}[curr][c]$ (or 0 if no transition from root)
    - **Problem No. 2**: Deterministic transition guarantees no backtracking
  
  - IF $\text{out}[curr] > 0$:  (bit-vector check: patterns matched at this state)
    - FOR each bit $j$ set in $\text{out}[curr]$:
      - IF $(j, i) \notin \text{reported}$:  (avoid duplicate alerts)
        - **Scoring**:
          - Base risk score: $1.25$ (exact match is high-confidence threat)
          - Fuzzy penalty: $0.0$ (no errors detected)
          
          - **O2 Proximity-Based Weighting (IDW)**:
            - $\text{proximity\_delta} ← \text{compute\_IDW\_score}(\text{input\_text}, i, k=50)$
            - Score adjustment: $\text{score} ← 1.25 + \text{proximity\_delta}$
            - Origin: Counters false positives from legitimate domains containing brand names
        
          - **O4 Segment-Bound URL Risk Analysis**:
            - $\text{url\_risk} ← \text{analyze\_url\_segment}(\text{input\_text}, i)$
            - Multiplier: $\text{final\_risk} ← (\text{score} - 0.0) \times \text{url\_risk}$
            - Origin: Zhang et al. (2007) CANTINA; Garera et al. (2007)
        
        - IF $\text{final\_risk} \geq 1.2$:
          - Report match with $\text{match\_type} ← \text{"exact"}$, $\text{error\_count} ← 0$
          - Add $(j, i)$ to reported set

---

### Layer 2: Bit-Parallel Fuzzy Matching (Bitap Algorithm)

**Purpose**: Catch residual obfuscation that survives normalization (e.g., character substitution)

**O1 — Bit-Parallel Fuzzy Matching (Bitap/Shift-Or Algorithm)**
- Origin: Baeza-Yates & Gonnet (1992)
- Objective: Detect pattern occurrences within Hamming distance $k$ using bitwise operations

FOR each pattern $P_j$ with normalized form $P_j^{norm}$:
  - $m ← \text{length}(P_j^{norm})$
  - IF $m > 63$: skip (Bitap impractical for very long patterns)
  
  - Build character bitmask table for the pattern:
    - FOR each position $i$ in $P_j^{norm}$:
      - $\text{char\_mask}[P_j^{norm}[i]] \text{ clears bit } i$ (0 = match active)
      - Convention: 1-bit = no match, 0-bit = match (shift-or standard)
  
  - Initialize bit-state arrays:
    - $D[e] \text{ for } e \in [0, k]$: tracks all 1s = no active match states
  
  - FOR each character position $j$ in normalized input text:
    - $c ← \text{input}[j]$
    - $cm ← \text{char\_mask}.get(c, \text{all\_1s})$ (all 1s if char not in pattern)
    - Save previous state: $\text{prev\_D} \leftarrow D$
    
    - **Layer 0 (Exact match)**:
      - $D[0] ← ((\text{prev\_D}[0] \ll 1) | cm) \text{ \& } (1 \ll m) - 1$
    
    - **Layers 1 to k (Fuzzy layers — substitution only)**:
      - FOR $e$ in $[1, k]$:
        - $\text{substitution} ← \text{prev\_D}[e-1] \ll 1$ (accept any char as substitute)
        - $\text{shift} ← ((\text{prev\_D}[e] \ll 1) | cm)$ (normal shift-or for this layer)
        - $D[e] ← (\text{substitution} \text{ AND } \text{shift}) \text{ \& } (1 \ll m) - 1$
    
    - **Match Detection**:
      - FOR $e$ in $[0, k]$:
        - IF bit $(m-1)$ is 0 in $D[e]$: (0 = match found)
          - Record match $(j, e)$ and break (report lowest error count only)

  - FOR each Bitap match $(j, e)$ with position $j$ and error count $e$:
    - IF $e = 0$: continue (already caught by Layer 1)
    - IF $(P_j, j) \in \text{reported}$: continue (skip duplicates)
    
    - **Scoring**:
      - Base risk score: $1.0$ (fuzzy match is lower confidence than exact)
      - Fuzzy penalty: $0.1 \times e$ (each error reduces score slightly)
      
      - **O2 Proximity-Based Weighting (IDW)**:
        - $\text{proximity\_delta} ← \text{compute\_IDW\_score}(\text{input\_text}, j, k=50)$
        - Score adjustment: $\text{score} ← 1.0 + \text{proximity\_delta}$
      
      - **O4 Segment-Bound URL Risk Analysis**:
        - $\text{url\_risk} ← \text{analyze\_url\_segment}(\text{input\_text}, j)$
        - Final risk: $\text{final\_risk} ← (\text{score} - 0.1 \times e) \times \text{url\_risk}$
    
    - Threshold: $\text{threshold} ← 1.2 - (e \times 0.15)$ (more errors = lower threshold)
    - IF $\text{final\_risk} \geq \text{threshold}$:
      - Report match with $\text{match\_type} ← \text{"fuzzy"}$, $\text{error\_count} ← e$
      - Add $(\text{pattern}, j)$ to reported set

---

### Layer 3: Morphological Pattern Matching (Affix Stripping)

**Purpose**: Detect patterns disguised via Filipino derivational morphology

**O3 — Filipino Affix Stripping**
- Origin: Schachter & Otanes (1972), Tagalog Reference Grammar
- Objective: Extract root words by removing known Filipino prefixes and suffixes

**Affix Inventory**:
- **Prefixes** (ordered longest-first): `[magpa, nakaka, pinaka, nag, mag, pag, na, ma, pa, i, ka, in]`
- **Suffixes** (hyphenated first for safety): `[-in, -an, -han, -hin, -ng, hin, han]`
  - Bare suffixes only strip if remaining root $\geq 4$ characters (avoid false roots)

FOR each word token in input text:
  - Extract token and its position: $(token, \text{word\_pos})$
  
  - Strip affixes:
    - Normalize hyphens: $\text{word} ← \text{word}.replace('-', '')$
    
    - **Prefix stripping** (longest-first):
      - FOR each prefix in prefixes (ordered by length descending):
        - IF $\text{word}.startswith(\text{prefix})$ AND $\text{length}(\text{word}) > \text{length}(\text{prefix}) + 2$:
          - $\text{root} ← \text{word}[\text{length}(\text{prefix}):]$
          - break
    
    - **Suffix stripping** (on possibly prefix-stripped root):
      - FOR each suffix in suffixes:
        - $\text{clean\_suffix} ← \text{suffix}.lstrip('-')$
        - IF $\text{root}.endswith(\text{clean\_suffix})$ AND $\text{length}(\text{root}) - \text{length}(\text{clean\_suffix}) \geq 4$:
          - $\text{root} ← \text{root}[:-\text{length}(\text{clean\_suffix}):]$
          - break
  
  - Normalize stripped root: $\text{norm\_root} ← \text{normalize}(\text{root})$
  
  - IF $\text{norm\_root}$ matches a pattern in the trie (run trie traversal):
    - $curr ← 0$
    - FOR each character in $\text{norm\_root}$:
      - $curr ← \text{goto}[curr][\text{char}]$
    - IF $\text{out}[curr] > 0$:
      - FOR each bit $j$ set in $\text{out}[curr]$:
        - IF $(\text{pattern}, \text{word\_pos}) \notin \text{reported}$:
          - **Scoring**:
            - Base risk score: $1.0$ (morphological match is lower confidence)
            - Affix penalty: $0.15$ (root extraction introduces uncertainty)
            
            - **O2 Proximity-Based Weighting (IDW)**:
              - $\text{proximity\_delta} ← \text{compute\_IDW\_score}(\text{input\_text}, \text{word\_pos}, k=50)$
              - Score adjustment: $\text{score} ← 1.0 + \text{proximity\_delta}$
            
            - **O4 Segment-Bound URL Risk Analysis**:
              - $\text{url\_risk} ← \text{analyze\_url\_segment}(\text{input\_text}, \text{word\_pos})$
              - Final risk: $\text{final\_risk} ← (\text{score} - 0.15) \times \text{url\_risk}$
          
          - IF $\text{final\_risk} \geq 1.05$:
            - Report match with $\text{match\_type} ← \text{"affix"}$
            - Add $(\text{pattern}, \text{word\_pos})$ to reported set

---

### Layer 4: Heuristic Anomaly Fallback (Dictionary-Independent Detection)

**Purpose**: Catch suspicious messages that contain no known patterns but exhibit phishing signals

IF no matches found in Layers 1–3:
  - Compute anomaly score: $(\text{score}, \text{signals}) ← \text{anomaly\_score}(\text{input\_text})$
    - **Score Components**:
      - +0.22: Urgency language (urgent, asap, immediately, now, deadline, etc.)
      - +0.20: Action requests (click, verify, confirm, login, update, etc.)
      - +0.28: Credential/payment language (password, pin, otp, wallet, bank, etc.)
      - −0.18: Benign context (official, help, customer, support, hotline, etc.)
      - +0.18: URL-like text (http://, www., or domain patterns)
      - +0.12: Obfuscated spelling (alphanumeric tokens containing @ $ 0-9)
      - +0.08: High digit ratio (≥ 8% digits)
  
  - IF $\text{score} \geq \text{anomaly\_threshold}$ (default 0.45):
    - Report match with $\text{match\_type} ← \text{"anomaly"}$, $\text{risk\_score} ← 0.95 + 0.4 \times \text{score}$

---

## Step 4: Risk Scoring with Proximity-Based Weighting (O2)

**Purpose**: Adjust match confidence based on contextual proximity to phishing indicators

**O2 — Inverse Distance Weighting (IDW) Proximity Scoring**
- Origin: Counters false positives; legitimate domains may contain brand keywords
- Objective: Boost confidence if threat-escalating terms ("boosters") are near the match; suppress if benign terms ("neutralizers") are present

**Boosters** (terms increasing phishing likelihood):
- English: urgent, click, verify, blocked, login, confirm, suspend, limited, action, immediately, warning, alert
- Taglish: i-verify, i-click, na-block, kumpirmahin, agad, panganib, mag-login, ibigay, ipadala, ipasok

**Neutralizers** (terms suggesting legitimacy):
- English: official, help, customer, support, hotline, representative, authorized, service, policy
- Taglish: opisyal, tulong, serbisyo, awtorisado, lehitimo

```
FUNCTION compute_IDW_score(text, match_index, window=50)
  context ← text[max(0, match_index - window) : min(len(text), match_index + window)]
  proximity_delta ← 0.0
  
  FOR each booster term:
    FOR each occurrence of booster in context:
      distance ← absolute distance from match_index
      proximity_delta ← proximity_delta + 1 / (distance + 1)
  
  FOR each neutralizer term:
    FOR each occurrence of neutralizer in context:
      distance ← absolute distance from match_index
      proximity_delta ← proximity_delta - 1 / (distance + 1)
  
  RETURN clamp(proximity_delta, -1.0, 1.0)
END FUNCTION
```

---

## Step 5: Segment-Bound URL Risk Analysis (O4)

**Purpose**: Determine if a match falls within a URL and assess structural risk

**O4 — Segment-Bound Risk Weights**
- Origin: Zhang et al. (2007) CANTINA; Garera et al. (2007)
- Objective: Differentiate risk by URL component; brand in subdomain = spoofing, brand in SLD = likely legitimate

**Risk Multipliers**:
- Shortener (known URL shortener service): 2.5× (destination unknown)
- Subdomain (pattern in subdomain): 2.0× (classic spoofing indicator)
- Path (pattern in path): 1.5× (manipulation attempt)
- Query (pattern in query params): 1.5× (manipulation attempt)
- SLD (pattern in second-level domain): 1.0× (may be legitimate registration)
- None (pattern not in any URL): 1.0× (baseline)

**Known Shorteners**: `{bit.ly, tinyurl.com, goo.gl, ow.ly, t.co, rb.gy, cutt.ly, shorturl.at, is.gd, buff.ly}`

```
FUNCTION segment_url(url)
  Strip scheme (http:// or https://) → rest
  Split on '?' → rest, query
  Split on '/' → rest, path
  Split host on '.' → host_parts
  
  IF len(host_parts) >= 2:
    tld ← host_parts[-1]
    sld ← host_parts[-2]
    subdomains ← host_parts[:-2]
  ELSE:
    tld ← host_parts[0]
    sld ← empty
    subdomains ← []
  
  RETURN {subdomains, sld, tld, path, query}
END FUNCTION

FUNCTION analyze_url_segment(text, match_index)
  FOR each URL in text:
    segments ← segment_url(URL)
    
    IF URL is known shortener:
      RETURN 2.5
    
    FOR each pattern P:
      norm_P ← normalize(P)
      
      IF norm_P found in any subdomain:
        RETURN 2.0  (spoofing)
      ELSE IF norm_P found in path or query:
        RETURN 1.5  (manipulation)
      ELSE IF norm_P found in SLD:
        RETURN 1.0  (likely legitimate)
  
  RETURN 1.0  (no URL context)
END FUNCTION
```

---

## Summary of Enhancements

| Enhancement | Objective | Origin | Problem Addressed |
|---|---|---|---|
| **SOP 1** — Symbol & Phonetic Normalization | Unified handling of obfuscated variants | Common phishing patterns | Problem No. 1: Overlapping patterns |
| **O1** — Bitap Fuzzy Matching | Residual obfuscation detection (Hamming distance) | Baeza-Yates & Gonnet (1992) | Problem No. 2: Deterministic transitions |
| **O2** — Proximity-based IDW Scoring | Context-aware confidence tuning | Mitigate false positives from legitimate domains | Problem No. 3: Failure link accuracy |
| **O3** — Filipino Affix Stripping | Root word extraction for Taglish | Schachter & Otanes (1972) | Problem No. 4: Interior pattern detection |
| **O4** — Segment-Bound URL Risk | Structural risk differentiation | Zhang et al. (2007); Garera et al. (2007) | URL-based spoofing detection |

---

## Complexity Analysis

- **Time**:
  - Trie construction: $O(N \times M)$ where $N$ = number of patterns, $M$ = max pattern length
  - Failure links (BFS): $O(|Q| \times |\Sigma|)$ where $|Q|$ = number of states, $|\Sigma|$ = alphabet
  - Layer 1 search: $O(|T|)$ where $|T|$ = text length (with lookups into failure link chains)
  - Layer 2 search (Bitap): $O(|T| \times M \times k)$ where $k$ = max error threshold (typically small, ≤ 2)
  - Layer 3 search (Affix): $O(W \times |T|)$ where $W$ = max word length and pattern lookups
  - Layer 4 search (Anomaly): $O(|T|)$ single pass
  - **Overall**: $O(|T| \times (M + k) + \text{affix\_overhead})$

- **Space**:
  - Trie: $O(|Q| \times |\Sigma|)$ for goto maps
  - Failure & output arrays: $O(|Q|)$
  - Bitap character mask: $O(|\Sigma|)$ per pattern
  - **Overall**: $O(|Q| \times |\Sigma|)$
