# Multipattern Aho-Corasick: Enhanced Phishing Detection

A rule-based phishing detection system using an enhanced Aho-Corasick automaton with fuzzy matching, contextual scoring, and Taglish language support.

## Features

### Core Algorithm Enhancements

- **O1: Bitap Fuzzy Matching** — Detects near-miss variants (obfuscations with up to `max_errors` Hamming distance)
- **O2: Inverse Distance Weighting (IDW)** — Proximity-based scoring of booster and neutralizer terms around detected patterns
- **O3: Affix-Aware Root Detection** — Strips Filipino derivational affixes (prefixes/suffixes) to recover hidden phishing roots
- **O4: URL Segment Risk Weighting** — Analyzes URL components (shortener, subdomain, SLD, path, query) with targeted risk scores
- **Fallback Review Mode** — Surfaces suspicious language patterns even when no dictionary match is found

### User Interface

- **Single Message Scan** — Real-time manual text scanning with pattern visualization
- **Batch CSV Processing** — Upload CSV files with a `message` or `text` column for bulk detection
- **Algorithm Explorer** — Visualize Trie structure, transition paths, and phishing detection heuristics
- **Pattern Management** — Edit categorized rule base without redeploying

## Project Structure

```
.
├── enhanced_aho/
│   ├── enhanced_aho_corasick.py    # Core algorithm implementation
│   ├── streamlit_app.py              # Web UI (Streamlit)
│   └── default_patterns.txt          # Categorized phishing ruleset
├── original_aho/
│   ├── aho.py                        # Original Aho-Corasick reference
│   ├── ahocorasick.py                # Reference implementation
│   ├── visualizer.py                 # Demo visualizer
│   └── test.py                       # Test suite
├── enhanced_algo_pseudocode.md       # Algorithm documentation
└── README.md                         # This file
```

## Quick Start

### Prerequisites

- Python 3.8+
- Streamlit
- Pandas, Matplotlib, NetworkX (for visualization)

### Installation

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1
pip install streamlit pandas matplotlib networkx graphviz
```

### Running the App

```bash
streamlit run enhanced_aho/streamlit_app.py
```

The app will open at `http://localhost:8501`.

### Loading a Dataset

1. **Single Message Scan** → Paste text in the text area and click "🔍 Scan Message"
2. **Batch CSV Upload** → Go to the "📊 Batch Processing" tab, upload a CSV with a `message` column, and click "🔍 Scan All Messages"

### Updating Phishing Rules

Edit the pattern dictionary in the sidebar:
- Use `[category: name]` headers to organize patterns

**Streamlit Web UI:** Streamlit, Pandas, Matplotlib, NetworkX, Graphviz
- One pattern per line under each category
- Click "🔄 Update Patterns" to reload

## Dataset Integration

To use the Kaggle Email Phishing Dataset:
For programmatic use of the algorithm:
```bash
python -m venv .venv
source .venv/bin/activate
# Done! No pip install needed for EnhancedAhoCorasick (stdlib only)
```

For the Streamlit web UI:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # Streamlit + visualization dependencies
```
1. Download from [https://www.kaggle.com/datasets/ethancratchley/email-phishing-dataset](https://www.kaggle.com/datasets/ethancratchley/email-phishing-dataset)
2. Extract `email_phishing_data.csv`
3. Upload via the Batch Processing tab or place in a `datasets/` folder
4. The CSV should have columns like `message`, `text`, or similar

## Algorithm Overview

### O1: Bitap Fuzzy Layer
Implements bit-parallel approximate string matching with substitution-only Hamming distance. Catches obfuscated patterns like `pa$$word` → `password`.

### O2: Inverse Distance Weighting
Scans a window around each pattern match and weights booster/neutralizer terms inversely by their distance to the match. Closer risky terms increase the risk score; nearby benign terms reduce it.

### O3: Filipino Affix Stripping
Strips common Tagalog prefixes (e.g., `mag-`, `na-`, `pag-`) and suffixes (e.g., `-ing`, `-han`) to expose hidden phishing roots in Taglish variants.

### O4: URL Segment Risk Weighting
Parses URLs and applies category-specific risk weights to subdomains, SLDs, shorteners, and path parameters.

## Configuration

### Detection Thresholds

- **Risk Score Threshold** (default: 1.2) — Display alerts above this score
- **Review Signal Threshold** (default: 0.45) — Sensitivity for anomaly detection

### Pattern Settings

Edit these in [enhanced_aho/enhanced_aho_corasick.py](enhanced_aho/enhanced_aho_corasick.py):
- `max_errors` — Maximum Hamming distance for fuzzy matching (default: 1)
- `anomaly_threshold` — Threshold for heuristic anomaly scoring
- `boosters` / `neutralizers` — Context terms for proximity scoring
- `prefixes` / `suffixes` — Filipino affix lists

## Testing & Validation

The app includes a validation suite under the Algorithm Explorer tab:

- **True Positives** — Correctly detected phishing samples
- **False Negatives** — Missed phishing samples
- **True Negatives** — Correctly cleared safe samples
- **False Positives** — Incorrectly flagged safe samples

## Performance

- **Time Complexity (Build)**: O(m × k) where m = pattern count, k = pattern length
- **Time Complexity (Search)**: O(n + z) where n = text length, z = matches found
- **Space Complexity**: O(m × k × σ) where σ = alphabet size

## License

Apache 2.0

## References

- Original Aho-Corasick: [Aho & Corasick (1975)](https://dl.acm.org/doi/10.1145/360825.360855)
- Bitap Algorithm: [Baeza-Yates & Gonnet (1992)](https://www.researchgate.net/publication/2838360_A_New_Approach_to_Text_Searching)
- Filipino Grammar: [Schachter & Otanes (1972), Tagalog Reference Grammar](https://www.oapen.org/handle/20.500.12657/35171)
