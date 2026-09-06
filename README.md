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

### Viber Bot Integration

- **Webhook scanning** — Scans text messages sent directly to the bot or to a group where it is a member
- **Engine toggle** — Switch between enhanced and baseline detection with `/mode enhanced` or `/mode baseline`
- **Risk tiers** — Logs low-risk detections, sends warnings for moderate risk, and sends an acknowledgment card for high risk
- **Conversation escalation** — Escalates repeated Tier 2+ messages within the rolling conversation window
- **Comparison harness** — Evaluates baseline and enhanced engines on the same labeled CSV dataset

## Software / Libraries

| Software/Library | Version | Function/Purpose |
| --- | --- | --- |
| Python | 3.10+ | Core programming language for algorithm implementation, scanning, and evaluation |
| Python Standard Library | Built-in | Provides `re`, `collections`, and `pathlib` for the core Enhanced Aho-Corasick logic |
| Streamlit | 1.28+ | Web UI for dataset upload, batch scanning, and interactive demonstration |
| Pandas | 1.5+ | Loads and processes CSV datasets in the Streamlit batch interface |
| NumPy | 1.23+ | Supports numerical operations used by the visualization layer |
| Matplotlib | 3.7+ | Renders trie structure and transition path visualizations |
| NetworkX | 3.0+ | Builds graph-based Trie visualizations for the algorithm explorer |
| Graphviz | 0.21+ | Optional graph rendering support for structure visualization |

The core `EnhancedAhoCorasick` algorithm is dependency-free and runs with Python alone. The external libraries above are required only for the Streamlit visualization and batch-processing interface.

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
├── viber_bot/
│   ├── server.py                      # Flask webhook and risk-tier responses
│   ├── _bootstrap.py                  # Adds shared engine directories to sys.path
│   ├── baseline_aho_corasick.py      # Baseline adapter
│   ├── compare_engines.py            # Dataset comparison harness
│   └── test_local.py                 # Mocked webhook smoke test
├── datasets/                         # Local evaluation datasets
├── pyrightconfig.json                # Repository-wide Python import paths
├── enhanced_algo_pseudocode.md       # Algorithm documentation
└── README.md                         # This file
```

## Quick Start

### Prerequisites

- Python 3.10+
- Only Python is needed for the core algorithm
- Install the UI libraries only if you will run the Streamlit app

### Installation

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1
# Core algorithm only: no pip install required

# Streamlit UI:
pip install -r requirements.txt
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
- One pattern per line under each category
- Click "🔄 Update Patterns" to reload

## Viber Bot

The Viber integration is a bot webhook, not a passive monitor of existing
private conversations. It can scan messages sent directly to the bot or in a
group where the bot is a member. Its simulated blocking response is a warning
card that requires acknowledgment; it cannot lock Viber's native chat UI.

### Viber Installation and Configuration

```bash
cd viber_bot
pip install -r requirements.txt
```

Set `VIBER_AUTH_TOKEN` to the bot token, then start the server:

```bash
# macOS/Linux
export VIBER_AUTH_TOKEN="your-token-here"

# Windows PowerShell
$env:VIBER_AUTH_TOKEN = "your-token-here"

python server.py
```

The server listens on port `5000` by default. Set `PORT` to use another port.
For local development, expose the server through an HTTPS tunnel such as
`ngrok`, then register the public webhook URL:

```bash
python register_webhook.py https://your-public-host.example/webhook
```

Optional settings are `ENGINE_MODE` (`enhanced` or `baseline`),
`PATTERN_FILE`, and `ANOMALY_THRESHOLD` (default `0.45`). The bot stores its
local SQLite detection log in `viber_bot/detections.db`; this generated file
is excluded from Git.

### Viber Local Validation

Run the mocked webhook test without a Viber account or public URL:

```bash
python viber_bot/test_local.py
```

Run the baseline/enhanced comparison using the built-in sample data:

```bash
python viber_bot/compare_engines.py
```

For a labeled CSV, provide the text column, label column, and positive label:

```bash
python viber_bot/compare_engines.py \
	--csv path/to/dataset.csv \
	--text-col message \
	--label-col label \
	--positive-label phishing
```

## Dataset Integration

To use the Kaggle Email Phishing Dataset:
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

The core modules require only Python. The Viber smoke test additionally uses
the packages in `viber_bot/requirements.txt`, and the Streamlit interface uses
the root `requirements.txt`. Pyright resolves the shared `enhanced_aho/` and
`original_aho/` modules through the repository-root `pyrightconfig.json`.

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
