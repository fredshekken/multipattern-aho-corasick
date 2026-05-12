"""
Enhanced Aho-Corasick Phishing Detection Web Visualizer
========================================================
A Streamlit-based web application for phishing detection using the Enhanced Aho-Corasick algorithm.

Features:
- Real-time text scanning for phishing patterns
- CSV batch processing
- Visual Trie structure exploration
- Transition path visualization
- Risk score analysis with contextual scoring
- Explainability with detection process visualization
"""

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from pathlib import Path
import networkx as nx
from io import StringIO
import graphviz
from enhanced_aho_corasick import EnhancedAhoCorasick
from collections import defaultdict, deque
import numpy as np

# ═══════════════════════════════════════════════════════════════════════
#  PAGE CONFIGURATION & STYLING
# ═══════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="Rule-Based Phishing Signal Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
<style>
    .main {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    }
    
    .stTabs [data-baseweb="tab-list"] button {
        font-weight: bold;
        font-size: 16px;
        padding: 12px 24px;
    }
    
    .threat-card {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        font-weight: bold;
        margin: 10px 0;
        box-shadow: 0 4px 6px rgba(255, 107, 107, 0.3);
    }
    
    .safe-card {
        background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        font-weight: bold;
        margin: 10px 0;
        box-shadow: 0 4px 6px rgba(59, 130, 246, 0.25);
    }

    .warning-card {
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        font-weight: bold;
        margin: 10px 0;
        box-shadow: 0 4px 6px rgba(245, 158, 11, 0.3);
    }
    
    .risk-score {
        font-size: 28px;
        font-weight: bold;
        color: #ff6b6b;
        text-align: center;
        padding: 15px;
        background: rgba(255, 107, 107, 0.1);
        border-radius: 8px;
        margin: 10px 0;
    }
    
    .context-box {
        background: #f8f9fa;
        padding: 12px;
        border-left: 4px solid #ff6b6b;
        border-radius: 4px;
        font-style: italic;
        margin-top: 8px;
    }
    
    .header-section {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 30px;
        border-radius: 12px;
        color: white;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════
#  SESSION STATE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════

PATTERN_FILE = Path(__file__).with_name("default_patterns.txt")
DATASETS_DIR = Path(__file__).parent.parent / "datasets"


def discover_datasets():
    """Find all CSV files in the datasets folder."""
    if DATASETS_DIR.exists():
        return sorted([f.name for f in DATASETS_DIR.glob("*.csv")])
    return []


def load_dataset(filename):
    """Load a CSV dataset from the datasets folder."""
    dataset_path = DATASETS_DIR / filename
    if dataset_path.exists():
        return pd.read_csv(dataset_path)
    return None


def load_default_patterns():
    if PATTERN_FILE.exists():
        return EnhancedAhoCorasick.parse_pattern_groups(
            PATTERN_FILE.read_text(encoding="utf-8")
        )
    return {}

@st.cache_resource
def initialize_scanner():
    """Initialize the Enhanced Aho-Corasick scanner from the pattern file."""
    return EnhancedAhoCorasick.from_pattern_file(PATTERN_FILE, max_errors=1)

if 'scanner' not in st.session_state:
    st.session_state.scanner = initialize_scanner()

if 'last_scan_results' not in st.session_state:
    st.session_state.last_scan_results = None

if 'last_scan_text' not in st.session_state:
    st.session_state.last_scan_text = ""

if 'detection_details' not in st.session_state:
    st.session_state.detection_details = None

if 'validation_results' not in st.session_state:
    st.session_state.validation_results = None

if 'batch_df' not in st.session_state:
    st.session_state.batch_df = None

if 'batch_dataset_name' not in st.session_state:
    st.session_state.batch_dataset_name = None

# ═══════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS (Defined Before Use)
# ═══════════════════════════════════════════════════════════════════════

def draw_trie_visualization(scanner, ax, max_depth=4):
    """Create a visual representation of the trie structure."""
    
    # Build networkx graph from scanner's goto structure
    G = nx.DiGraph()
    
    # BFS to build graph
    visited = set()
    queue = deque([(0, 0, None)])  # (node_id, depth, parent)
    
    while queue:
        node_id, depth, parent = queue.popleft()
        
        if node_id in visited or depth > max_depth:
            continue
        
        visited.add(node_id)
        
        # Determine node color
        if node_id == 0:
            node_color = '#667eea'
            node_size = 800
            label = 'ROOT'
        elif scanner.out[node_id] > 0:
            node_color = '#ff6b6b'
            node_size = 600
            label = f'S{node_id}*'
        else:
            node_color = '#51cf66'
            node_size = 500
            label = f'S{node_id}'
        
        G.add_node(node_id, color=node_color, size=node_size, label=label)
        
        # Add edges
        if node_id < len(scanner.goto):
            for char, next_node in scanner.goto[node_id].items():
                if next_node not in visited:
                    G.add_edge(node_id, next_node, label=char)
                    queue.append((next_node, depth + 1, node_id))
    
    # Layout
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
    
    # Draw nodes
    node_colors = [G.nodes[node].get('color', '#51cf66') for node in G.nodes()]
    node_sizes = [G.nodes[node].get('size', 500) for node in G.nodes()]
    
    nx.draw_networkx_nodes(
        G, pos,
        node_color=node_colors,
        node_size=node_sizes,
        ax=ax,
        alpha=0.9
    )
    
    # Draw edges
    nx.draw_networkx_edges(
        G, pos,
        edge_color='#1a1a2e',
        width=2,
        ax=ax,
        arrowsize=20,
        arrowstyle='->'
    )
    
    # Draw labels
    labels = {node: G.nodes[node].get('label', str(node)) for node in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels, font_size=10, font_weight='bold', ax=ax)
    
    # Draw edge labels
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=8, ax=ax)
    
    ax.set_title("Trie Structure (Aho-Corasick Automaton)", fontsize=14, fontweight='bold')
    ax.axis('off')
    
    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#667eea', label='Root State'),
        Patch(facecolor='#ff6b6b', label='Terminal State (Match)'),
        Patch(facecolor='#51cf66', label='Intermediate State')
    ]
    ax.legend(handles=legend_elements, loc='upper left', fontsize=10)


def trace_text_path(scanner, text):
    """Trace the path taken through the trie for given text."""
    normalized = scanner._normalize(text)
    transitions = []
    
    curr_state = 0
    for i, (orig_char, norm_char) in enumerate(zip(text, normalized)):
        next_state = scanner.goto[curr_state].get(norm_char, 0)
        
        # Check for matches
        match_patterns = []
        if scanner.out[next_state] > 0:
            for j, pattern in enumerate(scanner.patterns):
                if scanner.out[next_state] & (1 << j):
                    match_patterns.append(pattern)
        
        transitions.append({
            'step': i + 1,
            'original_char': orig_char,
            'normalized_char': norm_char,
            'state': next_state,
            'match': bool(match_patterns),
            'match_patterns': match_patterns
        })
        
        curr_state = next_state
    
    return transitions


def visualize_transition_path(scanner, transitions, text, ax):
    """Visualize the transition path through the trie."""
    
    steps = len(transitions)
    
    # Create visualization
    ax.set_xlim(-0.5, steps + 0.5)
    ax.set_ylim(-1, 3)
    
    # Draw character line
    for i, trans in enumerate(transitions):
        x = i + 0.5
        
        # Character box
        color = '#ff6b6b' if trans['match'] else '#51cf66'
        rect = FancyBboxPatch((x - 0.35, 2), 0.7, 0.6,
                             boxstyle="round,pad=0.05",
                             edgecolor='black',
                             facecolor=color,
                             alpha=0.7)
        ax.add_patch(rect)
        
        ax.text(x, 2.3, trans['original_char'], ha='center', va='center',
               fontweight='bold', fontsize=12)
        ax.text(x, 1.5, f"→ '{trans['normalized_char']}'", ha='center', va='center',
               fontsize=10, style='italic')
        ax.text(x, 0.8, f"S{trans['state']}", ha='center', va='center',
               fontsize=9, fontweight='bold')
        
        if trans['match']:
            ax.text(x, 0, f"✓ {', '.join(trans['match_patterns'][:2])}", 
                   ha='center', va='center', fontsize=8, color='#ff6b6b', fontweight='bold')
        
        if i < steps - 1:
            ax.arrow(x + 0.35, 1, 0.3, 0, head_width=0.1, head_length=0.1, fc='black', ec='black')
    
    ax.set_title(f"Transition Path for: '{text}'", fontsize=14, fontweight='bold')
    ax.axis('off')


def calculate_avg_pattern_length(patterns):
    """Calculate average pattern length."""
    if not patterns:
        return 0
    return sum(len(p) for p in patterns) / len(patterns)


def filter_visible_signals(results, threshold):
    return [
        item for item in results
        if item.get('match_type') == 'anomaly' or item.get('risk_score', 0) >= threshold
    ]

# ═══════════════════════════════════════════════════════════════════════
#  HEADER SECTION
# ═══════════════════════════════════════════════════════════════════════

st.markdown("""
<div class="header-section">
    <h1>🛡️ Rule-Based Phishing Signal Scanner</h1>
    <p style="font-size: 18px; margin-top: 10px;">
        Heuristic phishing signal scanning with normalization, contextual scoring, and review-mode fallbacks
    </p>
    <p style="font-size: 14px; opacity: 0.9; margin-top: 10px;">
        Rule-based detections are signals, not a guarantee of safety or malicious intent
    </p>
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════
#  SIDEBAR - CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Pattern Management
    st.subheader("Pattern Dictionary")
    pattern_upload = st.file_uploader(
        "Load patterns from a .txt file",
        type=["txt"],
        help="One pattern per line; uploaded contents seed the live dictionary"
    )

    if pattern_upload is not None:
        pattern_seed_text = pattern_upload.getvalue().decode("utf-8")
    else:
        pattern_seed_text = EnhancedAhoCorasick.format_pattern_groups(
            st.session_state.scanner.pattern_groups
        )

    custom_patterns = st.text_area(
        "Edit categorized phishing rules:",
        value=pattern_seed_text,
        height=200,
        help="Use [category: name] headers with one pattern per line under each section."
    )
    
    if st.button("🔄 Update Patterns", key="update_patterns"):
        pattern_groups = EnhancedAhoCorasick.parse_pattern_groups(custom_patterns)
        st.session_state.scanner = EnhancedAhoCorasick(pattern_groups, max_errors=1)
        st.session_state.scanner.save_patterns(PATTERN_FILE)
        st.success(f"✅ Updated! {len(st.session_state.scanner.patterns)} patterns loaded in {len(st.session_state.scanner.pattern_groups)} categories")
        st.rerun()

    category_counts = {
        category: len(patterns)
        for category, patterns in st.session_state.scanner.pattern_groups.items()
    }

    st.caption(f"Categories: {len(category_counts)} | Patterns: {len(st.session_state.scanner.patterns)}")
    st.dataframe(
        pd.DataFrame(
            {
                "Category": list(category_counts.keys()),
                "Count": list(category_counts.values()),
            }
        ),
        use_container_width=True,
        hide_index=True,
    )

    with st.expander("Add pattern to category", expanded=False):
        existing_categories = list(st.session_state.scanner.pattern_groups.keys())
        target_category = st.selectbox(
            "Category",
            options=[*existing_categories, "+ New category"],
            key="add_pattern_category_select",
        )
        new_category_name = ""
        if target_category == "+ New category":
            new_category_name = st.text_input(
                "New category name",
                key="add_pattern_new_category",
                placeholder="brand_terms",
            )

        new_pattern_value = st.text_input(
            "Pattern to add",
            key="add_pattern_value",
            placeholder="otp",
        )

        if st.button("➕ Add Pattern", key="add_pattern_btn", use_container_width=True):
            category_name = new_category_name.strip() if target_category == "+ New category" else target_category
            if not category_name:
                st.warning("Please choose or enter a category name.")
            elif not new_pattern_value.strip():
                st.warning("Please enter a pattern to add.")
            else:
                st.session_state.scanner.add_patterns([new_pattern_value.strip()], category=category_name)
                st.session_state.scanner.save_patterns(PATTERN_FILE)
                st.success(f"Added '{new_pattern_value.strip()}' to {category_name}.")
                st.rerun()
    
    st.divider()
    
    # Detection Thresholds
    st.subheader("Detection Settings")
    risk_threshold = st.slider(
        "Risk Score Threshold",
        min_value=0.5,
        max_value=3.0,
        value=1.2,
        step=0.1,
        help="Display alerts with risk score >= threshold; review signals can still appear below this"
    )

    anomaly_threshold = st.slider(
        "Review Signal Threshold",
        min_value=0.10,
        max_value=1.00,
        value=0.45,
        step=0.05,
        help="Lower values catch more unmatched suspicious messages; higher values are stricter"
    )
    
    st.divider()
    
    # Algorithm Information
    st.subheader("Algorithm Overview")
    with st.expander("📖 How it works"):
        st.markdown("""
        **O1: Bitap Fuzzy Layer**
        - Uses bit-parallel matching to catch near-miss variants (e.g., 1 character error)
        - Complements trie exact matches with resilient fuzzy detection

        **O2: Inverse Distance Weighting (IDW)**
        - Scores booster and neutralizer terms by proximity to each detected pattern
        - Closer risky terms increase score more; nearby benign terms reduce score

        **O3: Filipino Affix Stripping**
        - Strips common prefixes/suffixes from Taglish forms (e.g., i-gcash, gcashin)
        - Detects root phishing terms hidden in morphological variants

        **O4: URL Segmentation Risk**
        - Parses URL segments (subdomain, SLD, path, query) before applying risk weights
        - Flags shorteners and subdomain spoofing more aggressively than legitimate SLD matches

        **Fallback Review Mode**
        - Surfaces phishing-like language even when no dictionary entry matches
        - Labels uncertain cases as review signals instead of asserting safety

        **Categorized Rule Base**
        - Stores patterns in named groups such as brand, action, and financial indicators
        - Keeps the rule base editable without turning it into a hardcoded list
        """)

# ═══════════════════════════════════════════════════════════════════════
#  MAIN CONTENT - TABS
# ═══════════════════════════════════════════════════════════════════════

tab1, tab2, tab3 = st.tabs(["🔍 Single Message Scan", "📊 Batch Processing", "📚 Algorithm Explorer"])

# ═══════════════════════════════════════════════════════════════════════
#  TAB 1: SINGLE MESSAGE SCAN
# ═══════════════════════════════════════════════════════════════════════

with tab1:
    st.header("Manual Message Scanner")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        user_input = st.text_area(
            "📝 Enter message to scan:",
            placeholder="Paste suspicious message here...",
            height=150,
            key="message_input"
        )
    
    with col2:
        st.write("**Quick Actions**")
        if st.button("🔍 Scan Message", key="scan_btn", use_container_width=True):
            if user_input.strip():
                st.session_state.last_scan_text = user_input
                st.session_state.last_scan_results = st.session_state.scanner.enhanced_search(
                    user_input,
                    anomaly_threshold=anomaly_threshold
                )
                st.rerun()
            else:
                st.warning("Please enter a message to scan")
        
        if st.button("🗑️ Clear", key="clear_btn", use_container_width=True):
            st.session_state.last_scan_text = ""
            st.session_state.last_scan_results = None
            st.rerun()
    
    st.divider()
    
    # ─────────────────────────────────────────────────────────────────
    #  SCAN RESULTS DISPLAY
    # ─────────────────────────────────────────────────────────────────
    
    if st.session_state.last_scan_results is not None:
        raw_results = st.session_state.last_scan_results
        results = filter_visible_signals(raw_results, risk_threshold)
        threat_results = [r for r in results if r.get('match_type') != 'anomaly']
        review_results = [r for r in results if r.get('match_type') == 'anomaly']
        
        if results:
            # THREATS / REVIEW SIGNALS DETECTED
            if threat_results:
                st.markdown('<div class="threat-card"><h3>🚨 THREAT SIGNALS DETECTED</h3></div>', 
                           unsafe_allow_html=True)
            else:
                st.markdown('<div class="warning-card"><h3>⚠️ REVIEW SIGNALS DETECTED</h3></div>', 
                           unsafe_allow_html=True)
            
            for i, threat in enumerate(results):
                with st.container():
                    col_risk, col_content = st.columns([1, 3])
                    
                    with col_risk:
                        st.markdown(f"""
                        <div class="risk-score">
                            {threat['risk_score']:.2f}<br>
                            <span style="font-size: 14px;">Risk Score</span>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col_content:
                        st.markdown(f"### {threat['alert']}")
                        detail_col1, detail_col2 = st.columns(2)
                        with detail_col1:
                            st.caption(f"Match Type: {threat.get('match_type', 'n/a').upper()}")
                        with detail_col2:
                            st.caption(f"Error Count: {threat.get('error_count', 0)}")
                        st.markdown(f"""
                        <div class="context-box">
                            <strong>Context:</strong> "{threat['context']}"
                        </div>
                        """, unsafe_allow_html=True)
                        if threat.get('match_type') == 'anomaly' and threat.get('signals'):
                            st.caption(f"Heuristic signals: {', '.join(threat['signals'])}")
                
                if i < len(results) - 1:
                    st.divider()
            
            st.divider()
            
            # Expound Results Button
            col1, col2, col3 = st.columns([1, 1, 1])
            
            if len(raw_results) > len(results):
                st.info(
                    f"{len(raw_results) - len(results)} signal(s) hidden by the current threshold ({risk_threshold:.1f})."
                )

            with col1:
                if st.button("🔬 View Detection Process", key="expound_btn", use_container_width=True):
                    st.session_state.detection_details = {
                        'text': st.session_state.last_scan_text,
                        'results': raw_results
                    }
            
            with col2:
                if st.button("📥 Export Results", key="export_btn", use_container_width=True):
                    export_data = pd.DataFrame([
                        {
                            'Risk Score': r['risk_score'],
                            'Alert': r['alert'],
                            'Context': r['context']
                        }
                        for r in results
                    ])
                    csv = export_data.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name="phishing_detections.csv",
                        mime="text/csv"
                    )
            
            with col3:
                st.write("")  # Spacer
        
        else:
            # NO THREATS DETECTED
            if raw_results:
                st.markdown("""
                <div class="safe-card">
                    <h3>ℹ️ No Detections Above Current Threshold</h3>
                    <p>There were rule-based signals, but none cleared the current display threshold.</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="safe-card">
                    <h3>ℹ️ No Known Threats Matched Current Rules</h3>
                    <p>This message did not trigger the current rule set.</p>
                </div>
                """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════
#  TAB 2: BATCH PROCESSING
# ═══════════════════════════════════════════════════════════════════════

with tab2:
    st.header("Batch CSV Processing")
    
    # ─────────────────────────────────────────────────────────────────
    #  QUICK-SELECT SAMPLE DATASETS
    # ─────────────────────────────────────────────────────────────────
    
    st.subheader("📂 Quick-Load Datasets")
    available_datasets = discover_datasets()
    
    if available_datasets:
        col_ds1, col_ds2, col_ds3 = st.columns(len(available_datasets) + 1 if len(available_datasets) < 3 else 3)
        cols = [col_ds1, col_ds2, col_ds3]
        
        for idx, dataset_name in enumerate(available_datasets[:3]):
            with cols[idx]:
                if st.button(f"📊 {dataset_name.replace('.csv', '')}", use_container_width=True):
                    df = load_dataset(dataset_name)
                    if df is not None:
                        st.session_state.batch_df = df
                        st.session_state.batch_dataset_name = dataset_name
                        st.success(f"✅ Loaded {dataset_name} ({len(df)} rows)")
        
        st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Upload CSV File")
        uploaded_file = st.file_uploader(
            "Choose a CSV file",
            type="csv",
            help="CSV should have a 'message' or 'text' column"
        )
    
    with col2:
        st.subheader("Sample Format")
        sample_data = {
            'id': [1, 2, 3],
            'message': [
                'Verify your G-C@sh account',
                'Official bank notification',
                'Cl1ck here to claim prize'
            ]
        }
        st.dataframe(pd.DataFrame(sample_data), use_container_width=True)
    
    # Use uploaded file or session dataset
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.session_state.batch_df = df
        st.session_state.batch_dataset_name = uploaded_file.name
    elif 'batch_df' in st.session_state:
        df = st.session_state.batch_df
    else:
        df = None
    
    if df is not None:
        try:
            st.success(f"✅ Loaded {len(df)} rows")
            
            # Detect column name
            text_columns = [col for col in df.columns if 'message' in col.lower() or 'text' in col.lower()]
            
            if not text_columns:
                st.error("CSV must contain a 'message' or 'text' column")
            else:
                text_col = text_columns[0]
                
                if st.button("🔍 Scan All Messages", use_container_width=True):
                    progress_bar = st.progress(0)
                    results_list = []
                    
                    for idx, row in df.iterrows():
                        message = str(row[text_col])
                        threats = st.session_state.scanner.enhanced_search(
                            message,
                            anomaly_threshold=anomaly_threshold
                        )
                        visible_signals = filter_visible_signals(threats, risk_threshold)
                        has_threat = any(item.get('match_type') != 'anomaly' for item in visible_signals)
                        has_review = any(item.get('match_type') == 'anomaly' for item in visible_signals)

                        if has_threat:
                            status = '🚨 THREAT'
                        elif has_review:
                            status = '⚠️ REVIEW'
                        else:
                            status = '✅ CLEAR'
                        
                        results_list.append({
                            'Row': idx + 1,
                            'Message': message[:50] + '...' if len(message) > 50 else message,
                            'Signals Found': len(visible_signals),
                            'Max Risk Score': max([t['risk_score'] for t in visible_signals]) if visible_signals else 0.0,
                            'Status': status
                        })
                        
                        progress_bar.progress((idx + 1) / len(df))
                    
                    results_df = pd.DataFrame(results_list)
                    
                    st.divider()
                    st.subheader("📊 Batch Scan Results")
                    st.dataframe(results_df, use_container_width=True)
                    
                    # Summary Statistics
                    col1, col2, col3, col4 = st.columns(4)
                    
                    threats_count = results_df[results_df['Status'] == '🚨 THREAT'].shape[0]
                    review_count = results_df[results_df['Status'] == '⚠️ REVIEW'].shape[0]
                    clear_count = results_df[results_df['Status'] == '✅ CLEAR'].shape[0]
                    
                    with col1:
                        st.metric("Total Messages", len(results_df))
                    with col2:
                        st.metric("🚨 Threats", threats_count)
                    with col3:
                        st.metric("⚠️ Review", review_count)
                    with col4:
                        threat_rate = (threats_count / len(results_df) * 100) if len(results_df) > 0 else 0
                        st.metric("Threat Rate", f"{threat_rate:.1f}%")

                    st.caption(f"Clear messages: {clear_count}")
                    
                    # Download results
                    csv_export = results_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Results CSV",
                        data=csv_export,
                        file_name="batch_scan_results.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
        
        except Exception as e:
            st.error(f"Error processing file: {str(e)}")

# ═══════════════════════════════════════════════════════════════════════
#  TAB 3: ALGORITHM EXPLORER
# ═══════════════════════════════════════════════════════════════════════

with tab3:
    st.header("Algorithm Structure Explorer")
    st.caption("Validation checks below help track false negatives and false positives in the current rule set.")

    if st.button("🧪 Run Validation Suite", key="run_validation_suite"):
        st.session_state.validation_results = st.session_state.scanner.run_validation_suite(
            anomaly_threshold=anomaly_threshold
        )

    if st.session_state.validation_results:
        validation = st.session_state.validation_results
        summary = validation['summary']
        val_col1, val_col2, val_col3, val_col4 = st.columns(4)
        with val_col1:
            st.metric("True Positives", summary['true_positive'])
        with val_col2:
            st.metric("False Negatives", summary['false_negative'])
        with val_col3:
            st.metric("True Negatives", summary['true_negative'])
        with val_col4:
            st.metric("False Positives", summary['false_positive'])

        with st.expander("Validation cases", expanded=False):
            for case in validation['cases']:
                st.markdown(
                    f"- **{case['expected'].title()}** | Detected: {case['detected']} | Max Risk: {case['max_risk']:.2f} | {case['sample']}"
                )
    
    explorer_tab1, explorer_tab2, explorer_tab3 = st.tabs(
        ["🌳 Trie Structure", "🔗 Transition Paths", "📊 Statistics"]
    )
    
    # ─────────────────────────────────────────────────────────────────
    #  TAB 3.1: TRIE STRUCTURE VISUALIZATION
    # ─────────────────────────────────────────────────────────────────
    
    with explorer_tab1:
        st.subheader("Trie Data Structure")
        st.markdown("""
        The Trie structure is built during Step 1 (Normalization). Each node represents a state,
        and edges represent character transitions. Terminal nodes (with checkmarks) represent
        valid pattern matches.
        """)

        category_counts = {
            category: len(patterns)
            for category, patterns in st.session_state.scanner.pattern_groups.items()
        }

        overview_col1, overview_col2, overview_col3 = st.columns(3)
        with overview_col1:
            st.metric("Categories", len(category_counts))
        with overview_col2:
            st.metric("Patterns", len(st.session_state.scanner.patterns))
        with overview_col3:
            st.metric("Largest Category", max(category_counts.values()) if category_counts else 0)

        st.dataframe(
            pd.DataFrame(
                {
                    "Category": list(category_counts.keys()),
                    "Count": list(category_counts.values()),
                }
            ),
            use_container_width=True,
            hide_index=True,
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            show_trie = st.checkbox("🖼️ Visualize Trie Structure", value=False)
        
        with col2:
            max_depth = st.slider("Max depth to show", 1, 8, 4)
        
        if show_trie:
            fig, ax = plt.subplots(figsize=(14, 8), dpi=100)
            
            try:
                draw_trie_visualization(
                    st.session_state.scanner,
                    ax=ax,
                    max_depth=max_depth
                )
                st.pyplot(fig, use_container_width=True)
            except Exception as e:
                st.error(f"Visualization error: {str(e)}")
        
        # Trie Statistics
        st.divider()
        st.subheader("📈 Trie Statistics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total States", st.session_state.scanner.states_count)
        
        with col2:
            st.metric("Patterns", len(st.session_state.scanner.patterns))
        
        with col3:
            st.metric("Root Children", len(st.session_state.scanner.goto[0]))
        
        with col4:
            avg_depth = calculate_avg_pattern_length(st.session_state.scanner.patterns)
            st.metric("Avg Pattern Length", f"{avg_depth:.1f}")
        
        # Pattern List
        st.divider()
        st.subheader("Pattern Dictionary")
        pattern_df = pd.DataFrame({
            'Category': [
                category
                for category, patterns in st.session_state.scanner.pattern_groups.items()
                for _ in patterns
            ],
            'Pattern': st.session_state.scanner.patterns,
            'Normalized': [st.session_state.scanner._normalize(p) for p in st.session_state.scanner.patterns]
        })
        st.dataframe(pattern_df, use_container_width=True)
    
    # ─────────────────────────────────────────────────────────────────
    #  TAB 3.2: TRANSITION PATHS
    # ─────────────────────────────────────────────────────────────────
    
    with explorer_tab2:
        st.subheader("Step-by-Step Transition Path")
        st.markdown("""
        This section shows how the algorithm traverses the Trie as it processes each character.
        Watch the active state change as each character is processed, and see how normalization
        affects the path taken.
        """)
        
        path_text = st.text_input(
            "Enter text to trace:",
            value="gcash",
            placeholder="Type a word to see its traversal path..."
        )
        
        if path_text:
            col1, col2 = st.columns(2)
            
            with col1:
                show_steps = st.checkbox("Show Step-by-Step Breakdown", value=True)
            
            with col2:
                show_visual = st.checkbox("Show Visual Path", value=True)
            
            # Get transition details
            transitions = trace_text_path(st.session_state.scanner, path_text)
            
            if show_steps:
                st.subheader("Detailed Steps")
                for i, step in enumerate(transitions):
                    with st.container():
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            st.metric("Step", i + 1)
                        with col2:
                            st.metric("Input Char", step['original_char'])
                        with col3:
                            st.metric("Normalized", step['normalized_char'])
                        with col4:
                            st.metric("State", step['state'])
                        
                        if step['match']:
                            st.success(f"✅ Match detected: {step['match_patterns']}")
                    
                    if i < len(transitions) - 1:
                        st.divider()
            
            if show_visual:
                st.divider()
                st.subheader("Visual Transition Path")
                
                fig, ax = plt.subplots(figsize=(12, 6), dpi=100)
                
                try:
                    visualize_transition_path(
                        st.session_state.scanner,
                        transitions,
                        path_text,
                        ax=ax
                    )
                    st.pyplot(fig, use_container_width=True)
                except Exception as e:
                    st.error(f"Visualization error: {str(e)}")
    
    # ─────────────────────────────────────────────────────────────────
    #  TAB 3.3: ALGORITHM STATISTICS
    # ─────────────────────────────────────────────────────────────────
    
    with explorer_tab3:
        st.subheader("Algorithm Complexity Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric(
                "Time Complexity (Build)",
                "O(m × k)",
                delta="m=pattern count, k=pattern length"
            )
            st.metric(
                "Time Complexity (Search)",
                "O(n + z)",
                delta="n=text length, z=matches found"
            )
        
        with col2:
            st.metric(
                "Space Complexity",
                "O(m × k × σ)",
                delta="σ=alphabet size"
            )
            st.metric(
                "Preprocessing",
                "Single Pass"
            )
        
        st.divider()
        st.subheader("Enhancement Layers")
        
        enhancement_data = {
            'Layer': ['O1', 'O2', 'O3', 'O4'],
            'Feature': [
                'Bitap Fuzzy Matching',
                'IDW Proximity Scoring',
                'Affix-Aware Root Detection',
                'URL Segment Risk Weighting'
            ],
            'Purpose': [
                'Catch near-match obfuscations with up to max_errors tolerance',
                'Weight boosters/neutralizers by distance to the matched index',
                'Strip Filipino affixes to recover hidden phishing roots',
                'Score URL context by segment (shortener/subdomain/path/query/SLD)'
            ]
        }
        
        st.dataframe(pd.DataFrame(enhancement_data), use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════
#  DETECTION PROCESS VISUALIZATION (Modal-like)
# ═══════════════════════════════════════════════════════════════════════

if st.session_state.detection_details:
    st.divider()
    st.header("🔬 Detailed Detection Process")
    
    with st.expander("Click to expand detection analysis", expanded=True):
        text = st.session_state.detection_details['text']
        results = st.session_state.detection_details['results']
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Original Message")
            st.text_area(
                "Input text:",
                value=text,
                height=100,
                disabled=True,
                label_visibility="collapsed"
            )
            
            st.subheader("Normalized Text")
            normalized = st.session_state.scanner._normalize(text)
            st.text_area(
                "Normalized:",
                value=normalized,
                height=100,
                disabled=True,
                label_visibility="collapsed"
            )
        
        with col2:
            st.subheader("Detection Summary")
            
            for threat in results:
                with st.container():
                    st.markdown(f"**Risk Score: {threat['risk_score']:.2f}**")
                    pattern_name = threat['alert'].split("'")[1] if "'" in threat['alert'] else 'Unknown'
                    st.markdown(f"*Pattern:* `{pattern_name}`")
                    st.markdown(f"*Match Type:* {threat.get('match_type', 'n/a')} | *Error Count:* {threat.get('error_count', 0)}")
                    st.markdown(f"*Context:* {threat['context']}")
                    if threat.get('match_type') == 'anomaly' and threat.get('signals'):
                        st.caption(f"Heuristic signals: {', '.join(threat['signals'])}")
            
            st.subheader("Transformation Map")
            st.markdown("**Normalization Map**")
            st.json(st.session_state.scanner.norm_map)
            st.markdown("**Phonetic Map**")
            st.json(st.session_state.scanner.phonetic_map)
        
        # Visualize normalization effects
        st.divider()
        st.subheader("Normalization Effects")
        
        fig, ax = plt.subplots(figsize=(12, 4), dpi=100)
        
        # Create character mapping visualization
        chars_in_text = list(set(text.lower()))
        norm_chars = [st.session_state.scanner._normalize(c) for c in chars_in_text]
        
        y_pos = np.arange(len(chars_in_text))
        colors = ['#ff6b6b' if c != n else '#51cf66' for c, n in zip(chars_in_text, norm_chars)]
        
        ax.barh(y_pos, [1]*len(chars_in_text), color=colors, alpha=0.7)
        ax.set_yticks(y_pos)
        ax.set_yticklabels([f"'{c}' → '{n}'" for c, n in zip(chars_in_text, norm_chars)])
        ax.set_xlabel("Transformation Applied")
        ax.set_title("Character Normalization Effects in Your Message", fontsize=14, fontweight='bold')
        ax.set_xlim(0, 1.2)
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#ff6b6b', alpha=0.7, label='Obfuscation Detected'),
            Patch(facecolor='#51cf66', alpha=0.7, label='No Change Needed')
        ]
        ax.legend(handles=legend_elements, loc='lower right')
        
        st.pyplot(fig, use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════
#  FOOTER
# ═══════════════════════════════════════════════════════════════════════

st.divider()
st.markdown("""
<div style="text-align: center; color: #666; font-size: 12px;">
    <p>🛡️ Enhanced Aho-Corasick Phishing Detection System</p>
    <p>Built with Streamlit | Powered by Advanced Pattern Matching & Contextual Analysis</p>
</div>
""", unsafe_allow_html=True)
