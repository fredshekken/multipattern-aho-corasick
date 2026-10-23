import pandas as pd
from enhanced_aho_corasick import EnhancedAhoCorasick

# File paths
PATTERNS_FILE = "default_patterns.txt"
CSV_PATH = r"C:\Projects\PLM-CS Projects\aho-corasick\viber_bot\uploaded_datasets\4ce8fec37e73_philippine_sms_cleaned.csv"

# I-initialize ang engine gamit ang parameters ng inyong study
engine = EnhancedAhoCorasick.from_pattern_file(
    PATTERNS_FILE,
    max_errors=1,
    anomaly_threshold=0.45,
    exact_threshold=1.2,
    fuzzy_threshold=1.2,
    affix_threshold=1.05,
    warning_threshold=1.142,
    min_evidence=0
)

# Load dataset
df = pd.read_csv(CSV_PATH)

# Hanapin ang label column at text column
label_col = [c for c in df.columns if c.lower() in ['label', 'class', 'target']][0]
text_col = [c for c in df.columns if c.lower() in ['text', 'message', 'sms', 'clean_text', 'content']][0]

# Salain ang legitimate messages (ham / 0)
# Sa karaniwang datasets: 0 = Ham/Legitimate, 1 = Spam/Phishing
df_legit = df[df[label_col].isin([0, '0', 'ham', 'legit', 'benign'])].copy()

total_legit = len(df_legit)
print(f"Loaded legitimate dataset: {total_legit} messages (Target: 4,516)")
print(f"Scanning messages using text column: '{text_col}'...")

counts = {0: 0, 1: 0, 2: 0, 3: 0}

for idx, text in enumerate(df_legit[text_col]):
    msg = str(text) if pd.notna(text) else ""
    assessment = engine.assess_message(msg)
    tier = assessment["action_tier"]
    counts[tier] += 1

t0 = counts[0]
t1 = counts[1]
t2 = counts[2]
t3 = counts[3]

total_fp = t1 + t2 + t3

print("\n" + "="*52)
print("=== OFFICIAL OPERATIONAL RATES (CHAPTER 4) ===")
print("="*52)
print(f"Total Legitimate Messages (N):     {total_legit}")
print(f"Tier 0 (True Negatives):            {t0} ({t0/total_legit*100:.2f}%)")
print(f"Tier 1 (Silent Clearance):          {t1} ({t1/total_legit*100:.2f}%)")
print(f"Tier 2 (Passive Review Rate):       {t2} ({t2/total_legit*100:.2f}%)")
print(f"Tier 3 (Active Interruption Rate):  {t3} ({t3/total_legit*100:.2f}%)")
print("-" * 52)
print(f"Total Algorithmic False Positives: {total_fp}")
print(f"Algorithmic FPR:                   {total_fp/total_legit*100:.2f}%")
print("="*52)