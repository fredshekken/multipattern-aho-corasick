import os
import pandas as pd

datasets_dir = r"C:\Projects\PLM-CS Projects\aho-corasick\datasets"

for fname in os.listdir(datasets_dir):
    if fname.endswith(".csv"):
        fpath = os.path.join(datasets_dir, fname)
        try:
            df = pd.read_csv(fpath)
            print(f"File: {fname} | Total Rows: {len(df)} | Columns: {list(df.columns)}")
            
            # Check label counts kung may label column
            for col in ['label', 'Label', 'class', 'Class', 'target']:
                if col in df.columns:
                    print(f"   Value counts for '{col}':\n{df[col].value_counts().to_dict()}")
        except Exception as e:
            print(f"Error reading {fname}: {e}")
        print("-" * 50)