"""
Split the labeled dataset ONCE into a validation file and a test file.

Why: the anomaly threshold (Table 4.2) must be chosen on data that the
final evaluation (Table 4.1, Table 4.3, operational rates) never sees.

How:
  - Messages with the same text (ignoring case and extra spaces) are kept
    together, so a duplicate can never land on both sides.
  - The split is stratified: the phishing/legit ratio is the same in both files.
  - A fixed seed (42) makes the split reproducible.

Usage (from viber_bot):
    python split_dataset.py --csv uploaded_datasets/da24fda71670_philippine_sms_cleaned.csv

Outputs (next to the input file):
    sms_validation.csv   (default 20%)  -> use ONLY for calibrate_thresholds.py
    sms_test.csv         (default 80%)  -> use for compare_engines, operational_rates, benchmark_speed
"""

import argparse
import csv
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

csv.field_size_limit(sys.maxsize)


def norm(text):
    return " ".join(text.split()).casefold()


def main():
    ap = argparse.ArgumentParser(description="Make a fixed validation/test split")
    ap.add_argument("--csv", required=True)
    ap.add_argument("--text-col", default="text")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--positive-label", default="1")
    ap.add_argument("--val-frac", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", default=None,
                    help="Folder for the two output files (default: same folder as --csv)")
    args = ap.parse_args()

    src = Path(args.csv)
    with open(src, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    if not fieldnames:
        sys.exit(f"{src} has no header row")

    pos_label = str(args.positive_label).strip().lower()

    def is_pos(row):
        return str(row.get(args.label_col, "")).strip().lower() == pos_label

    # Group rows that share the same text.
    groups = defaultdict(list)
    for row in rows:
        groups[norm(row.get(args.text_col, ""))].append(row)

    # Each group goes to the stratum of its majority label.
    pos_keys, neg_keys = [], []
    for key, members in groups.items():
        n_pos = sum(is_pos(r) for r in members)
        (pos_keys if n_pos * 2 >= len(members) else neg_keys).append(key)

    rng = random.Random(args.seed)
    pos_keys.sort()
    neg_keys.sort()
    rng.shuffle(pos_keys)
    rng.shuffle(neg_keys)

    def take_validation(keys):
        """Pick groups for validation until ~val_frac of the ROWS are reached."""
        total_rows = sum(len(groups[k]) for k in keys)
        target = round(total_rows * args.val_frac)
        val, test, count = [], [], 0
        for k in keys:
            if count < target:
                val.append(k)
                count += len(groups[k])
            else:
                test.append(k)
        return val, test

    pv, pt = take_validation(pos_keys)
    nv, nt = take_validation(neg_keys)

    val_rows = [r for k in pv + nv for r in groups[k]]
    test_rows = [r for k in pt + nt for r in groups[k]]
    rng.shuffle(val_rows)
    rng.shuffle(test_rows)

    out_dir = Path(args.out_dir) if args.out_dir else src.parent
    val_path = out_dir / "sms_validation.csv"
    test_path = out_dir / "sms_test.csv"
    for path, data in ((val_path, val_rows), (test_path, test_rows)):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(data)

    # Report + safety checks
    def describe(name, data):
        c = Counter(is_pos(r) for r in data)
        n = len(data)
        print(f"  {name:<11} {n:>5} rows | phishing {c[True]:>5} ({c[True] / n:.2%}) | legit {c[False]:>5}")

    print(f"Source: {src} ({len(rows)} rows, {len(groups)} unique texts)")
    describe("validation", val_rows)
    describe("test", test_rows)
    overlap = {norm(r[args.text_col]) for r in val_rows} & {norm(r[args.text_col]) for r in test_rows}
    print(f"  overlap between validation and test: {len(overlap)} texts")
    assert len(val_rows) + len(test_rows) == len(rows), "row count mismatch"
    assert not overlap, "validation and test share texts"
    print(f"\nSaved:\n  {val_path}\n  {test_path}")


if __name__ == "__main__":
    main()