"""
Threshold calibration for the Enhanced Aho-Corasick engine.

The engine has no gradient-trained parameters — it's a rule-based /
heuristic system. The closest equivalent to "training" here is
calibrating its tunable thresholds (anomaly_threshold, exact_threshold,
fuzzy_threshold, affix_threshold) against labeled data.

To keep this methodologically honest for Chapter 4, this script follows
the standard train/validation/test discipline:

    1. Split the labeled dataset into train / validation / test
       (the "train" split isn't actually used by this rule-based engine,
       but is kept for symmetry and in case you add ML components later).
    2. Grid-search candidate threshold combinations, scoring each ONLY
       on the validation split.
    3. Pick the best combination (by F1, or by "best recall subject to
       FPR <= max_fpr" if you care more about false positives).
    4. Report final metrics using that chosen combination ONLY on the
       untouched test split — these are the numbers that go in the
       thesis, not the validation numbers used to pick the config.

Usage:
    python calibrate_thresholds.py --csv ../datasets/phishing_email.csv \
        --text-col text_combined --label-col label --positive-label 1 \
        --pattern-file ../enhanced_aho/default_patterns.txt \
        --sample-size 6000 --max-text-chars 20000
"""

import argparse
import csv
import random
import sys
import time

csv.field_size_limit(sys.maxsize)

import _bootstrap  # noqa: F401
from enhanced_aho_corasick import EnhancedAhoCorasick


def load_and_split(csv_path, text_col, label_col, positive_label,
                    sample_size=None, max_text_chars=None, seed=42,
                    train_frac=0.6, val_frac=0.2):
    """Stratified train/val/test split (test_frac = 1 - train_frac - val_frac)."""
    pos, neg = [], []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get(text_col, "")
            if max_text_chars is not None and len(text) > max_text_chars:
                text = text[:max_text_chars]
            label = str(row.get(label_col, "")).strip().lower()
            is_phishing = label == str(positive_label).strip().lower()
            (pos if is_phishing else neg).append(text)

    rng = random.Random(seed)
    rng.shuffle(pos)
    rng.shuffle(neg)

    if sample_size is not None:
        # keep the same phishing:legit ratio as the full dataset
        frac = sample_size / (len(pos) + len(neg))
        pos = pos[:max(1, int(len(pos) * frac))]
        neg = neg[:max(1, int(len(neg) * frac))]

    def split_list(items):
        n = len(items)
        i_train = int(n * train_frac)
        i_val = int(n * (train_frac + val_frac))
        return items[:i_train], items[i_train:i_val], items[i_val:]

    pos_train, pos_val, pos_test = split_list(pos)
    neg_train, neg_val, neg_test = split_list(neg)

    def to_rows(p, n):
        return [(t, True) for t in p] + [(t, False) for t in n]

    return to_rows(pos_train, neg_train), to_rows(pos_val, neg_val), to_rows(pos_test, neg_test)


def evaluate(engine, dataset):
    tp = fp = tn = fn = 0
    start = time.perf_counter()
    for text, is_phishing in dataset:
        predicted = not engine.assess_message(text)["is_clean"]
        if predicted and is_phishing:
            tp += 1
        elif predicted and not is_phishing:
            fp += 1
        elif not predicted and not is_phishing:
            tn += 1
        else:
            fn += 1
    elapsed = time.perf_counter() - start

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": accuracy, "precision": precision, "recall": recall,
        "f1": f1, "fpr": fpr, "elapsed_sec": elapsed,
    }


def main():
    parser = argparse.ArgumentParser(description="Calibrate enhanced-engine thresholds")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--text-col", default="text")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--positive-label", default="phishing")
    parser.add_argument("--pattern-file", required=True)
    parser.add_argument("--sample-size", type=int, default=None,
                         help="Subsample the dataset for faster tuning (recommended "
                              "given the O(patterns x text_length) fuzzy layer cost).")
    parser.add_argument("--max-text-chars", type=int, default=None)
    parser.add_argument("--max-fpr", type=float, default=None,
                         help="If set, pick the config with the best recall among "
                              "those whose validation FPR <= this value, instead of "
                              "picking by highest F1.")
    args = parser.parse_args()

    train, val, test = load_and_split(
        args.csv, args.text_col, args.label_col, args.positive_label,
        sample_size=args.sample_size, max_text_chars=args.max_text_chars,
    )
    print(f"Split sizes -> train: {len(train)} (unused by this rule-based engine), "
          f"val: {len(val)}, test: {len(test)}\n")

    # Grid to search. Start small — each combination requires a full pass
    # over the validation set. Expand once you've confirmed this runs in
    # a reasonable time for your dataset size / Kaggle session.
    anomaly_grid = [0.45, 0.55, 0.65, 0.75, 0.85]
    exact_grid = [1.2]     # add e.g. [1.1, 1.2, 1.3] once the basic grid works
    affix_grid = [1.05]    # add e.g. [1.0, 1.05, 1.15] similarly

    trials = []
    for anomaly_t in anomaly_grid:
        for exact_t in exact_grid:
            for affix_t in affix_grid:
                engine = EnhancedAhoCorasick.from_pattern_file(
                    args.pattern_file,
                    anomaly_threshold=anomaly_t,
                    exact_threshold=exact_t,
                    affix_threshold=affix_t,
                )
                metrics = evaluate(engine, val)
                trials.append({
                    "anomaly_threshold": anomaly_t,
                    "exact_threshold": exact_t,
                    "affix_threshold": affix_t,
                    **metrics,
                })
                print(f"  anomaly={anomaly_t:.2f} exact={exact_t:.2f} affix={affix_t:.2f}  "
                      f"-> F1={metrics['f1']:.4f}  FPR={metrics['fpr']:.4f}  "
                      f"Recall={metrics['recall']:.4f}  ({metrics['elapsed_sec']:.1f}s)")

    if args.max_fpr is not None:
        candidates = [t for t in trials if t["fpr"] <= args.max_fpr] or trials
        best = max(candidates, key=lambda t: t["recall"])
        criterion = f"best recall with FPR <= {args.max_fpr}"
    else:
        best = max(trials, key=lambda t: t["f1"])
        criterion = "best F1"

    print(f"\n=== BEST CONFIG ({criterion}) ===")
    print(f"  anomaly_threshold = {best['anomaly_threshold']}")
    print(f"  exact_threshold   = {best['exact_threshold']}")
    print(f"  affix_threshold   = {best['affix_threshold']}")
    print(f"  (validation) Accuracy={best['accuracy']:.4f}  Precision={best['precision']:.4f}  "
          f"Recall={best['recall']:.4f}  F1={best['f1']:.4f}  FPR={best['fpr']:.4f}")

    print(f"\n=== FINAL TEST-SET RESULT (report this in Chapter 4, not the validation numbers) ===")
    final_engine = EnhancedAhoCorasick.from_pattern_file(
        args.pattern_file,
        anomaly_threshold=best["anomaly_threshold"],
        exact_threshold=best["exact_threshold"],
        affix_threshold=best["affix_threshold"],
    )
    test_metrics = evaluate(final_engine, test)
    print(f"  TP={test_metrics['tp']}  FP={test_metrics['fp']}  "
          f"TN={test_metrics['tn']}  FN={test_metrics['fn']}")
    print(f"  Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"  Precision: {test_metrics['precision']:.4f}")
    print(f"  Recall:    {test_metrics['recall']:.4f}")
    print(f"  F1-score:  {test_metrics['f1']:.4f}")
    print(f"  FPR:       {test_metrics['fpr']:.4f}")


if __name__ == "__main__":
    main()