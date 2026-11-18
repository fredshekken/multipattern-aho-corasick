"""
Threshold calibration for the Enhanced Aho-Corasick engine (Table 4.2).

The engine is rule-based, so "training" here means choosing its anomaly
threshold on labeled validation data that the final evaluation never sees.

Recommended use (Chapter 4):
    1. Run split_dataset.py once. It makes sms_validation.csv and sms_test.csv
       with no shared messages.
    2. Run this script with --validation-only on sms_validation.csv.
       Every row is used for validation; nothing is reported on test data.
    3. Use the chosen threshold, then run compare_engines.py,
       operational_rates.py and benchmark_speed.py on sms_test.csv.

    python calibrate_thresholds.py --csv uploaded_datasets/sms_validation.csv \
        --positive-label 1 --pattern-file ../enhanced_aho/default_patterns.txt \
        --validation-only

Selection rule: highest validation F1. If two thresholds tie, the first
(lowest) one in the grid is kept. Use --max-fpr to pick the best recall
among thresholds whose validation FPR is at or below a limit instead.

Old mode (without --validation-only): splits ONE file 60/20/20 into
train/validation/test and reports the test part. Kept for reference only.
"""

import argparse
import csv
import random
import sys
import time

csv.field_size_limit(sys.maxsize)

import _bootstrap  # noqa: F401
from enhanced_aho_corasick import EnhancedAhoCorasick

ANOMALY_GRID = [0.45, 0.55, 0.65, 0.75, 0.85]
EXACT_GRID = [1.2]
AFFIX_GRID = [1.05]


def read_rows(csv_path, text_col, label_col, positive_label, max_text_chars=None):
    pos, neg = [], []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            text = row.get(text_col, "")
            if max_text_chars is not None and len(text) > max_text_chars:
                text = text[:max_text_chars]
            label = str(row.get(label_col, "")).strip().lower()
            (pos if label == str(positive_label).strip().lower() else neg).append(text)
    return pos, neg


def load_and_split(csv_path, text_col, label_col, positive_label,
                   sample_size=None, max_text_chars=None, seed=42,
                   train_frac=0.6, val_frac=0.2):
    """Old mode: stratified train/val/test split of one file."""
    pos, neg = read_rows(csv_path, text_col, label_col, positive_label, max_text_chars)
    rng = random.Random(seed)
    rng.shuffle(pos)
    rng.shuffle(neg)

    if sample_size is not None:
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


def build_engine(args, anomaly_t, exact_t, affix_t):
    # Same settings as compare_engines.py, so the chosen value carries over.
    return EnhancedAhoCorasick.from_pattern_file(
        args.pattern_file,
        anomaly_threshold=anomaly_t,
        exact_threshold=exact_t,
        affix_threshold=affix_t,
        resolve_shorteners=not args.no_resolve_shorteners,
        flag_lookalike_domains=not args.no_lookalike_domains,
    )


def main():
    parser = argparse.ArgumentParser(description="Calibrate enhanced-engine thresholds")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--text-col", default="text")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--positive-label", default="1")
    parser.add_argument("--pattern-file", required=True)
    parser.add_argument("--validation-only", action="store_true",
                        help="Use EVERY row of --csv as validation data (use with "
                             "sms_validation.csv from split_dataset.py). No test numbers.")
    parser.add_argument("--sample-size", type=int, default=None,
                        help="Old mode only: subsample before splitting.")
    parser.add_argument("--max-text-chars", type=int, default=None)
    parser.add_argument("--max-fpr", type=float, default=None,
                        help="Pick the best recall among thresholds with validation "
                             "FPR <= this value, instead of the best F1.")
    parser.add_argument("--no-resolve-shorteners", action="store_true",
                        help="Do not contact shortened links (offline run).")
    parser.add_argument("--no-lookalike-domains", action="store_true",
                        help="Turn OFF the lookalike-domain check (ON by default).")
    args = parser.parse_args()

    if args.validation_only:
        pos, neg = read_rows(args.csv, args.text_col, args.label_col,
                             args.positive_label, args.max_text_chars)
        val = [(t, True) for t in pos] + [(t, False) for t in neg]
        test = None
        print(f"Validation-only mode: {len(val)} rows "
              f"({len(pos)} phishing / {len(neg)} legit) from {args.csv}")
    else:
        _train, val, test = load_and_split(
            args.csv, args.text_col, args.label_col, args.positive_label,
            sample_size=args.sample_size, max_text_chars=args.max_text_chars,
        )
        print(f"Old split mode -> validation: {len(val)}, test: {len(test)}")
    print("Shortener resolution:", "OFF" if args.no_resolve_shorteners else "ON (live network)")
    print("Lookalike-domain check:", "OFF" if args.no_lookalike_domains else "ON")
    print()

    trials = []
    for anomaly_t in ANOMALY_GRID:
        for exact_t in EXACT_GRID:
            for affix_t in AFFIX_GRID:
                metrics = evaluate(build_engine(args, anomaly_t, exact_t, affix_t), val)
                trials.append({"anomaly_threshold": anomaly_t, "exact_threshold": exact_t,
                               "affix_threshold": affix_t, **metrics})
                print(f"  tau={anomaly_t:.2f}  TP={metrics['tp']} FP={metrics['fp']} "
                      f"TN={metrics['tn']} FN={metrics['fn']}  ({metrics['elapsed_sec']:.1f}s)")

    print("\n=== TABLE 4.2 (validation set) ===")
    print(f"  {'tau':>5}  {'Accuracy':>9}  {'Precision':>9}  {'Recall':>8}  {'F1':>8}  {'FPR':>7}")
    for t in trials:
        print(f"  {t['anomaly_threshold']:>5.2f}  {t['accuracy']:>9.2%}  {t['precision']:>9.2%}  "
              f"{t['recall']:>8.2%}  {t['f1']:>8.2%}  {t['fpr']:>7.2%}")

    if args.max_fpr is not None:
        candidates = [t for t in trials if t["fpr"] <= args.max_fpr] or trials
        best = max(candidates, key=lambda t: t["recall"])
        criterion = f"best recall with FPR <= {args.max_fpr}"
    else:
        best = max(trials, key=lambda t: t["f1"])  # ties keep the first (lowest) tau
        criterion = "best F1, ties keep the lowest tau"

    print(f"\n=== CHOSEN ({criterion}) ===")
    print(f"  anomaly_threshold = {best['anomaly_threshold']}")
    print(f"  exact_threshold   = {best['exact_threshold']}")
    print(f"  affix_threshold   = {best['affix_threshold']}")

    if test is not None:
        print("\n=== OLD MODE TEST RESULT ===")
        m = evaluate(build_engine(args, best["anomaly_threshold"], best["exact_threshold"],
                                  best["affix_threshold"]), test)
        print(f"  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}  "
              f"Acc={m['accuracy']:.4f} P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f} FPR={m['fpr']:.4f}")


if __name__ == "__main__":
    main()