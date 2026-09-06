"""
Baseline vs Enhanced comparison harness — this produces the numbers for
Chapter 4's "Performance Output" and "Data Output", following the exact
evaluation methodology already defined in Section 3.1 of the thesis:
accuracy, precision, recall, F1-score, and false positive rate, computed
identically for both algorithm versions on the same dataset.

Usage:
    python compare_engines.py --csv path/to/dataset.csv \
        --text-col message --label-col label \
        --positive-label phishing --pattern-file ../enhanced_aho/default_patterns.txt

    (--pattern-file defaults to ../enhanced_aho/default_patterns.txt if omitted)

    (omit --csv to run on the small built-in sample set instead, useful for
    a quick sanity check before your real Kaggle CSVs are wired in)

CSV label column is expected to contain values indicating phishing vs
legitimate; use --positive-label to say which value counts as "phishing"
(e.g. "phishing", "1", "spam" — whatever your specific CSV uses).
"""

import argparse
import csv
import time
from pathlib import Path

import _bootstrap  # noqa: F401 — sets up sys.path for enhanced_aho/ and original_aho/
from baseline_aho_corasick import BaselineAhoCorasick
from enhanced_aho_corasick import EnhancedAhoCorasick

DEFAULT_PATTERN_FILE = str(
    Path(__file__).resolve().parent.parent / "enhanced_aho" / "default_patterns.txt"
)


SAMPLE_DATA = [
    ("ALERTO: Ang iyong G-C@sh ay na-bl0cked. Paki-berify ang iyong impormasyon.", True),
    ("URGENT: Your gcash account is blocked. Click here to verify: https://gcash.verify-now.com/login", True),
    ("Kailangan mo i-berify ang iyong account. Mag-klik ka na.", True),
    ("Nag-update na ako ng password ko sa gcash kanina, okay na.", False),
    ("Pwede mo i-login sa aking account? Need ko lang i-check yung balance.", False),
    ("Team meeting moved to 3 PM tomorrow, see you all there.", False),
    ("Congratulations! You've won a prize, claim it now: https://bit.ly/xk29z", True),
    ("Paalala lang, bukas na ang deadline ng project natin.", False),
]


def load_csv(path, text_col, label_col, positive_label):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get(text_col, "")
            label = str(row.get(label_col, "")).strip().lower()
            is_phishing = label == str(positive_label).strip().lower()
            rows.append((text, is_phishing))
    return rows


def evaluate(engine, dataset, predict_fn):
    tp = fp = tn = fn = 0
    start = time.perf_counter()
    for text, is_phishing in dataset:
        predicted_phishing = predict_fn(engine, text)
        if predicted_phishing and is_phishing:
            tp += 1
        elif predicted_phishing and not is_phishing:
            fp += 1
        elif not predicted_phishing and not is_phishing:
            tn += 1
        else:
            fn += 1
    elapsed = time.perf_counter() - start

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": accuracy, "precision": precision, "recall": recall,
        "f1": f1, "fpr": fpr, "elapsed_sec": elapsed,
        "messages_per_sec": total / elapsed if elapsed > 0 else float("inf"),
    }


def baseline_predict(engine, text):
    return len(engine.search(text)) > 0


def enhanced_predict(engine, text):
    return not engine.assess_message(text)["is_clean"]


def print_report(name, metrics):
    print(f"\n=== {name} ===")
    print(f"  TP={metrics['tp']}  FP={metrics['fp']}  TN={metrics['tn']}  FN={metrics['fn']}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1-score:  {metrics['f1']:.4f}")
    print(f"  FPR:       {metrics['fpr']:.4f}")
    print(f"  Time:      {metrics['elapsed_sec']:.4f}s "
          f"({metrics['messages_per_sec']:.1f} msg/s)")


def main():
    parser = argparse.ArgumentParser(description="Compare baseline vs enhanced Aho-Corasick")
    parser.add_argument("--csv", help="Path to labeled CSV dataset")
    parser.add_argument("--text-col", default="text")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--positive-label", default="phishing")
    parser.add_argument("--pattern-file", default=DEFAULT_PATTERN_FILE)
    args = parser.parse_args()

    if args.csv:
        dataset = load_csv(args.csv, args.text_col, args.label_col, args.positive_label)
        print(f"Loaded {len(dataset)} rows from {args.csv}")
    else:
        dataset = SAMPLE_DATA
        print(f"No --csv given — using {len(dataset)}-row built-in sample set "
              f"(replace with your real Kaggle CSVs for actual thesis numbers).")

    baseline = BaselineAhoCorasick.from_pattern_file(args.pattern_file)
    enhanced = EnhancedAhoCorasick.from_pattern_file(args.pattern_file)

    baseline_metrics = evaluate(baseline, dataset, baseline_predict)
    enhanced_metrics = evaluate(enhanced, dataset, enhanced_predict)

    print_report("BASELINE (classic Aho-Corasick, Chapter 1)", baseline_metrics)
    print_report("ENHANCED (this study's Objectives 1-4)", enhanced_metrics)

    print("\n=== Delta (Enhanced - Baseline) ===")
    for key in ("accuracy", "precision", "recall", "f1", "fpr"):
        delta = enhanced_metrics[key] - baseline_metrics[key]
        sign = "+" if delta >= 0 else ""
        print(f"  {key}: {sign}{delta:.4f}")


if __name__ == "__main__":
    main()
