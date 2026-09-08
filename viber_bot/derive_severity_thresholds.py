"""
Empirical derivation of severity band cutoffs (Low / Moderate / High / Critical).

Background: the engine's final_risk score has a solid theoretical basis
(Multi-Criteria Decision Analysis, Belton & Stewart 2002 — already cited in
Chapter 3). The four-tier severity structure is modeled on the CVSS
convention (a defensible, citable structural reference). What was NOT
empirically grounded were the specific numeric cutoffs separating the four
tiers (previously a smooth rescaling of CVSS's 0-10 boundaries onto this
engine's score range).

This script derives those cutoffs from the actual score distribution
observed in the evaluation datasets instead, using the following discipline
to keep the result methodologically honest:

  1. Each dataset is split into train / validation / test (train is unused
     by this rule-based engine, kept for symmetry with calibrate_thresholds.py).
  2. Cutoffs are derived ONLY from the VALIDATION split of each dataset.
  3. The SAME derivation is run independently on two different datasets.
     If similar cutoffs emerge independently in both, that is evidence the
     cutoffs reflect a real property of the scoring formula rather than an
     artifact of one specific dataset.
  4. The derived cutoffs are then checked against the untouched TEST split
     of each dataset — these confirmation numbers are what should be quoted
     in the thesis, not the validation numbers used to pick the cutoffs.

Method: a detection's final_risk score is only useful if it correlates with
whether the detection was actually correct. So for each candidate score
threshold t, this script computes "precision at or above t" — of all
detections with score >= t, what fraction were true phishing? Higher scores
should show higher precision if the score is meaningful. The three band
cutoffs are the lowest scores at which precision-at-or-above first reaches
three target precision milestones (default 0.50, 0.75, 0.90), each requiring
a minimum sample size so a cutoff isn't chosen from a handful of noisy points.

Usage:
    python derive_severity_thresholds.py \
        --csv-a ../datasets/phishing_email.csv --text-col-a text_combined --label-col-a label \
        --csv-b ../datasets/phishing_legit_dataset_KD_10000.csv --text-col-b text --label-col-b label \
        --positive-label 1 --pattern-file ../enhanced_aho/default_patterns.txt \
        --sample-size 6000 --max-text-chars 20000
"""

import argparse
import csv
import random
import sys

csv.field_size_limit(sys.maxsize)

import _bootstrap  # noqa: F401
from enhanced_aho_corasick import EnhancedAhoCorasick

DEFAULT_PRECISION_TARGETS = (0.50, 0.75, 0.90)
DEFAULT_MINIMUM_SUPPORT = 20


def load_and_split(csv_path, text_column, label_column, positive_label,
                    sample_size=None, max_text_length=None, random_seed=42,
                    train_fraction=0.6, validation_fraction=0.2):
    """Stratified train/validation/test split (test fraction = the remainder)."""
    positive_examples, negative_examples = [], []
    with open(csv_path, newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            text = row.get(text_column, "")
            if max_text_length is not None and len(text) > max_text_length:
                text = text[:max_text_length]
            label_value = str(row.get(label_column, "")).strip().lower()
            is_phishing = label_value == str(positive_label).strip().lower()
            (positive_examples if is_phishing else negative_examples).append(text)

    generator = random.Random(random_seed)
    generator.shuffle(positive_examples)
    generator.shuffle(negative_examples)

    if sample_size is not None:
        total = len(positive_examples) + len(negative_examples)
        fraction = sample_size / total if total else 0
        positive_examples = positive_examples[:max(1, int(len(positive_examples) * fraction))]
        negative_examples = negative_examples[:max(1, int(len(negative_examples) * fraction))]

    def split_by_fraction(items):
        count = len(items)
        train_end = int(count * train_fraction)
        validation_end = int(count * (train_fraction + validation_fraction))
        return items[:train_end], items[train_end:validation_end], items[validation_end:]

    positive_train, positive_validation, positive_test = split_by_fraction(positive_examples)
    negative_train, negative_validation, negative_test = split_by_fraction(negative_examples)

    def combine(positives, negatives):
        return [(text, True) for text in positives] + [(text, False) for text in negatives]

    return (
        combine(positive_train, negative_train),
        combine(positive_validation, negative_validation),
        combine(positive_test, negative_test),
    )


def collect_detection_scores(engine, labeled_examples):
    """
    Runs every example through the engine and returns one (score, is_actual_phishing)
    pair per example THAT PRODUCED AT LEAST ONE DETECTION. Clean (undetected)
    examples are excluded here because severity bands only classify messages
    that were already flagged — they don't apply to messages the engine
    considered clean.
    """
    scored_examples = []
    for text, is_actual_phishing in labeled_examples:
        result = engine.assess_message(text)
        if result["is_clean"]:
            continue
        highest_score = max(detection["risk_score"] for detection in result["detections"])
        scored_examples.append((highest_score, is_actual_phishing))
    return scored_examples


def precision_at_or_above(scored_examples, threshold):
    """Precision among examples whose score is >= threshold. Returns (precision, support)."""
    selected = [is_phishing for score, is_phishing in scored_examples if score >= threshold]
    support = len(selected)
    if support == 0:
        return None, 0
    true_positive_count = sum(1 for is_phishing in selected if is_phishing)
    return true_positive_count / support, support


def find_cutoff_for_precision_target(scored_examples, target_precision,
                                      minimum_support=DEFAULT_MINIMUM_SUPPORT):
    """
    Finds the LOWEST score threshold at which precision-at-or-above reaches
    target_precision, requiring at least minimum_support examples at that
    threshold so the cutoff isn't chosen from a handful of noisy points.
    Returns None if no candidate threshold meets both conditions.
    """
    candidate_scores = sorted(set(score for score, _ in scored_examples))
    for candidate in candidate_scores:
        precision, support = precision_at_or_above(scored_examples, candidate)
        if precision is not None and precision >= target_precision and support >= minimum_support:
            return candidate
    return None


def derive_cutoffs(scored_examples, precision_targets=DEFAULT_PRECISION_TARGETS,
                    minimum_support=DEFAULT_MINIMUM_SUPPORT):
    return [
        find_cutoff_for_precision_target(scored_examples, target, minimum_support)
        for target in precision_targets
    ]


def summarize_dataset(label, csv_path, text_column, label_column, positive_label,
                       engine, sample_size, max_text_length, precision_targets,
                       minimum_support):
    print(f"\n=== {label}: {csv_path} ===")
    train_set, validation_set, test_set = load_and_split(
        csv_path, text_column, label_column, positive_label,
        sample_size=sample_size, max_text_length=max_text_length,
    )
    print(f"Split sizes -> train: {len(train_set)} (unused), "
          f"validation: {len(validation_set)}, test: {len(test_set)}")

    validation_scores = collect_detection_scores(engine, validation_set)
    print(f"Flagged examples in validation split: {len(validation_scores)}")

    cutoffs = derive_cutoffs(validation_scores, precision_targets, minimum_support)
    for target, cutoff in zip(precision_targets, cutoffs):
        if cutoff is None:
            print(f"  Could not find a stable cutoff for target precision {target:.2f} "
                  f"(insufficient support at any score level)")
        else:
            precision, support = precision_at_or_above(validation_scores, cutoff)
            print(f"  Target precision {target:.2f} -> cutoff = {cutoff:.3f} "
                  f"(actual precision {precision:.3f}, support {support})")

    return cutoffs, test_set


def confirm_on_test_split(engine, test_set, cutoffs, precision_targets):
    print("  -- Confirmation on held-out TEST split (report these, not validation numbers) --")
    test_scores = collect_detection_scores(engine, test_set)
    for target, cutoff in zip(precision_targets, cutoffs):
        if cutoff is None:
            continue
        precision, support = precision_at_or_above(test_scores, cutoff)
        if precision is None:
            print(f"  cutoff={cutoff:.3f} (target {target:.2f}) -> no test examples at or above this score")
        else:
            print(f"  cutoff={cutoff:.3f} (target {target:.2f}) -> "
                  f"test precision = {precision:.3f} (support {support})")


def main():
    parser = argparse.ArgumentParser(
        description="Empirically derive severity band cutoffs from two independent datasets."
    )
    parser.add_argument("--csv-a", required=True)
    parser.add_argument("--text-col-a", default="text")
    parser.add_argument("--label-col-a", default="label")
    parser.add_argument("--csv-b", required=True)
    parser.add_argument("--text-col-b", default="text")
    parser.add_argument("--label-col-b", default="label")
    parser.add_argument("--positive-label", default="1")
    parser.add_argument("--pattern-file", required=True)
    parser.add_argument("--sample-size", type=int, default=None)
    parser.add_argument("--max-text-chars", type=int, default=None)
    parser.add_argument("--precision-targets", type=float, nargs=3,
                         default=list(DEFAULT_PRECISION_TARGETS),
                         help="Three ascending precision milestones defining the "
                              "Low/Moderate, Moderate/High, and High/Critical boundaries.")
    parser.add_argument("--minimum-support", type=int, default=DEFAULT_MINIMUM_SUPPORT)
    args = parser.parse_args()

    engine = EnhancedAhoCorasick.from_pattern_file(args.pattern_file)
    precision_targets = tuple(args.precision_targets)

    cutoffs_a, test_set_a = summarize_dataset(
        "DATASET A", args.csv_a, args.text_col_a, args.label_col_a, args.positive_label,
        engine, args.sample_size, args.max_text_chars, precision_targets, args.minimum_support,
    )
    confirm_on_test_split(engine, test_set_a, cutoffs_a, precision_targets)

    cutoffs_b, test_set_b = summarize_dataset(
        "DATASET B", args.csv_b, args.text_col_b, args.label_col_b, args.positive_label,
        engine, args.sample_size, args.max_text_chars, precision_targets, args.minimum_support,
    )
    confirm_on_test_split(engine, test_set_b, cutoffs_b, precision_targets)

    print("\n=== CROSS-DATASET COMPARISON ===")
    print("If cutoffs are close between A and B, that supports treating them as a "
          "property of the scoring formula rather than an artifact of one dataset.")
    for target, cutoff_a, cutoff_b in zip(precision_targets, cutoffs_a, cutoffs_b):
        if cutoff_a is None or cutoff_b is None:
            print(f"  target={target:.2f}: A={cutoff_a} B={cutoff_b} (at least one undefined)")
            continue
        difference = abs(cutoff_a - cutoff_b)
        average = (cutoff_a + cutoff_b) / 2
        print(f"  target={target:.2f}: A={cutoff_a:.3f}  B={cutoff_b:.3f}  "
              f"difference={difference:.3f}  suggested_combined_cutoff={average:.3f}")


if __name__ == "__main__":
    main()