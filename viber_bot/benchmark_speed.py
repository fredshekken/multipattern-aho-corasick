r"""
Processing-speed benchmark for Table 4.1.

Speed varies from run to run (other programs, power settings, CPU boost), so a
single run is not a reliable number. This script times both engines several
times on the same dataset, in the same way as compare_engines.py, and reports
the MEDIAN messages per second together with the computer it ran on.

Usage (from the viber_bot folder):
    python benchmark_speed.py --csv uploaded_datasets\da24fda71670_philippine_sms_cleaned.csv --positive-label 1

Tips for a fair measurement: plug in the laptop, close other programs, and do
not use the computer while it runs.
"""
import argparse
import os
import platform
import statistics

import _bootstrap  # noqa: F401
from compare_engines import (
    DEFAULT_PATTERN_FILE, load_csv, evaluate, baseline_predict, enhanced_predict,
)
from baseline_aho_corasick import BaselineAhoCorasick
from enhanced_aho_corasick import EnhancedAhoCorasick


def describe_machine():
    cpu = platform.processor() or platform.machine()
    ram = "unknown"
    try:
        if platform.system() == "Windows":
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(MemoryStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
            ram = f"{status.ullTotalPhys / 1024 ** 3:.1f} GB"
        else:
            # os.sysconf only exists on Mac and Linux, so look it up by name
            sysconf = getattr(os, "sysconf", None)
            if sysconf is not None:
                ram = f"{sysconf('SC_PAGE_SIZE') * sysconf('SC_PHYS_PAGES') / 1024 ** 3:.1f} GB"
    except Exception:
        pass
    return (f"{platform.system()} {platform.release()} | CPU: {cpu} | "
            f"logical cores: {os.cpu_count()} | RAM: {ram} | Python {platform.python_version()}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--text-col", default="text")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--positive-label", default="1")
    ap.add_argument("--pattern-file", default=DEFAULT_PATTERN_FILE)
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()

    data = load_csv(args.csv, args.text_col, args.label_col, args.positive_label)
    baseline = BaselineAhoCorasick.from_pattern_file(args.pattern_file)
    # Same settings as the benchmark: offline (no shortened link is contacted),
    # lookalike check on, URL trace printing off so printing does not slow it down.
    enhanced = EnhancedAhoCorasick.from_pattern_file(
        args.pattern_file, resolve_shorteners=False, url_trace=False)

    print(f"Loaded {len(data)} rows")
    print("Machine:", describe_machine())

    # Warm-up run (not counted): loads code and fills caches
    evaluate(baseline, data, baseline_predict)
    evaluate(enhanced, data, enhanced_predict)

    results = {"Original": [], "Enhanced": []}
    counts = {"Original": set(), "Enhanced": set()}
    for run in range(1, args.runs + 1):
        for name, engine, fn in (("Original", baseline, baseline_predict),
                                 ("Enhanced", enhanced, enhanced_predict)):
            m = evaluate(engine, data, fn)
            results[name].append(m["messages_per_sec"])
            counts[name].add((m["tp"], m["fp"], m["tn"], m["fn"]))
        print(f"  run {run}: Original {results['Original'][-1]:,.1f} msg/s | "
              f"Enhanced {results['Enhanced'][-1]:,.1f} msg/s")

    print("\n=== SPEED (report the median) ===")
    for name, speeds in results.items():
        print(f"  {name:9s} median {statistics.median(speeds):,.1f} msg/s "
              f"(min {min(speeds):,.1f}, max {max(speeds):,.1f}, {len(speeds)} runs)")
        tp, fp, tn, fn = next(iter(counts[name]))
        same = "same in every run" if len(counts[name]) == 1 else "CHANGED between runs (check this)"
        print(f"            TP/FP/TN/FN = {tp}/{fp}/{tn}/{fn} ({same})")


if __name__ == "__main__":
    main()