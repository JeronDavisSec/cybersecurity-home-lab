#!/usr/bin/env python3
"""Rank source IPs by failed authentication activity in a synthetic auth log."""
import argparse
import re
from collections import Counter
from pathlib import Path

PATTERN = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9.]+)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    args = parser.parse_args()

    counts = Counter()
    for line in args.logfile.read_text(errors="replace").splitlines():
        match = PATTERN.search(line)
        if match:
            counts[match.group(2)] += 1

    print("Suspicious IP report")
    print("====================")
    for ip, count in counts.most_common():
        status = "FLAG" if count >= args.threshold else "normal"
        print(f"{ip:15} {count:3} failed attempts  [{status}]")


if __name__ == "__main__":
    main()
