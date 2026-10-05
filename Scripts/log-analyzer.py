#!/usr/bin/env python3
"""Analyze Linux-style authentication logs for suspicious activity."""
import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9.]+)")
SUCCESS = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([0-9.]+)")


def analyze(path: Path, threshold: int):
    failures = Counter()
    users = defaultdict(Counter)
    successes = []

    for line in path.read_text(errors="replace").splitlines():
        match = FAILED.search(line)
        if match:
            user, ip = match.groups()
            failures[ip] += 1
            users[ip][user] += 1
            continue
        match = SUCCESS.search(line)
        if match:
            user, ip = match.groups()
            successes.append((user, ip, line))

    findings = []
    for ip, count in failures.items():
        if count >= threshold:
            findings.append({
                "severity": "HIGH" if count >= threshold * 2 else "MEDIUM",
                "type": "Repeated authentication failures",
                "source_ip": ip,
                "attempts": count,
                "targeted_users": ", ".join(users[ip].keys()),
            })

    return findings, successes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--csv", type=Path, help="Optional CSV output file")
    args = parser.parse_args()

    findings, successes = analyze(args.logfile, args.threshold)
    print(f"Analyzed: {args.logfile}")
    print(f"Findings: {len(findings)}")
    for finding in findings:
        print(f"[{finding['severity']}] {finding['source_ip']} - "
              f"{finding['attempts']} failures targeting {finding['targeted_users']}")

    if successes:
        print(f"Successful authentications observed: {len(successes)}")

    if args.csv:
        with args.csv.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["severity", "type", "source_ip", "attempts", "targeted_users"])
            writer.writeheader()
            writer.writerows(findings)
        print(f"Wrote findings to {args.csv}")


if __name__ == "__main__":
    main()
