#!/usr/bin/env python3
"""
SSH Authentication Log Analyzer

Detects repeated failed SSH authentication attempts,
identifies targeted accounts, and reports possible
brute-force activity.
"""

import argparse
import re
from collections import Counter
from pathlib import Path
from contextlib import redirect_stdout
from io import StringIO
from datetime import datetime

FAILED = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([0-9.]+)"
)

SUCCESS = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([0-9.]+)"
)


def analyze(path: Path, threshold: int, output: Path = None):
    failures = Counter()
    users = {}
    successes = []

    with path.open("r", encoding="utf-8", errors="ignore") as log_file:
        for line in log_file:
            failed_match = FAILED.search(line)

            if failed_match:
                username, ip = failed_match.groups()
                failures[ip] += 1

                if ip not in users:
                    users[ip] = Counter()

                users[ip][username] += 1

            success_match = SUCCESS.search(line)

            if success_match:
                username, ip = success_match.groups()
                timestamp = line[:15]
                successes.append((ip, username, timestamp))

    print("=" * 60)
    print("SSH SECURITY LOG ANALYSIS")
    print("=" * 60)

    alerts_found = False

    for ip, count in failures.most_common():
        if count >= threshold:
            alerts_found = True

            targeted_accounts = ", ".join(sorted(users[ip].keys()))

            successful_login = [
                username
                for source_ip, username, timestamp in successes
                if source_ip == ip
            ]

            if successful_login:
                severity = "CRITICAL"
                success_status = "YES"
            else:
                severity = "HIGH"
                success_status = "NO"

            print()
            print("=" * 60)
            print("SECURITY ALERT")
            print("=" * 60)
            print(f"Severity: {severity}")
            print("Detection: SSH Brute Force")
            print(f"Source IP: {ip}")
            print(f"Failed Attempts: {count}")
            print(f"Targeted Accounts: {targeted_accounts}")
            print(f"Successful Login: {success_status}")
            print("MITRE ATT&CK: T1110 - Brute Force")
            print("=" * 60)

            if successful_login:
                print(
                    "[!] Successful authentication detected "
                    f"for: {', '.join(successful_login)}"
                )

    if not alerts_found:
        print()
        print("[OK] No brute-force activity detected.")
        print(f"Threshold: {threshold} failed attempts")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze SSH authentication logs for brute-force activity."
    )
    parser.add_argument("logfile", type=Path, help="Path to the authentication log")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required to trigger an alert (default: 5)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for saving the analysis report",
    )
    args = parser.parse_args()

    if not args.logfile.is_file():
        parser.error(f"Log file not found: {args.logfile}")

    if args.threshold < 1:
        parser.error("Threshold must be at least 1")

    if args.output:
        buffer = StringIO()

        with redirect_stdout(buffer):
            analyze(args.logfile, args.threshold)

        report = buffer.getvalue()
        print(report, end="")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
        print(f"\nReport saved to: {args.output}")
    else:
        analyze(args.logfile, args.threshold)


if __name__ == "__main__":
    main()
