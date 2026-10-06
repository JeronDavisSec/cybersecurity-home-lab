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


FAILED = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([0-9.]+)"
)

SUCCESS = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([0-9.]+)"
)


def analyze(path: Path, threshold: int):
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
                successes.append((ip, username))

    print("=" * 60)
    print("SSH SECURITY LOG ANALYSIS")
    print("=" * 60)

    alerts_found = False

    for ip, count in failures.most_common():
        if count >= threshold:
            alerts_found = True

            targeted_accounts = ", ".join(
                sorted(users[ip].keys())
            )

            successful_login = [
                username
                for source_ip, username in successes
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
                    f"[!] Successful authentication detected "
                    f"for: {', '.join(successful_login)}"
                )

    if not alerts_found:
        print()
        print("[OK] No brute-force activity detected.")
        print(f"Threshold: {threshold} failed attempts")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze SSH authentication logs for suspicious activity."
    )

    parser.add_argument(
        "logfile",
        type=Path,
        help="Path to authentication log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required to trigger an alert"
    )

    args = parser.parse_args()

    if not args.logfile.exists():
        print(f"[ERROR] Log file not found: {args.logfile}")
        return

    analyze(args.logfile, args.threshold)


if __name__ == "__main__":
    main()
