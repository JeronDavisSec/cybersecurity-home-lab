#!/usr/bin/env python3
"""Perform a safe, read-only local security posture check."""
import os
import platform
import shutil
import socket


def check(command, label):
    print(f"{label:28}: {'available' if shutil.which(command) else 'not found'}")


def main():
    print("Local Security Posture Audit")
    print("============================")
    print(f"Hostname                    : {socket.gethostname()}")
    print(f"Operating system            : {platform.platform()}")
    print(f"Python                      : {platform.python_version()}")
    print(f"Running as UID              : {os.getuid() if hasattr(os, 'getuid') else 'N/A'}")
    check("ssh", "SSH client")
    check("git", "Git")
    check("python3", "Python 3")
    print("\nRecommendations:")
    print("- Use MFA where supported.")
    print("- Disable unused services.")
    print("- Apply security updates regularly.")
    print("- Review authentication logs.")
    print("- Use least privilege for daily work.")


if __name__ == "__main__":
    main()
