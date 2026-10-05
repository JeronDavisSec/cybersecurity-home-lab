# Lab Setup

## Recommended Environment

- One Linux VM (Ubuntu Server or similar)
- Python 3.10+
- Git
- Optional: VirtualBox or VMware

## Safe Lab Principle

Use synthetic logs and systems you own or are explicitly authorized to test. This project intentionally avoids exploit code and unauthorized scanning.

## Setup

```bash
git clone <YOUR-REPOSITORY-URL>
cd cybersecurity-home-lab
python3 --version
python3 scripts/log-analyzer.py logs/sample-auth.log --threshold 5
```

## Expected Result

The analyzer should flag `203.0.113.50` because it has seven failed attempts in the sample data.
