import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

# Importing a hyphenated filename directly is awkward, so test the expected sample behavior
# through the command-line interface in a lightweight integration test.
import subprocess


def test_sample_log_flags_known_ip():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "log-analyzer.py"),
         str(ROOT / "logs" / "sample-auth.log"), "--threshold", "5"],
        capture_output=True, text=True, check=True
    )
    assert "203.0.113.50" in result.stdout
    assert "Findings: 1" in result.stdout
