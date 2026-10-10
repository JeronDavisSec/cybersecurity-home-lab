import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "scripts" / "log-analyzer.py"


class TestSSHLogAnalyzer(unittest.TestCase):

    def run_analyzer(self, log_text):
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".log",
            encoding="utf-8",
            delete=False
        ) as log_file:
            log_file.write(log_text)
            log_path = Path(log_file.name)

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(ANALYZER),
                    str(log_path)
                ],
                capture_output=True,
                text=True,
                check=False
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        finally:
            log_path.unlink(missing_ok=True)

    def make_failed_log(self, count):
        return "".join(
            f"Oct 05 12:00:{i:02d} server sshd[1000]: "
            "Failed password for admin from 203.0.113.50 "
            "port 22 ssh2\n"
            for i in range(count)
        )

    def test_brute_force_detected(self):
        output = self.run_analyzer(self.make_failed_log(7))

        self.assertIn("HIGH", output)
        self.assertIn("SSH Brute Force", output)
        self.assertIn("203.0.113.50", output)

    def test_successful_login_escalates_to_critical(self):
        log = self.make_failed_log(7)
        log += (
            "Oct 05 12:01:00 server sshd[2001]: "
            "Accepted password for admin from 203.0.113.50 "
            "port 22 ssh2\n"
        )

        output = self.run_analyzer(log)

        self.assertIn("CRITICAL", output)
        self.assertIn("Successful Login: YES", output)

    def test_below_threshold_does_not_alert(self):
        output = self.run_analyzer(self.make_failed_log(3))

        self.assertIn("No brute-force activity detected", output)


if __name__ == "__main__":
    unittest.main()
