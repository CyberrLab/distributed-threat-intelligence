import importlib.util
from pathlib import Path
import unittest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "correlation-engine"
    / "risk_score.py"
)

spec = importlib.util.spec_from_file_location(
    "risk_score", SCRIPT
)
risk_score = importlib.util.module_from_spec(spec)
spec.loader.exec_module(risk_score)


class RiskScoreTests(unittest.TestCase):

    def test_no_activity_has_zero_score(self):
        score, reasons = risk_score.calculate_risk(
            (0, 0, 0, 0, 0), []
        )
        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

    def test_failed_login_adds_five_points(self):
        score, _ = risk_score.calculate_risk(
            (1, 0, 0, 0, 1), []
        )
        self.assertEqual(score, 5)

    def test_suspicious_command_adds_points(self):
        score, reasons = risk_score.calculate_risk(
            (0, 1, 0, 0, 1), ["wget example.com/file"]
        )
        self.assertEqual(score, 15)
        self.assertTrue(
            any("suspicious command" in r for r in reasons)
        )

    def test_multiple_targets_add_twenty_points(self):
        score, _ = risk_score.calculate_risk(
            (0, 0, 0, 0, 2), []
        )
        self.assertEqual(score, 20)

    def test_score_is_capped_at_one_hundred(self):
        score, _ = risk_score.calculate_risk(
            (20, 20, 20, 1, 3),
            ["wget file", "curl file", "sudo whoami"]
        )
        self.assertEqual(score, 100)

    def test_risk_level_boundaries(self):
        self.assertEqual(risk_score.risk_level(29), "LOW")
        self.assertEqual(risk_score.risk_level(30), "MEDIUM")
        self.assertEqual(risk_score.risk_level(60), "HIGH")
        self.assertEqual(risk_score.risk_level(80), "CRITICAL")


if __name__ == "__main__":
    unittest.main()
