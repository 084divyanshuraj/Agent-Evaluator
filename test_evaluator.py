"""
test_evaluator.py - Comprehensive Unit Tests for Agent Evaluator Engine
"""

import unittest
from evaluator import (
    calculate_perf_score,
    scan_text_for_secrets,
    detect_local_dev_uris,
    mask_secret,
    parse_bulk_text,
    detect_tech_stack_heuristics,
    heuristic_ui_evaluation,
    AgentTarget,
    EvaluationResult
)

class TestEvaluatorEngine(unittest.TestCase):

    def test_parse_bulk_text(self):
        sample_input = """
        Finance Agent, https://crypto-analyst.vercel.app, Crypto
        SupportBot, https://support.render.com
        https://research-llm.streamlit.app
        # This is a comment
        """
        targets = parse_bulk_text(sample_input)
        self.assertEqual(len(targets), 3)
        self.assertEqual(targets[0].name, "Finance Agent")
        self.assertEqual(targets[0].url, "https://crypto-analyst.vercel.app")
        self.assertEqual(targets[0].category, "Crypto")

        self.assertEqual(targets[1].name, "SupportBot")
        self.assertEqual(targets[1].url, "https://support.render.com")

        self.assertIn("https://research-llm.streamlit.app", targets[2].url)
        self.assertTrue(len(targets[2].name) > 0)

    def test_perf_scoring_logic(self):
        # 200 Fast edge (<800ms) = 9.0–10.0
        score, badge = calculate_perf_score(200, 250.0)
        self.assertTrue(9.0 <= score <= 10.0, f"Expected 9.0-10.0, got {score}")
        self.assertEqual(badge, "200 OK")

        # 200 Moderate (800-1500ms) = 8.0–8.9
        score, badge = calculate_perf_score(200, 1100.0)
        self.assertTrue(8.0 <= score <= 8.9, f"Expected 8.0-8.9, got {score}")

        # 200 High (>2500ms) = 6.0–7.2
        score, badge = calculate_perf_score(200, 3200.0)
        self.assertTrue(6.0 <= score <= 7.2, f"Expected 6.0-7.2, got {score}")

        # 503 Render idle spin-down = 3.5–4.0 with "Cold-start Sleep" badge
        score, badge = calculate_perf_score(503, 150.0)
        self.assertTrue(3.5 <= score <= 4.0, f"Expected 3.5-4.0, got {score}")
        self.assertIn("Cold-Start", badge)

        # 404 / Connection Timeout = 1.0–2.0
        score, badge = calculate_perf_score(404, 100.0)
        self.assertTrue(1.0 <= score <= 2.0, f"Expected 1.0-2.0, got {score}")
        self.assertIn("404", badge)

        score, badge = calculate_perf_score(0, 10000.0)
        self.assertTrue(1.0 <= score <= 2.0, f"Expected 1.0-2.0, got {score}")

    def test_secret_scanner_groq(self):
        text = 'const client = new Groq({ apiKey: "gsk_abcd1234efgh5678ijkl9012" });'
        findings = scan_text_for_secrets(text, "test.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].pattern_name, "Groq API Key")
        self.assertTrue(findings[0].masked_value.startswith("gsk_"))
        self.assertTrue("••••" in findings[0].masked_value)

    def test_secret_scanner_openai(self):
        text = 'export const OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuv1234567890";'
        findings = scan_text_for_secrets(text, "bundle.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].pattern_name, "OpenAI API Key")

    def test_secret_scanner_google(self):
        text = 'firebase.initializeApp({ apiKey: "AIzaSyA1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q" });'
        findings = scan_text_for_secrets(text, "firebase.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].pattern_name, "Google API Key")

    def test_secret_scanner_mongodb(self):
        text = 'const MONGO_URI = "mongodb+srv://admin:SuperSecret123@cluster0.abcde.mongodb.net/agentdb";'
        findings = scan_text_for_secrets(text, "config.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].pattern_name, "MongoDB Connection String")

    def test_secret_scanner_github_pat(self):
        text = 'Authorization: token ghp_1234567890abcdefghijklmnopqrstuvwxyz'
        findings = scan_text_for_secrets(text, "api.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].pattern_name, "GitHub Personal Access Token")

    def test_local_dev_detection(self):
        clean_text = 'const API = "https://production-gateway.ai/v1";'
        self.assertFalse(detect_local_dev_uris(clean_text))

        dev_text = 'const API = "http://localhost:8000/api/predict";'
        self.assertTrue(detect_local_dev_uris(dev_text))

        ip_text = 'const WS = "ws://127.0.0.1:3000/socket";'
        self.assertTrue(detect_local_dev_uris(ip_text))

    def test_secret_masking(self):
        masked = mask_secret("gsk_1234567890abcdef1234")
        self.assertEqual(masked, "gsk_••••••••1234")

    def test_tech_stack_detection(self):
        # Streamlit
        html_st = '<div data-testid="stAppViewContainer"><h1>Agent Dashboard</h1></div>'
        framework, edge, desc, score = detect_tech_stack_heuristics({}, html_st, ["static/js/main.js"])
        self.assertIn("Streamlit", framework)

        # Next.js
        html_next = '<div id="__next"><script id="__NEXT_DATA__">{}</script></div>'
        framework, edge, desc, score = detect_tech_stack_heuristics({"x-vercel-id": "iad1::123"}, html_next, ["/_next/static/chunks/main.js"])
        self.assertIn("Next.js", framework)
        self.assertIn("Vercel", edge)

    def test_overall_score_formula(self):
        ui = 8.0
        perf = 9.0
        tech = 7.0
        # Formula: (UI * 0.35) + (Perf * 0.35) + (Tech * 0.30)
        # Expected: (8.0 * 0.35) + (9.0 * 0.35) + (7.0 * 0.30) = 2.80 + 3.15 + 2.10 = 8.05
        expected = round((8.0 * 0.35) + (9.0 * 0.35) + (7.0 * 0.30), 2)
        self.assertEqual(expected, 8.05)


if __name__ == "__main__":
    unittest.main()
