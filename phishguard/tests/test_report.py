"""Unit tests for M7 - Report generator module."""
from modules.report import generate_report, mask_recipient, template_fallback_report


def test_mask_recipient():
    assert mask_recipient("student@example.com") == "s*****t@example.com"
    assert mask_recipient("me@test.org") == "m*@test.org"
    assert mask_recipient("") == "—"


def test_template_fallback_phishing():
    contributions = [{"title": "DMARC failed", "points": 25, "evidence": "p=reject"}]
    rep = template_fallback_report("phishing", 85, contributions)
    assert "PHISHING" in rep["summary"]
    assert "85/100" in rep["summary"]
    assert "DMARC failed" in rep["evidence_explained"]
    assert "Do NOT click" in rep["recommended_actions"]
    assert rep["is_ai_generated"] is False


def test_template_fallback_safe():
    rep = template_fallback_report("safe", 0, [])
    assert "SAFE" in rep["summary"]
    assert "0/100" in rep["summary"]
    assert rep["is_ai_generated"] is False


def test_generate_report_uses_llm_when_available():
    def mock_llm(*a, **k):
        return {
            "summary": "AI summary of fraudulent message.",
            "evidence_explained": "AI explanation of spoofing traces.",
            "recommended_actions": "1. Do not click links.",
        }

    parsed = {"from": {"name": "Test", "address": "attacker@fake.com"}, "to": ["target@company.com"], "subject": "Urgent"}
    scoring = {"verdict": "phishing", "score": 75, "raw_total": 75, "contributions": [{"title": "SPF fail", "points": 20, "evidence": "softfail"}], "not_run": []}
    rep = generate_report(parsed, [], scoring, llm_fn=mock_llm)
    assert rep["summary"] == "AI summary of fraudulent message."
    assert rep["is_ai_generated"] is True
    assert rep["verdict"] == "phishing"
    assert rep["score"] == 75
    assert "t****t@company.com" in rep["to_list"]


def test_generate_report_falls_back_when_offline():
    parsed = {"from": {"name": "Exam Cell", "address": "exam@srmist.edu.in"}, "to": ["student@srmist.edu.in"], "subject": "Grades"}
    scoring = {"verdict": "suspicious", "score": 45, "raw_total": 45, "contributions": [{"title": "Lookalike domain", "points": 25, "evidence": "edit distance 1"}], "not_run": []}
    rep = generate_report(parsed, [], scoring, llm_fn=lambda *a, **k: None)
    assert "SUSPICIOUS" in rep["summary"]
    assert rep["is_ai_generated"] is False
    assert rep["score"] == 45
