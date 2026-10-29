"""Unit tests for M5 - Tone analysis module."""
from modules.tone import check_tone, mask_email_addresses


def test_mask_email_addresses():
    raw = "Contact admin@example.com or support@srmist.edu.in immediately!"
    masked = mask_email_addresses(raw)
    assert "admin@example.com" not in masked
    assert "support@srmist.edu.in" not in masked
    assert "[email_redacted]" in masked


def test_check_tone_empty_content():
    res = check_tone({"subject": "", "body_text": ""})
    assert res["status"] == "pass"
    assert res["score"] == 0.0
    assert len(res["findings"]) == 0


def test_check_tone_offline_fallback_returns_error_status():
    # Simulated offline LLM (returns None)
    res = check_tone({"subject": "Urgent password reset", "body_text": "Your account will be suspended."},
                     llm_fn=lambda *a, **k: None)
    assert res["status"] == "error"
    assert res["score"] is None
    assert len(res["findings"]) == 0
    assert "LLM tone check unavailable" in res["error"]


def test_check_tone_high_manipulation_score():
    def mock_llm(*a, **k):
        return {
            "score": 8.0,
            "tactics": [
                {"tactic": "urgency", "quote": "act within 24 hours"},
                {"tactic": "threat", "quote": "account suspension"},
            ],
        }

    parsed = {"subject": "Urgent Notice", "body_text": "Please act within 24 hours to avoid account suspension."}
    res = check_tone(parsed, llm_fn=mock_llm)
    assert res["status"] == "fail"
    assert res["score"] == 8.0
    assert len(res["findings"]) == 1
    # 8.0 * 1.5 = 12.0 points
    assert res["findings"][0]["points"] == 12.0
    assert "Manipulative wording (AI)" in res["findings"][0]["title"]
    assert len(res["details"]) == 2


def test_check_tone_points_capped_at_15():
    def mock_llm(*a, **k):
        return {"score": 10.0, "tactics": [{"tactic": "threat", "quote": "severe legal action"}]}

    parsed = {"subject": "Legal action", "body_text": "Immediate payment required."}
    res = check_tone(parsed, llm_fn=mock_llm)
    assert res["score"] == 10.0
    # 10.0 * 1.5 = 15.0 max cap
    assert res["findings"][0]["points"] == 15.0


def test_check_tone_zero_score_is_pass():
    def mock_llm(*a, **k):
        return {"score": 0.0, "tactics": []}

    parsed = {"subject": "Weekly Newsletter", "body_text": "Here are your weekly updates."}
    res = check_tone(parsed, llm_fn=mock_llm)
    assert res["status"] == "pass"
    assert res["score"] == 0.0
    assert len(res["findings"]) == 0
