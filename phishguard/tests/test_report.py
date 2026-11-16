import json

import pytest

from modules import load_config
from modules.llm_client import LLMError
from modules.report import build_report_text, template_text

CFG = load_config()
FIELDS = ("summary", "evidence_explained", "recommended_actions")


def result(verdict="phishing", score=70, rows=None, not_run=()):
    rows = [{"check": "sender", "id": "dmarc_fail", "title": "DMARC failed", "points": 25,
             "evidence": "Reply-To attacker@evil.com differs from the From domain"}] if rows is None else rows
    return {"verdict": verdict, "score": score, "contributions": rows, "not_run": list(not_run)}


def good(verdict="phishing", filler=50):
    words = " ".join(["calm"] * filler)
    return {f: f"{f} {words}" for f in FIELDS}


# ---------- template fallback (FR-7.4)

@pytest.mark.parametrize("verdict", ["safe", "suspicious", "phishing"])
def test_template_fills_all_three_fields_for_every_verdict(verdict):
    t = template_text(result(verdict, 5))
    assert all(t[f].strip() for f in FIELDS) and "5 out of 100" in t["summary"]


def test_template_lists_flags_and_unrun_checks():
    t = template_text(result(not_run=["tone"]))
    assert "DMARC failed (+25 points)" in t["evidence_explained"] and "tone" in t["evidence_explained"]
    assert "no points were added" in template_text(result("safe", 0, rows=[]))["evidence_explained"]


def test_unreachable_ai_gives_template_with_a_reason(ai):
    r = build_report_text(result(), CFG)
    assert r["source"] == "template" and "could not be reached" in r["note"] and r["summary"]


def test_try_ai_false_never_calls_the_ai(ai):
    r = build_report_text(result(), CFG, try_ai=False)
    assert r["source"] == "template" and ai.calls == []


# ---------- AI text accepted / rejected (FR-7.2, 7.3)

def test_good_ai_text_is_used(ai):
    ai.answers = lambda s, u: good()
    r = build_report_text(result(), CFG)
    assert r["source"] == "ai" and r["note"] == "" and r["summary"].startswith("summary calm")


@pytest.mark.parametrize("answer", [
    {"summary": "x", "evidence_explained": "y"},                                  # missing field
    {"summary": "ok " * 40, "evidence_explained": "", "recommended_actions": "z " * 40},   # empty field
    {"summary": "short", "evidence_explained": "short", "recommended_actions": "short"},   # far too short
    {f: "word " * 200 for f in FIELDS},                                           # far too long
    {"summary": 1, "evidence_explained": 2, "recommended_actions": 3},            # wrong types
])
def test_unusable_ai_text_falls_back_to_template(ai, answer):
    ai.answers = lambda s, u: answer
    r = build_report_text(result(), CFG)
    assert r["source"] == "template" and r["note"]


def test_text_that_calls_a_phishing_email_safe_is_rejected(ai):
    bad = good()
    bad["summary"] = "This email is safe and looks fine. " + bad["summary"]
    ai.answers = lambda s, u: bad
    assert build_report_text(result("phishing"), CFG)["source"] == "template"
    assert build_report_text(result("safe", 3, rows=[]), CFG)["source"] == "ai"   # same words are fine for a safe verdict


def test_contradiction_rule_only_fires_when_the_email_itself_is_called_safe():
    from modules.report import contradicts_verdict
    for text in ("This email is safe and looks fine.", "The email appears to be legitimate.", "The verdict is safe.",
                 "The message looks completely genuine.", "Nothing is wrong. It is harmless."):
        assert contradicts_verdict(text), text
    for text in ("It lacks two standard security signatures that help prove it is legitimate.",       # real AI reports
                 "There is no DKIM signature or DMARC record to prove the email is legitimate.",
                 "This email is not safe.", "The verdict is suspicious.", "It is safe to delete this email.",
                 "We cannot confirm the email is genuine.", "Check that the website is genuine before you log in."):
        assert not contradicts_verdict(text), text


def test_ai_error_message_is_kept_as_the_note(ai):
    ai.answers = lambda s, u: LLMError("The AI returned broken JSON.")
    assert build_report_text(result(), CFG)["note"] == "The AI returned broken JSON."


# ---------- privacy (FR-7.1, PRV-2)

def test_ai_is_not_fed_the_details_it_misreads_as_causes(ai):
    rows = [{"check": "sender", "id": "dmarc_fail", "title": "DMARC failed", "points": 25,
             "evidence": "From domain srmist.edu.in, policy p=none; SPF fail for evil.com (did not pass), no DKIM found"},
            {"check": "tone", "id": "tone_manipulation", "title": "Manipulative wording (AI)", "points": 12,
             "evidence": "Manipulation score 8/10 x 1.5 (capped at 15)"}]
    ai.answers = lambda s, u: good()
    build_report_text(result(rows=rows), CFG)
    sent = ai.calls[0]["user"]
    assert "p=none" not in sent and "x 1.5" not in sent and "capped" not in sent
    assert "From domain srmist.edu.in, SPF fail for evil.com" in sent and "pressures the reader" in sent


def test_ai_gets_only_verdict_score_and_masked_findings(ai):
    ai.answers = lambda s, u: good()
    build_report_text(result(), CFG)
    sent = json.loads(ai.calls[0]["user"])
    assert set(sent) == {"verdict", "score", "findings"} and sent["verdict"] == "phishing" and sent["score"] == 70
    assert "attacker@" not in ai.calls[0]["user"] and "***@evil.com" in ai.calls[0]["user"]
    assert "never change" in ai.calls[0]["system"]
