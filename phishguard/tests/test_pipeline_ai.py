"""The AI parts wired into the whole pipeline and the page."""
import re
from pathlib import Path

from app import app
from modules.llm_client import LLMError
from pipeline import run_pipeline

SAMPLES = Path(__file__).parent.parent / "data" / "samples"
FIELDS = ("summary", "evidence_explained", "recommended_actions")


def fake_ai(score):
    """Answers the tone prompt with a quote taken from the email's own subject, and the report prompt with valid text."""
    def answer(system, user):
        if "<email>" in user:
            subject = re.search(r"Subject: (.+)", user).group(1).strip()
            return {"score": score, "tactics": [{"tactic": "urgency", "quote": subject}]}
        return {f: " ".join([f] + ["calm"] * 50) for f in FIELDS}
    return answer


def raw(name="forged_exam_cell.eml"):
    return (SAMPLES / name).read_bytes()


def test_pipeline_runs_without_any_ai_and_still_gives_a_verdict(ai):
    r = run_pipeline(raw())
    assert r["report"]["source"] == "template" and "tone" in r["not_run"]
    assert len(ai.calls) == 1                       # tone found the AI unreachable, so the report did not wait again


def test_tone_adds_points_but_never_changes_how_the_verdict_is_decided(ai):
    base = run_pipeline(raw("genuine_college.eml"))
    ai.answers = fake_ai(10)
    r = run_pipeline(raw("genuine_college.eml"))
    tone_rows = [x for x in r["rows"] if x["check"] == "tone"]
    assert tone_rows and tone_rows[0]["points"] == 20
    assert r["total"] == min(100, base["total"] + 20)
    assert r["report"]["source"] == "ai" and r["band"] in ("safe", "suspicious", "phishing")


def test_page_shows_tone_card_and_report_with_ai(ai):
    ai.answers = fake_ai(7)
    page = app.test_client().post("/analyze", data={"sample": "forged_exam_cell.eml"}).data.decode()
    assert "Tone (AI) check" in page and "Plain-English report" in page
    assert "explanation was written by an AI" in page and "What you should do" in page


def test_page_shows_template_report_when_ai_is_down(ai):
    page = app.test_client().post("/analyze", data={"sample": "forged_exam_cell.eml"}).data.decode()
    assert "Plain-English report" in page and "filled in from a template" in page
    assert "could not be reached" in page and "Could not run:" in page and "tone" in page.split("Could not run:")[1][:60]


def test_ai_text_is_escaped_on_the_page(ai):
    evil = {f: "<script>alert(1)</script> " + " ".join(["calm"] * 50) for f in FIELDS}
    ai.answers = lambda system, user: LLMError("tone skipped") if "<email>" in user else evil
    page = app.test_client().post("/analyze", data={"sample": "forged_exam_cell.eml"}).data.decode()
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
