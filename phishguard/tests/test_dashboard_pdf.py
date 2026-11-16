"""Session 5: dashboard extras (M8) and the PDF report (M7)."""
import re
import sys
from datetime import datetime
from pathlib import Path

import pytest
from flask import render_template

import app as app_module
from app import app
from modules.llm_client import LLMError
from modules.report import build_report_context
from pipeline import run_pipeline

SAMPLES = Path(__file__).parent.parent / "data" / "samples"
SAMPLE_NAMES = sorted(p.name for p in SAMPLES.glob("*.eml"))
LINK = re.compile(r'/report\.pdf\?id=([\w-]+)')


def analyse(client, name):
    page = client.post("/analyze", data={"sample": name}).data.decode()
    match = LINK.search(page)
    return page, match.group(1) if match else None


# ---------- FR-8.6 / FR-8.7: every demo email gives a PDF

def test_four_demo_samples_exist():
    assert len(SAMPLE_NAMES) >= 4 and {"forged_exam_cell.eml", "genuine_college.eml", "newsletter.eml"} <= set(SAMPLE_NAMES)


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_every_sample_runs_end_to_end_and_downloads_a_pdf(name):
    client = app.test_client()
    page, token = analyse(client, name)
    assert "Download report (PDF)" in page and token and "Plain-English report" in page
    r = client.get(f"/report.pdf?id={token}")
    assert r.status_code == 200 and r.mimetype == "application/pdf"
    assert r.data.startswith(b"%PDF-") and len(r.data) > 2000
    assert re.fullmatch(r'attachment; filename="phishguard_report_\d{8}_\d{4}\.pdf"', r.headers["Content-Disposition"])


def test_pdf_filename_uses_the_time_of_analysis():
    result = run_pipeline((SAMPLES / "genuine_college.eml").read_bytes())
    ctx = build_report_context(result, "sample: genuine_college.eml", now=datetime(2026, 11, 16, 13, 30))
    assert ctx["stamp"] == "20261116_1330" and ctx["generated"] == "16 Nov 2026, 13:30"
    token = app_module._remember(ctx)
    r = app.test_client().get(f"/report.pdf?id={token}")
    assert 'filename="phishguard_report_20261116_1330.pdf"' in r.headers["Content-Disposition"]


# ---------- error and edge cases

def test_unknown_or_missing_id_is_a_friendly_404():
    client = app.test_client()
    for url in ("/report.pdf?id=nope", "/report.pdf"):
        r = client.get(url)
        assert r.status_code == 404 and b"no longer available" in r.data and b"Download report" not in r.data


def test_download_button_only_appears_with_results():
    client = app.test_client()
    assert b"Download report" not in client.get("/").data
    bad = client.post("/analyze", data={"sample": ""}).data
    assert b"Please choose a .eml file first" in bad and b"Download report" not in bad


def test_missing_pdf_library_gives_a_clear_message_and_the_dashboard_still_works(monkeypatch):
    client = app.test_client()
    _, token = analyse(client, "genuine_college.eml")
    monkeypatch.setitem(sys.modules, "weasyprint", None)           # makes "from weasyprint import HTML" fail
    r = client.get(f"/report.pdf?id={token}")
    assert r.status_code == 500 and b"needs the WeasyPrint library" in r.data
    assert client.get("/").status_code == 200


def test_render_failure_is_reported_without_a_stack_trace(monkeypatch):
    import weasyprint
    client = app.test_client()
    _, token = analyse(client, "genuine_college.eml")

    class Broken:
        def __init__(self, **_):
            pass

        def write_pdf(self):
            raise RuntimeError("secret internals")
    monkeypatch.setattr(weasyprint, "HTML", Broken)
    r = client.get(f"/report.pdf?id={token}")
    assert r.status_code == 500 and b"could not be created" in r.data and b"secret internals" not in r.data


# ---------- in-memory store

def test_store_keeps_only_the_last_20_reports():
    first = app_module._remember({"stamp": "x"})
    tokens = [app_module._remember({"stamp": str(i)}) for i in range(25)]
    assert len(app_module.REPORTS) == 20
    assert first not in app_module.REPORTS and tokens[-1] in app_module.REPORTS and tokens[0] not in app_module.REPORTS
    assert len(set(tokens + [first])) == 26                        # tokens are unique


def test_store_holds_only_the_finished_report_not_the_email():
    client = app.test_client()
    _, token = analyse(client, "forged_exam_cell.eml")
    stored = app_module.REPORTS[token]
    assert "parsed" not in stored and "body_text" not in repr(stored) and "Immediate action required" not in repr(stored)


# ---------- FR-7.6 / FR-7.8: what the report contains and leaves out

def standalone_report_html(name="forged_exam_cell.eml"):
    result = run_pipeline((SAMPLES / name).read_bytes())
    ctx = build_report_context(result, f"sample: {name}")
    with app.test_request_context():
        return render_template("report.html", report=ctx)


def test_report_has_no_email_body_and_masks_recipients():
    html = standalone_report_html()
    assert "Immediate action required" not in html and "unless you verify" not in html
    assert "student@gmail.com" not in html and "***@gmail.com" in html


def test_short_tone_quotes_may_appear_as_evidence_but_never_the_body(ai):
    answer = {"score": 8, "tactics": [{"tactic": "credential_request", "quote": "verify your login credentials"}]}
    ai.answers = lambda system, user: answer if "<email>" in user else LLMError("report text not under test")
    html = standalone_report_html()
    assert "verify your login credentials" in html          # a short quoted phrase is evidence (at most 15 words)
    assert "Immediate action required" not in html and "Dear Student" not in html


def test_report_contains_everything_the_spec_lists():
    html = standalone_report_html()
    for needed in ("PhishGuard-AI Phishing Analysis Report", "Analysed ", "Phishing", "/ 100", "examcell@srmist.edu.in",
                   "URGENT: Your hall ticket will be cancelled in 24 hours", "185.234.72.19", "Checks performed",
                   "Sender (SPF, DKIM, DMARC)", "Link and domain", "Points breakdown", "Total score",
                   "Plain-English report", "What this email is", "What gave it away", "What you should do",
                   "verdict and score come from fixed rules", "does not include the email body"):
        assert needed in html, needed
    assert "@page" in html and "A4" in html


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_pdf_is_at_most_two_pages_and_the_footer_is_in_the_page_margin(name):
    from weasyprint import HTML
    html = standalone_report_html(name)
    assert len(HTML(string=html).render().pages) <= 2            # the footer must never sit alone on a page
    assert "@bottom-center" in html and 'class="rp-note rp-footer"' not in html


def test_dashboard_shows_the_footer_inline_but_the_pdf_page_does_not():
    page, _ = analyse(app.test_client(), "genuine_college.eml")
    assert 'class="rp-note rp-footer"' in page and "does not include the email body" in page


def test_report_is_inert_no_links_or_external_files():
    html = standalone_report_html()
    assert "<a " not in html and "http://srmlst" not in html and "203.0.113.50/login" not in html   # SAF-1: links are never rendered
    assert not re.search(r'(src|href)="https?:', html)


def test_dashboard_report_and_pdf_share_one_template():
    page, _ = analyse(app.test_client(), "forged_exam_cell.eml")
    pdf_html = standalone_report_html()
    for shared in ("PhishGuard-AI Phishing Analysis Report", "Checks performed", "Points breakdown", "What you should do"):
        assert shared in page and shared in pdf_html


# ---------- FR-8.1 / FR-8.2 / FR-8.5 on the page

def test_page_has_verdict_banner_dropzone_and_progress_indicator():
    client = app.test_client()
    index = client.get("/").data.decode()
    assert "Drag a .eml file here" in index and 'id="progress"' in index and "Checking" in index
    page, _ = analyse(client, "forged_exam_cell.eml")
    assert 'class="verdict phishing"' in page and "rate big phishing" in page


def test_raw_parsed_details_are_kept_but_collapsed():
    page, _ = analyse(app.test_client(), "forged_exam_cell.eml")
    assert '<details class="tech">' in page and "Parsed email details (technical)" in page
    assert "Immediate action required" in page          # the user's own screen may still show the body
