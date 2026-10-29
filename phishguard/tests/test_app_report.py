"""Integration tests for report generation in app."""
from app import app


def test_report_route_renders_ok():
    c = app.test_client()
    resp = c.get("/report")
    assert resp.status_code == 200
    assert b"Threat Assessment &amp; Forensic Analysis Report" in resp.data
    assert b"PhishGuard-AI" in resp.data


def test_report_sample_renders_verdict_and_evidence():
    c = app.test_client()
    resp = c.get("/report?sample=forged_exam_cell.eml")
    assert resp.status_code == 200
    assert b"phishing" in resp.data or b"PHISHING" in resp.data
    assert b"Executive Summary" in resp.data
    assert b"Print / Save as PDF" in resp.data


def test_dashboard_renders_executive_summary_after_analyze():
    c = app.test_client()
    resp = c.post("/analyze", data={"sample": "forged_exam_cell.eml"})
    assert resp.status_code == 200
    assert b"Executive Summary &amp; Plain-English Report" in resp.data
    assert b"Download / Print Report" in resp.data
