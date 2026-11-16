"""M8 - Flask app. Upload an email (or pick a sample), run the checks, show the dashboard, offer the PDF report."""
import secrets
import threading
from collections import OrderedDict
from pathlib import Path

import yaml
from flask import Flask, Response, render_template, request

from modules.parser import ParseError
from modules.report import build_report_context
from pipeline import run_pipeline

BASE = Path(__file__).parent
CONFIG = yaml.safe_load((BASE / "config.yaml").read_text())

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = CONFIG["app"]["max_upload_mb"] * 1024 * 1024 + 4096

SAMPLES_DIR = BASE / "data" / "samples"

# The PDF button needs the report of the email just analysed. We keep only the finished report (never the
# email itself) in memory, under a random token, for the last few analyses. Nothing is written to disk (PRV-1).
MAX_REPORTS = 20
REPORTS = OrderedDict()
REPORTS_LOCK = threading.Lock()   # the Flask dev server handles requests on several threads


def _remember(context):
    token = secrets.token_urlsafe(16)
    with REPORTS_LOCK:
        REPORTS[token] = context
        while len(REPORTS) > MAX_REPORTS:
            REPORTS.popitem(last=False)
    return token


def _sample_names():
    return sorted(p.name for p in SAMPLES_DIR.glob("*.eml"))


def _page(error=None, result=None, source="", selected="", report=None, report_id="", status=200):
    """One place that renders the page, so every route passes the same variables."""
    result = result or {}
    return render_template(
        "dashboard.html", samples=_sample_names(), selected=selected, source=source, error=error,
        parsed=result.get("parsed"), checks=result.get("checks", []), rows=result.get("rows", []),
        total=result.get("total", 0), band=result.get("band"), bands=result.get("bands", []),
        raw_total=result.get("raw_total", 0), not_run=result.get("not_run", []),
        report=report, report_id=report_id), status


@app.get("/")
def index():
    return _page()


@app.post("/analyze")
def analyze():
    """Upload a .eml (or pick a built-in sample), run the checks, show the results."""
    sample = request.form.get("sample")
    upload = request.files.get("email")
    source, selected = "", sample or ""
    try:
        if sample:
            path = SAMPLES_DIR / Path(sample).name  # .name blocks path tricks
            if not path.is_file():
                raise ParseError("Unknown sample email.")
            raw, source = path.read_bytes(), f"sample: {path.name}"
        elif upload and upload.filename:
            raw, source = upload.read(), f"uploaded file: {upload.filename}"  # memory only (PRV-1)
        else:
            raise ParseError("Please choose a .eml file first.")
        result = run_pipeline(raw)
        report = build_report_context(result, source)
        return _page(result=result, source=source, selected=selected, report=report, report_id=_remember(report))
    except ParseError as exc:
        return _page(error=str(exc), selected=selected)


@app.get("/report.pdf")
def report_pdf():
    """FR-8.7: the PDF for an email analysed in this session. Built from the same template as the dashboard report."""
    with REPORTS_LOCK:
        report = REPORTS.get(request.args.get("id", ""))
    if report is None:
        return _page(error="That report is no longer available. Please analyse the email again.", status=404)
    try:
        from weasyprint import HTML          # imported here so a missing PDF library cannot break the dashboard
    except (ImportError, OSError):
        return _page(error="PDF export needs the WeasyPrint library, which is not installed on this computer. "
                           "The report on this page is still complete.", status=500)
    try:
        pdf = HTML(string=render_template("report.html", report=report)).write_pdf()
    except Exception:                         # a rendering fault must not show a stack trace to the user
        return _page(error="The PDF could not be created. The report on this page is still complete.", status=500)
    filename = f"phishguard_report_{report['stamp']}.pdf"      # time of the analysis, not of the download
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.errorhandler(413)
def too_large(_):
    return _page(error="File is larger than 5 MB.", status=413)


if __name__ == "__main__":
    app.run(host=CONFIG["app"]["host"], port=CONFIG["app"]["port"], debug=True)
