"""M8 (early version) - Flask app. Upload an email, show parsed fields and check results."""
from pathlib import Path

import yaml
from flask import Flask, render_template, request

from modules.parser import ParseError
from pipeline import run_pipeline

BASE = Path(__file__).parent
CONFIG = yaml.safe_load((BASE / "config.yaml").read_text())

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = CONFIG["app"]["max_upload_mb"] * 1024 * 1024 + 4096

SAMPLES_DIR = BASE / "data" / "samples"


def _sample_names():
    return sorted(p.name for p in SAMPLES_DIR.glob("*.eml"))


def _page(error=None, result=None, source="", selected="", status=200):
    """One place that renders the page, so every route passes the same variables."""
    result = result or {}
    return render_template(
        "dashboard.html", samples=_sample_names(), selected=selected, source=source, error=error,
        parsed=result.get("parsed"), checks=result.get("checks", []), rows=result.get("rows", []),
        total=result.get("total", 0), band=result.get("band"), bands=result.get("bands", []),
        raw_total=result.get("raw_total", 0), not_run=result.get("not_run", [])), status


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
        return _page(result=run_pipeline(raw), source=source, selected=selected)
    except ParseError as exc:
        return _page(error=str(exc), selected=selected)


@app.errorhandler(413)
def too_large(_):
    return _page(error="File is larger than 5 MB.", status=413)


if __name__ == "__main__":
    app.run(host=CONFIG["app"]["host"], port=CONFIG["app"]["port"], debug=True)
