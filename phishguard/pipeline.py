"""Runs M1, then the checks in parallel, then M6, then the report text (M7)."""
from concurrent.futures import ThreadPoolExecutor

from modules import offline
from modules.certificate import check_certificate
from modules.links import check_links
from modules.parser import parse_eml
from modules.report import build_report_text
from modules.scoring import BANDS, score_email
from modules.sender import check_sender
from modules.tone import check_tone


def run_pipeline(raw):
    """Parse the email, run the checks side by side (NFR-2), score, then explain. Raises ParseError for bad files."""
    parsed = parse_eml(raw)
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(check_sender, parsed, raw), pool.submit(check_links, parsed),
                pool.submit(check_certificate, parsed), pool.submit(check_tone, parsed)]
        checks = [job.result() for job in jobs]
    if offline.mode() == "replay":       # be honest on the page: these answers were not looked up just now
        for check in checks:
            for d in check.get("details", []):
                if d.get("source") == "live":
                    d["source"] = "saved answer (offline)"
    result = score_email(checks)
    # If the AI could not even be reached for the tone check, do not wait for it a second time.
    tone = next(c for c in checks if c["check"] == "tone")
    report = build_report_text(result, try_ai=not tone.get("llm_unreachable"))
    return {"parsed": parsed, "checks": checks, "rows": result["contributions"], "total": result["score"], "raw_total": result["raw_total"],
            "band": result["verdict"], "bands": BANDS, "not_run": result["not_run"],
            "by_check": result["by_check"], "report": report}
