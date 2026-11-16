"""Runs M1, then the checks in parallel, then M6, then the report text (M7). Session 6 adds M4."""
from concurrent.futures import ThreadPoolExecutor

from modules.links import check_links
from modules.parser import parse_eml
from modules.report import build_report_text
from modules.scoring import BANDS, score_email
from modules.sender import check_sender
from modules.tone import check_tone


def run_pipeline(raw):
    """Parse the email, run the checks side by side (NFR-2), score, then explain. Raises ParseError for bad files."""
    parsed = parse_eml(raw)
    with ThreadPoolExecutor(max_workers=3) as pool:
        sender_job = pool.submit(check_sender, parsed, raw)
        links_job = pool.submit(check_links, parsed)
        tone_job = pool.submit(check_tone, parsed)
        checks = [sender_job.result(), links_job.result(), tone_job.result()]
    result = score_email(checks)
    # If the AI could not even be reached for the tone check, do not wait for it a second time.
    report = build_report_text(result, try_ai=not checks[2].get("llm_unreachable"))
    return {"parsed": parsed, "checks": checks, "rows": result["contributions"], "total": result["score"], "raw_total": result["raw_total"],
            "band": result["verdict"], "bands": BANDS, "not_run": result["not_run"],
            "by_check": result["by_check"], "report": report}
