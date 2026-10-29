"""Runs M1, then the checks in parallel (M2, M3, M5), then scoring (M6) and report (M7)."""
from concurrent.futures import ThreadPoolExecutor

from modules.links import check_links
from modules.parser import parse_eml
from modules.report import generate_report
from modules.scoring import BANDS, score_email
from modules.sender import check_sender
from modules.tone import check_tone


def run_pipeline(raw, llm_fn=None):
    """Parse email, run checks side by side (NFR-2), score with fixed rules (M6), and generate report (M7)."""
    parsed = parse_eml(raw)
    with ThreadPoolExecutor(max_workers=3) as pool:
        sender_job = pool.submit(check_sender, parsed, raw)
        links_job = pool.submit(check_links, parsed)
        tone_job = pool.submit(check_tone, parsed, llm_fn=llm_fn)
        checks = [sender_job.result(), links_job.result(), tone_job.result()]
    scoring = score_email(checks)
    report = generate_report(parsed, checks, scoring, llm_fn=llm_fn)
    return {
        "parsed": parsed,
        "checks": checks,
        "rows": scoring["contributions"],
        "total": scoring["score"],
        "raw_total": scoring["raw_total"],
        "band": scoring["verdict"],
        "bands": BANDS,
        "not_run": scoring["not_run"],
        "by_check": scoring["by_check"],
        "report": report,
    }
