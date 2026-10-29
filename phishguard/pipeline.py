"""Runs M1, then the checks in parallel, then M6. Later sessions add M4, M5 and M7."""
from concurrent.futures import ThreadPoolExecutor

from modules.links import check_links
from modules.parser import parse_eml
from modules.scoring import BANDS, score_email
from modules.sender import check_sender


def run_pipeline(raw):
    """Parse the email, run the checks side by side (NFR-2), then score. Raises ParseError for bad files."""
    parsed = parse_eml(raw)
    with ThreadPoolExecutor(max_workers=2) as pool:
        sender_job = pool.submit(check_sender, parsed, raw)
        links_job = pool.submit(check_links, parsed)
        checks = [sender_job.result(), links_job.result()]
    result = score_email(checks)
    return {"parsed": parsed, "checks": checks, "rows": result["contributions"], "total": result["score"], "raw_total": result["raw_total"],
            "band": result["verdict"], "bands": BANDS, "not_run": result["not_run"],
            "by_check": result["by_check"]}
