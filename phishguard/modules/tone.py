"""M5 - Tone analysis module (LLM).

Inspects the email subject and body for psychological manipulation:
urgency, artificial pressure, threats, credential harvesting prompts,
and authority impersonation. Returns a manipulation score (0-10) which
adds at most 15 capped points in M6.

Privacy (PRV-2): all email addresses are masked before sending to the LLM.
Fallback (NFR-3): if the LLM is unavailable or fails, returns status 'error'
which adds 0 points and does not interrupt the pipeline.
"""
import re

from modules import load_config
from modules.llm_client import call_llm

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

TONE_SYSTEM_PROMPT = (
    "You are an expert cybersecurity analyst assessing email text for social engineering and phishing tactics. "
    "Analyze the provided email subject and body. Detect manipulation techniques including:\n"
    "- Urgency or artificial deadlines ('act within 24 hours', 'immediate action required')\n"
    "- Threats or consequences ('account will be suspended', 'legal action')\n"
    "- Credential or sensitive info harvesting ('confirm password', 'verify login')\n"
    "- Reward bait or unrealistic offers ('lottery winner', 'unexpected refund')\n"
    "- False authority impersonation ('IT Helpdesk', 'Dean of Academic Affairs')\n\n"
    "Respond with STRICT JSON only in this format:\n"
    "{\n"
    '  "score": <float between 0.0 and 10.0 representing manipulation intensity>,\n'
    '  "tactics": [\n'
    '    {"tactic": "<tactic name>", "quote": "<exact short quote from text>"}\n'
    "  ]\n"
    "}"
)


def mask_email_addresses(text):
    """Replace email addresses with [email_redacted] (PRV-2)."""
    if not text:
        return ""
    return EMAIL_REGEX.sub("[email_redacted]", text)


def check_tone(parsed, llm_fn=None, config=None):
    """Analyze the email subject and body for manipulative tone.

    Returns findings in the standard check format for M6.
    """
    config = config or load_config()
    subject = parsed.get("subject") or ""
    body = parsed.get("body_text") or ""

    # If completely empty body and subject, pass cleanly with 0 score
    if not subject.strip() and not body.strip():
        return {
            "check": "tone",
            "status": "pass",
            "score": 0.0,
            "tactics": [],
            "findings": [],
            "details": [{"name": "Manipulation score", "result": "0/10", "evidence": "Empty email content", "source": "analyzer"}],
        }

    # Mask email addresses and truncate body to 4000 chars (README section 7)
    masked_subject = mask_email_addresses(subject)
    masked_body = mask_email_addresses(body)[:4000]

    user_prompt = f"Subject: {masked_subject}\n\nBody:\n{masked_body}"

    call = llm_fn or call_llm
    res = call(user_prompt, system_prompt=TONE_SYSTEM_PROMPT, json_mode=True, config=config)

    if not isinstance(res, dict) or "score" not in res:
        # LLM not configured or offline: return status 'error' so M6 adds 0 points and marks as not_run
        return {
            "check": "tone",
            "status": "error",
            "error": "LLM tone check unavailable (offline fallback active)",
            "score": None,
            "tactics": [],
            "findings": [],
            "details": [],
        }

    try:
        raw_score = float(res["score"])
        score = max(0.0, min(10.0, raw_score))
    except (ValueError, TypeError):
        return {
            "check": "tone",
            "status": "error",
            "error": "Invalid tone score format returned by LLM",
            "score": None,
            "tactics": [],
            "findings": [],
            "details": [],
        }

    tactics = res.get("tactics", []) if isinstance(res.get("tactics"), list) else []
    findings = []
    details = []

    cfg_tone = config.get("tone", {"weight": 1.5, "max_points": 15})
    weight = cfg_tone.get("weight", 1.5)
    max_pts = cfg_tone.get("max_points", 15)

    if score > 0:
        pts = round(min(max_pts, weight * score), 1)
        tactic_names = [t.get("tactic", "pressure") for t in tactics if isinstance(t, dict)]
        tactics_summary = ", ".join(tactic_names[:3]) if tactic_names else "psychological urgency"
        findings.append({
            "id": "tone_manipulation",
            "title": "Manipulative wording (AI)",
            "points": pts,
            "evidence": f"Manipulation score {score:g}/10 ({len(tactics)} tactics flagged: {tactics_summary})",
        })

    for t in tactics:
        if isinstance(t, dict) and "tactic" in t:
            quote = t.get("quote", "")
            details.append({
                "name": t.get("tactic", "").capitalize(),
                "result": "Detected",
                "evidence": f'"{quote}"' if quote else "Identified in email text",
                "source": "LLM tone analysis",
            })

    if not details:
        details.append({
            "name": "Manipulation score",
            "result": f"{score:g}/10",
            "evidence": "No specific manipulation tactics flagged" if score == 0 else f"General manipulation index {score:g}/10",
            "source": "LLM tone analysis",
        })

    status = "fail" if score >= 6.0 else ("warn" if score > 0 else "pass")
    return {
        "check": "tone",
        "status": status,
        "score": score,
        "tactics": tactics,
        "findings": findings,
        "details": details,
    }
