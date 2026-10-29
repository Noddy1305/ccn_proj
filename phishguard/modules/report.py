"""M7 - Report generator module (LLM + Template Fallback).

Generates plain-English threat reporting from the rule-based verdict (M6)
and technical findings (FR-7.1 to FR-7.4).
The LLM never makes the verdict; it only writes the three explanatory fields:
  - summary (what this email is)
  - evidence_explained (what gave it away)
  - recommended_actions (what the reader should do)

If the LLM is unavailable or offline, an intelligent deterministic template
fills all three fields (FR-7.4).
"""
from datetime import datetime, timezone
import re

from modules import load_config
from modules.llm_client import call_llm

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

REPORT_SYSTEM_PROMPT = (
    "You are an expert cybersecurity advisor creating a concise, plain-English incident report for an email analysis. "
    "You are provided with the rule-based verdict, numerical risk score, and technical findings. "
    "Do NOT contradict or alter the verdict. Write in clear, professional English accessible to non-technical users. "
    "Return STRICT JSON with exactly three fields (120-200 words total):\n"
    "{\n"
    '  "summary": "<2-3 sentences explaining what this email is and whether it is safe or fraudulent>",\n'
    '  "evidence_explained": "<2-3 sentences explaining the key technical indicators that determined this score>",\n'
    '  "recommended_actions": "<bulleted or numbered recommendations for the recipient>"\n'
    "}"
)


def mask_recipient(addr):
    """Mask email recipient addresses (e.g., student@example.com -> s***t@example.com) (FR-7.8)."""
    if not addr:
        return "—"
    if "@" not in addr:
        return "[redacted]"
    user, domain = addr.split("@", 1)
    if len(user) <= 2:
        masked_user = user[0] + "*"
    else:
        masked_user = user[0] + ("*" * (len(user) - 2)) + user[-1]
    return f"{masked_user}@{domain}"


def template_fallback_report(verdict, score, contributions):
    """Deterministic, rule-based report generator when LLM is unavailable (FR-7.4)."""
    top_flags = [c["title"] for c in contributions[:3]]

    if verdict == "phishing":
        summary = (
            f"This email has been confirmed as PHISHING with an elevated risk score of {score}/100. "
            "It displays multiple severe technical anomalies indicative of domain spoofing, identity theft, "
            "or malicious credential harvesting."
        )
        if top_flags:
            flags_str = ", ".join(top_flags)
            evidence = (
                f"The analysis detected critical security failures, primarily: {flags_str}. "
                "The message origin fails sender domain authentication and contains deceptive destination indicators."
            )
        else:
            evidence = (
                f"High-severity indicators were identified across multiple inspection layers totaling {score} risk points."
            )
        actions = (
            "1. Do NOT click any links, open attachments, or reply to this sender.\n"
            "2. Report this message to your security operations or IT administration.\n"
            "3. Delete or isolate the message immediately."
        )

    elif verdict == "suspicious":
        summary = (
            f"This email has been classified as SUSPICIOUS with a risk score of {score}/100. "
            "While it may not exhibit catastrophic fraud signatures, it presents noticeable red flags that require vigilance."
        )
        if top_flags:
            flags_str = ", ".join(top_flags)
            evidence = (
                f"Warning indicators include: {flags_str}. "
                "These attributes are commonly associated with newly configured marketing campaigns, misconfigured servers, or indirect phishing attempts."
            )
        else:
            evidence = f"Cumulative risk findings reached {score} points, exceeding the safe threshold."
        actions = (
            "1. Verify the authenticity of this message using a known out-of-band contact channel.\n"
            "2. Avoid clicking embedded links; navigate to the official service website manually.\n"
            "3. Do not submit login credentials or personal information."
        )

    else:  # safe
        summary = (
            f"This email has been verified as SAFE with a risk score of {score}/100. "
            "No substantial indicators of spoofing, malicious links, or manipulative intent were detected."
        )
        evidence = (
            "Sender authentication (SPF/DKIM/DMARC) verified successfully or exhibited no critical discrepancies. "
            "Embedded links resolve to established, reputable domains with no detected brand impersonation."
        )
        actions = (
            "1. Standard email hygiene still applies.\n"
            "2. Proceed normally, but remain cautious if subsequent messages request sensitive information."
        )

    return {
        "summary": summary,
        "evidence_explained": evidence,
        "recommended_actions": actions,
        "is_ai_generated": False,
    }


def generate_report(parsed, checks, scoring_result, llm_fn=None, config=None):
    """Build the complete report data dictionary (FR-7.1 to 7.8)."""
    config = config or load_config()
    verdict = scoring_result.get("verdict", "safe")
    score = scoring_result.get("score", 0)
    contributions = scoring_result.get("contributions", [])

    # Format findings list for LLM (FR-7.1: not the raw email)
    findings_summary = [
        f"- {c['title']} (+{c['points']} pts): {c['evidence']}"
        for c in contributions
    ]
    findings_text = "\n".join(findings_summary) if findings_summary else "No technical red flags found (0 points)."

    user_prompt = (
        f"Verdict: {verdict.upper()}\n"
        f"Numerical Risk Score: {score} out of 100\n"
        f"Sender: {parsed.get('from', {}).get('address', 'unknown')}\n"
        f"Subject: {parsed.get('subject', '(no subject)')}\n\n"
        f"Technical Findings:\n{findings_text}\n"
    )

    call = llm_fn or call_llm
    res = call(user_prompt, system_prompt=REPORT_SYSTEM_PROMPT, json_mode=True, config=config)

    if (
        isinstance(res, dict)
        and res.get("summary")
        and res.get("evidence_explained")
        and res.get("recommended_actions")
    ):
        text_data = {
            "summary": str(res["summary"]).strip(),
            "evidence_explained": str(res["evidence_explained"]).strip(),
            "recommended_actions": str(res["recommended_actions"]).strip(),
            "is_ai_generated": True,
        }
    else:
        text_data = template_fallback_report(verdict, score, contributions)

    now = datetime.now(timezone.utc)
    timestamp_str = now.strftime("%Y-%m-%d %H:%M UTC")
    report_id = f"PG-{now.strftime('%Y%m%d-%H%M%S')}"

    # Mask recipients for privacy (FR-7.8)
    masked_recipients = [mask_recipient(addr) for addr in parsed.get("to", [])]

    return {
        "report_id": report_id,
        "timestamp": timestamp_str,
        "verdict": verdict,
        "score": score,
        "raw_total": scoring_result.get("raw_total", score),
        "summary": text_data["summary"],
        "evidence_explained": text_data["evidence_explained"],
        "recommended_actions": text_data["recommended_actions"],
        "is_ai_generated": text_data["is_ai_generated"],
        "from_name": parsed.get("from", {}).get("name", ""),
        "from_address": parsed.get("from", {}).get("address", ""),
        "reply_to": parsed.get("reply_to", {}).get("address") or "—",
        "to_list": masked_recipients,
        "subject": parsed.get("subject", "(no subject)"),
        "date": parsed.get("date", "—"),
        "sending_ip": parsed.get("sending_ip") or "not found",
        "contributions": contributions,
        "checks": checks,
        "not_run": scoring_result.get("not_run", []),
    }
