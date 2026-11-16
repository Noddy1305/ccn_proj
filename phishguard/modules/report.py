"""M7 - Report (the AI writes words only; code makes the verdict).

build_report_text(): explains an ALREADY DECIDED verdict in plain English: what the email is,
what gave it away, and what the reader should do. The AI sees only the verdict, score and
findings (FR-7.1), never the email itself. If the AI is down or answers badly, a template fills
the same three fields from the findings (FR-7.4), so a report always exists.

build_report_context(): gathers everything the report page and the PDF show into one plain dict
(FR-7.5, 7.6). It never holds the email body and masks recipient addresses (FR-7.8).
"""
import json
import re
from datetime import datetime

from modules import llm_client, load_config
from modules.llm_client import LLMError, mask_addresses
from modules.scoring import BANDS

FIELDS = ("summary", "evidence_explained", "recommended_actions")
MIN_WORDS, MAX_WORDS = 60, 320          # FR-7.2 asks for 120-200; this loose band only catches nonsense
CONTRADICTS_VERDICT = re.compile(r"\b(?:is|looks|appears|seems)\s+(?:completely\s+|totally\s+)?(?:safe|genuine|legitimate|harmless)\b", re.I)

ACTIONS = {
    "safe": "No action is needed. As with any email, think before you click, and open important sites by typing the address yourself.",
    "suspicious": "Do not click links, open attachments or reply yet. Contact the sender using a phone number or website you already trust, and ask if they really sent it.",
    "phishing": "Do not click anything, reply or open attachments. Delete the email and report it to your IT or security team. If you already clicked or entered a password, change that password straight away.",
}
VERDICT_WORDS = {
    "safe": "no meaningful warning signs",
    "suspicious": "some warning signs",
    "phishing": "strong signs of forgery or deception",
}

SYSTEM = """You write the plain-English explanation in a phishing-email report for a non-technical reader.

You are given a verdict, a score out of 100 and a list of findings that were ALREADY decided by fixed rules. You explain them. You never change, doubt or contradict the verdict, and you never invent findings that are not in the list.

Stick strictly to the findings:
- Use only facts written in the findings. Do not say who the email pretends to be, or what department it claims to be from, unless a finding says so.
- Keep each finding's meaning exactly. "Missing" or "none" is not "failed"; a lookalike link is not a lookalike sender.
- Do not add reasons or causes that are not in the findings. Say what was found, not why it happened.
  Wrong: "DMARC failed because the policy was weak". Right: "The DMARC check failed".
- Never mention points, scaling or arithmetic. Only the score out of 100 may appear as a number.
- Say the score only as "X out of 100". Do not call it perfect, high or low.

Write simple, calm English. 120 to 200 words in total across all three fields.
Reply with JSON only, in this shape:
{"summary": "what kind of email this is and the verdict", "evidence_explained": "what gave it away, in everyday words", "recommended_actions": "what the reader should do now"}"""


def findings_for_ai(result):
    """FR-7.1 / PRV-2: only verdict-level facts, with email addresses masked.

    Two details are left out because the AI kept misreading them as causes: the DMARC "policy p=none"
    text ("DMARC failed because the policy is none") and the tone score arithmetic ("scaled to 15 points")."""
    findings = []
    for r in result["contributions"]:
        evidence = mask_addresses(r["evidence"])
        if r["id"] == "tone_manipulation":
            evidence = "the wording of the email pressures the reader"
        findings.append({"flag": mask_addresses(r["title"]), "points": r["points"],
                         "evidence": re.sub(r"policy p=\w+;?\s*", "", evidence)})
    return findings


def template_text(result):
    """FR-7.4: the same three fields, written from the findings with no AI."""
    verdict, score = result["verdict"], result["score"]
    label = dict((k, n) for k, n, _, _ in BANDS)[verdict]
    summary = f"PhishGuard-AI found {VERDICT_WORDS[verdict]} in this email. Its risk score is {score} out of 100, which is rated {label}."
    if result["contributions"]:
        parts = [f"{r['title']} (+{r['points']:g} points): {r['evidence']}" for r in result["contributions"][:5]]
        evidence = "The score comes from these red flags, largest first. " + " ".join(p.rstrip(".") + "." for p in parts)
    else:
        evidence = "None of the checks found a red flag, so no points were added."
    if result["not_run"]:
        evidence += " These checks could not run and added no points: " + ", ".join(result["not_run"]) + "."
    return {"summary": summary, "evidence_explained": evidence, "recommended_actions": ACTIONS[verdict]}


def validate(answer, verdict):
    """Accept the AI's text only if it is complete, a sensible length, and does not argue with the verdict."""
    text = {}
    for field in FIELDS:
        value = answer.get(field)
        if not isinstance(value, str) or not value.strip():
            raise LLMError(f"The AI report is missing '{field}'.")
        text[field] = value.strip()
    words = sum(len(v.split()) for v in text.values())
    if not MIN_WORDS <= words <= MAX_WORDS:
        raise LLMError(f"The AI report was {words} words, outside the allowed length.")
    if verdict in ("suspicious", "phishing") and CONTRADICTS_VERDICT.search(" ".join(text.values())):
        raise LLMError("The AI report contradicted the verdict.")      # FR-7.3
    return text


CHECK_TITLES = {"sender": "Sender (SPF, DKIM, DMARC)", "links": "Link and domain", "tone": "Tone (AI)"}


def build_report_context(result, source, now=None):
    """Everything the report page and the PDF show, in one plain dict (FR-7.5, FR-7.6).

    This is the ONLY thing kept after an analysis (so the PDF button can fetch it later).
    It never holds the email body, and recipient addresses are masked (FR-7.8, PRV-1).
    """
    now = now or datetime.now()
    parsed = result["parsed"]
    sender = parsed["from"]
    labels = dict((k, n) for k, n, _, _ in BANDS)
    checks = []
    for c in result["checks"]:
        lines = [{"name": d["name"], "result": d["result"] + (f" (p={d['policy']})" if d.get("policy") else ""),
                  "evidence": d["evidence"]} for d in c.get("details", [])]
        checks.append({"title": CHECK_TITLES.get(c["check"], c["check"].capitalize()), "status": c["status"],
                       "error": c.get("error", ""), "lines": lines})
    return {
        "generated": now.strftime("%d %b %Y, %H:%M"), "stamp": now.strftime("%Y%m%d_%H%M"), "source": source,
        "verdict": result["band"], "verdict_label": labels[result["band"]],
        "score": result["total"], "raw_total": result["raw_total"],
        "email": {"from": f"{sender['name']} <{sender['address']}>" if sender["name"] else sender["address"],
                  "reply_to": parsed["reply_to"]["address"], "return_path": parsed["return_path"]["address"],
                  "to": [mask_addresses(a) for a in parsed["to"]], "subject": parsed["subject"],
                  "date": parsed["date"], "sending_ip": parsed["sending_ip"] or "not found"},
        "checks": checks, "flags": result["rows"], "not_run": result["not_run"], "text": result["report"],
    }


def build_report_text(result, config=None, try_ai=True):
    """Three text sections plus `source` ('ai' or 'template') and `note` (why the template was used)."""
    config = config or load_config()
    if try_ai:
        try:
            prompt = json.dumps({"verdict": result["verdict"], "score": result["score"],
                                 "findings": findings_for_ai(result)}, ensure_ascii=False)
            answer = llm_client.complete_json(SYSTEM, prompt, config["llm"]["report_max_tokens"], config)
            return {**validate(answer, result["verdict"]), "source": "ai", "note": ""}
        except LLMError as exc:
            note = str(exc)
    else:
        note = "The AI was not reachable."
    return {**template_text(result), "source": "template", "note": note}
