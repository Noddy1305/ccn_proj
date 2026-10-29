"""M6 - Risk scoring engine.

Turns every check's findings into ONE score (0-100) and a verdict, using fixed rules
from config.yaml. No AI, no randomness: the same input always gives the same score
(FR-6.4). This is the only place that decides the verdict.
"""
import math

from modules import load_config

# Legend shown on the dashboard. Keys match verdict_for().
BANDS = [
    ("safe", "Safe", "0-29", "Looks genuine. No meaningful warning signs were found. Normal caution still applies."),
    ("suspicious", "Suspicious", "30-59",
     "Some warning signs. Do not click links or reply until you have confirmed the sender another way."),
    ("phishing", "Phishing", "60-100",
     "Strong evidence of forgery or deception. Do not click, reply or open anything. Delete or report it."),
]


def verdict_for(score, config):
    """FR-6.2: map the score to safe / suspicious / phishing using the config thresholds."""
    t = config["thresholds"]
    if score >= t["phishing_from"]:
        return "phishing"
    return "suspicious" if score >= t["suspicious_from"] else "safe"


def points_for(finding, config):
    """Points for one finding. The config table is the single source of truth, so changing a
    weight in config.yaml changes the score without touching any check. A finding id the
    config does not know keeps the points the check gave it."""
    return config["points"].get(finding["id"], finding.get("points", 0))


def tone_points(check, config):
    """Tone (LLM) score s (0-10) -> weight x s, capped. Returns (points, evidence) or None."""
    if check.get("status") == "error" or check.get("score") is None:
        return None
    s = max(0.0, min(10.0, float(check["score"])))
    cfg = config["tone"]
    pts = round(min(cfg["max_points"], cfg["weight"] * s), 1)
    return pts, f"Manipulation score {s:g}/10 x {cfg['weight']} (capped at {cfg['max_points']})"


def score_email(checks, config=None):
    """FR-6.1 to 6.4. `checks` is the list of check results (sender, links, ...).

    Returns:
      score         int 0-100 (sum of points, halves rounded up, capped at 100)
      raw_total     the sum before capping (shown on the page when it exceeds 100)
      verdict       safe / suspicious / phishing
      contributions findings that added points, largest first
      by_check      points per check
      not_run       checks that errored: they add 0 points and show as "could not run"
    """
    config = config or load_config()
    rows, not_run, by_check = [], [], {}

    for order, check in enumerate(checks):
        name = check["check"]
        if check.get("status") == "error":
            not_run.append(name)               # PRD section 6: an errored check adds 0 points
            continue
        seen = set()                           # each finding counts once per email
        if name == "tone":
            tone = tone_points(check, config)
            if tone and tone[0] > 0:
                rows.append({"check": "tone", "id": "tone_manipulation", "title": "Manipulative wording (AI)",
                             "points": tone[0], "evidence": tone[1], "_order": order})
            continue
        for f in check.get("findings", []):
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            pts = points_for(f, config)
            if pts > 0:
                rows.append({"check": name, "id": f["id"], "title": f["title"], "points": pts,
                             "evidence": f["evidence"], "_order": order})

    # FR-6.3: largest first. Ties broken by check order then id, so output is always identical.
    rows.sort(key=lambda r: (-r["points"], r["_order"], r["id"]))
    for r in rows:
        by_check[r["check"]] = round(by_check.get(r["check"], 0) + r["points"], 1)
        del r["_order"]

    raw_total = round(sum(r["points"] for r in rows), 1)
    # Rounding rule: halves round UP (29.5 -> 30), always. Then cap at 100 (FR-6.1).
    score = min(100, math.floor(raw_total + 0.5))
    return {"score": score, "raw_total": raw_total, "verdict": verdict_for(score, config),
            "contributions": rows, "by_check": by_check, "not_run": not_run}
