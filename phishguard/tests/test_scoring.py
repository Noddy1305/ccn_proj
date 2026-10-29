import copy
import random

from modules import load_config
from modules.scoring import score_email, verdict_for

CFG = load_config()


def finding(fid, points=0, check_title=None):
    return {"id": fid, "title": check_title or fid, "points": points, "evidence": f"evidence for {fid}"}


def check(name, *findings, status="warn", **extra):
    return {"check": name, "status": status, "findings": list(findings), **extra}


# ---------- FR-6.1 adding and capping

def test_points_are_added_up():
    r = score_email([check("sender", finding("dmarc_fail"), finding("spf_fail")),
                     check("links", finding("raw_ip_link"))], CFG)
    assert r["score"] == 25 + 20 + 15
    assert r["by_check"] == {"sender": 45, "links": 15}


def test_score_is_capped_at_100():
    r = score_email([check("sender", finding("dmarc_fail"), finding("spf_fail"), finding("dkim_invalid")),
                     check("links", finding("lookalike_domain"), finding("domain_age_new"),
                           finding("raw_ip_link"), finding("link_text_mismatch"))], CFG)
    assert sum(c["points"] for c in r["contributions"]) > 100
    assert r["score"] == 100 and r["verdict"] == "phishing"


def test_no_findings_scores_zero_safe():
    r = score_email([check("sender", status="pass"), check("links", status="pass")], CFG)
    assert r["score"] == 0 and r["verdict"] == "safe" and r["contributions"] == []


# ---------- FR-6.2 thresholds (boundaries)

def test_verdict_boundaries():
    assert [verdict_for(s, CFG) for s in (0, 29, 30, 59, 60, 100)] == \
        ["safe", "safe", "suspicious", "suspicious", "phishing", "phishing"]


# ---------- FR-6.3 contributing findings, largest first

def test_contributions_sorted_largest_first_and_zero_point_findings_left_out():
    r = score_email([check("sender", finding("dkim_none"), finding("dmarc_fail"), finding("mystery", 0)),
                     check("links", finding("raw_ip_link"))], CFG)
    assert [c["id"] for c in r["contributions"]] == ["dmarc_fail", "raw_ip_link", "dkim_none"]
    assert all({"check", "id", "title", "points", "evidence"} <= set(c) for c in r["contributions"])


# ---------- FR-6.4 determinism

def test_same_input_same_output_and_order_of_checks_does_not_change_score():
    checks = [check("sender", finding("spf_softfail"), finding("domain_mismatch")),
              check("links", finding("domain_age_recent"), finding("domain_unresolved"))]
    first = score_email(checks, CFG)
    assert score_email(checks, CFG) == first
    shuffled = checks[:]
    random.Random(1).shuffle(shuffled)
    assert score_email(shuffled, CFG)["score"] == first["score"]
    assert score_email(copy.deepcopy(checks), CFG) == first


def test_equal_points_have_stable_order():
    a = score_email([check("links", finding("raw_ip_link"), finding("brand_in_domain"))], CFG)
    b = score_email([check("links", finding("brand_in_domain"), finding("raw_ip_link"))], CFG)
    assert [c["id"] for c in a["contributions"]] == [c["id"] for c in b["contributions"]]


# ---------- PRD section 6 rules

def test_each_finding_counts_once_even_if_repeated():
    r = score_email([check("links", finding("raw_ip_link"), finding("raw_ip_link"))], CFG)
    assert r["score"] == 15


def test_errored_check_adds_zero_and_is_listed_as_not_run():
    r = score_email([check("sender", finding("dmarc_fail"), status="error"), check("links", finding("raw_ip_link"))], CFG)
    assert r["score"] == 15 and r["not_run"] == ["sender"]


def test_engine_works_with_only_some_checks():
    assert score_email([check("sender", finding("spf_fail"))], CFG)["score"] == 20      # no links/cert/tone at all
    assert score_email([], CFG)["score"] == 0


def test_weights_come_from_config_not_from_the_finding():
    cfg = copy.deepcopy(CFG)
    cfg["points"]["raw_ip_link"] = 40
    r = score_email([check("links", finding("raw_ip_link", points=15))], cfg)
    assert r["score"] == 40                                   # tuning needs no code change
    unknown = score_email([check("links", finding("brand_new_rule", points=7))], CFG)
    assert unknown["score"] == 7                              # unknown id keeps the check's own points


def test_thresholds_come_from_config():
    cfg = copy.deepcopy(CFG)
    cfg["thresholds"].update(suspicious_from=10, phishing_from=20)
    assert score_email([check("sender", finding("spf_fail"))], cfg)["verdict"] == "phishing"


# ---------- tone (M5 plugs in later): 1.5 x s, max 15, can never convict alone

def test_tone_points_formula_and_cap():
    assert score_email([check("tone", score=4)], CFG)["score"] == 6
    assert score_email([check("tone", score=10)], CFG)["score"] == 15
    assert score_email([check("tone", score=10)], CFG)["contributions"][0]["id"] == "tone_manipulation"


def test_tone_alone_can_never_reach_suspicious():
    r = score_email([check("tone", score=10)], CFG)
    assert r["score"] == 15 and r["verdict"] == "safe"
    assert CFG["tone"]["max_points"] < CFG["thresholds"]["suspicious_from"]


def test_tone_error_or_missing_score_adds_nothing():
    assert score_email([check("tone", status="error")], CFG)["not_run"] == ["tone"]
    assert score_email([check("tone", status="warn")], CFG)["score"] == 0       # no score key


def test_tone_adds_to_other_checks():
    r = score_email([check("sender", finding("dmarc_fail")), check("tone", score=8)], CFG)
    assert r["score"] == 25 + 12 and r["verdict"] == "suspicious"


# ---------- rounding and capped display

def test_halves_round_up_at_the_verdict_line():
    # 25 (dmarc_fail) + tone 3 x 1.5 = 4.5 -> 29.5 must become 30 (Suspicious), 28.5 -> 29 (Safe)
    assert score_email([check("sender", finding("dmarc_fail")), check("tone", score=3)], CFG)["score"] == 30
    r = score_email([check("sender", finding("dmarc_fail")), check("tone", score=3)], CFG)
    assert r["raw_total"] == 29.5 and r["verdict"] == "suspicious"
    r2 = score_email([check("sender", finding("spf_fail")), check("tone", score=5.67)], CFG)   # 20 + 8.5 = 28.5
    assert r2["raw_total"] == 28.5 and r2["score"] == 29 and r2["verdict"] == "safe"


def test_raw_total_reported_when_capped():
    r = score_email([check("sender", finding("dmarc_fail"), finding("spf_fail"), finding("dkim_invalid")),
                     check("links", finding("lookalike_domain"), finding("domain_age_new"), finding("raw_ip_link"))], CFG)
    assert r["raw_total"] == 25 + 20 + 20 + 25 + 20 + 15 == 125 and r["score"] == 100
