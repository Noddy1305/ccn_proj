from datetime import datetime, timezone

from modules import links
from modules.links import brand_in, check_links, host_of, load_trusted, lookalike_of, text_domain

NOW = datetime(2026, 10, 29, tzinfo=timezone.utc)
TRUSTED, BRANDS = load_trusted()


def parsed_with(*pairs):
    return {"links": [{"text": t, "href": h} for t, h in pairs]}


def run(*pairs):
    return check_links(parsed_with(*pairs), now=NOW)


def ids(result):
    return {f["id"] for f in result["findings"]}


def points(result):
    return {f["id"]: f["points"] for f in result["findings"]}


# ---------- pure helpers

def test_host_of_ignores_non_web_links():
    assert host_of("https://WWW.Example.com:8080/a?b=1") == "www.example.com"
    assert host_of("http://srmist.edu.in@evil.com/x") == "evil.com"     # real host is after the @
    assert host_of("mailto:a@b.com") == "" and host_of("tel:123") == "" and host_of("#") == ""


def test_text_domain_only_for_domain_like_text():
    assert text_domain("https://www.srmist.edu.in/hallticket") == "srmist.edu.in"
    assert text_domain("Visit www.paypal.com now") == "paypal.com"
    assert text_domain("Help Center") == ""
    assert text_domain("invoice.pdf") == ""
    assert text_domain("e.g. this") == ""


def test_lookalike_one_letter_off():
    cand, trusted_domain, dist = lookalike_of("srmlst.edu.in", TRUSTED)
    assert trusted_domain == "srmist.edu.in" and dist == 1


def test_lookalike_hidden_in_subdomain():
    cand, trusted_domain, _ = lookalike_of("srmlst.edu.in.verify-login.com", TRUSTED)
    assert cand == "srmlst.edu.in" and trusted_domain == "srmist.edu.in"


def test_lookalike_two_letters_only_for_long_domains():
    assert lookalike_of("hdfcbxxk.cxm", TRUSTED) is None       # 3 edits: too far
    assert lookalike_of("hdfcbnk.cxm", TRUSTED)[2] == 2         # 11 chars, 2 edits: allowed
    assert lookalike_of("amazon.cx", TRUSTED) is None           # 9 chars: only 1 edit allowed
    assert lookalike_of("hdfcbnk.com", TRUSTED)[2] == 1
    assert lookalike_of("unionbankofindla.co.in", TRUSTED) is not None
    assert lookalike_of("icicibank.com", TRUSTED) is None       # exact trusted domain is not a lookalike


def test_short_and_unrelated_domains_are_not_lookalikes():
    assert lookalike_of("t.co", TRUSTED) is None
    assert lookalike_of("shopmart.com", TRUSTED) is None
    assert lookalike_of("203.0.113.50", TRUSTED) is None


def test_brand_in_domain():
    assert brand_in("srmist-verify.com", BRANDS) == "srmist"
    assert brand_in("paypal.com.evil.net", BRANDS) == "paypal"
    assert brand_in("securepaypal-login.com", BRANDS) == "paypal"
    assert brand_in("shopmart.com", BRANDS) is None


# ---------- findings, one per fixture (PRD section 10)

def test_lookalike_finding(zone):
    zone.live("srmlst.edu.in", 4000)
    r = run(("click", "http://srmlst.edu.in/login"))
    assert points(r)["lookalike_domain"] == 25 and r["status"] == "fail"   # 25 >= heavy flag (20)


def test_new_domain_under_30_days(zone):
    zone.live("fresh-offers.com", 5, NOW)
    r = run(("x", "https://fresh-offers.com/a"))
    assert points(r) == {"domain_age_new": 20}


def test_domain_30_to_180_days(zone):
    zone.live("midage-shop.com", 100, NOW)
    assert points(run(("x", "https://midage-shop.com"))) == {"domain_age_recent": 10}


def test_old_domain_no_age_finding(zone):
    zone.live("shopmart.com", 4000, NOW)
    assert run(("x", "https://shopmart.com")) ["status"] == "pass"


def test_link_text_mismatch(zone):
    zone.live("evil-site.com", 4000, NOW)
    r = run(("https://www.srmist.edu.in/hallticket", "http://evil-site.com/p"))
    assert points(r) == {"link_text_mismatch": 15}
    assert "srmist.edu.in" in r["findings"][0]["evidence"]


def test_text_and_href_same_domain_is_fine(zone):
    r = run(("https://www.srmist.edu.in/x", "https://srmist.edu.in/x"))
    assert r["status"] == "pass" and r["findings"] == []


def test_brand_combosquatting(zone):
    zone.live("srmist-verify.com", 4000, NOW)
    assert points(run(("x", "https://srmist-verify.com/a"))) == {"brand_in_domain": 15}


def test_raw_ip_link():
    r = run(("click", "http://185.234.72.19/login"))
    assert points(r) == {"raw_ip_link": 15}
    assert r["details"][0]["result"] == "raw IP"


def test_domain_not_resolving(zone):
    zone.created["ghost-domain.net"] = "notfound"
    assert points(run(("x", "http://ghost-domain.net/a"))) == {"domain_unresolved": 10}


# ---------- rules and safety

def test_each_finding_counts_once_even_with_many_links(zone):
    zone.live("a-fresh.com", 3, NOW)
    zone.live("b-fresh.com", 2, NOW)
    r = run(("x", "http://a-fresh.com/1"), ("y", "http://a-fresh.com/2"), ("z", "http://b-fresh.com/3"),
            ("i", "http://1.2.3.4/a"), ("j", "http://5.6.7.8/b"))
    assert [f["id"] for f in r["findings"]].count("raw_ip_link") == 1
    assert points(r)["domain_age_new"] == 20
    assert "a-fresh.com" in r["findings"][0]["evidence"] or "b-fresh.com" in str(r["findings"])


def test_trusted_domains_and_subdomains_skip_lookups(zone):
    zone.broken = True      # would error if any lookup were attempted and counted
    r = run(("Help", "https://support.google.com/youtube/?p=x"), ("t", "https://c.gle/AGSJ"),
            ("m", "https://www.youtube.com/paid_memberships"))
    assert r["status"] == "pass" and r["findings"] == []
    assert {d["result"] for d in r["details"]} == {"trusted"}


def test_no_internet_adds_zero_points_and_shows_error(zone):
    zone.broken = True
    r = run(("x", "http://some-unknown-site.com/a"))
    assert r["findings"] == [] and r["status"] == "error"


def test_hidden_registration_date_is_unknown_not_penalised(zone):
    zone.a["hidden-date.in"] = ["1.2.3.4"]       # resolves, but WHOIS gives no date
    r = run(("x", "https://hidden-date.in"))
    assert r["findings"] == [] and r["status"] == "pass"
    assert "unknown" in r["details"][0]["evidence"]


def test_no_links_and_non_web_links(zone):
    assert run()["status"] == "pass"
    r = run(("mail us", "mailto:a@b.com"), ("call", "tel:123"))
    assert r["status"] == "pass" and r["details"][0]["name"] == "(no web links)"


def test_domain_cap_limits_lookups(zone):
    cfg = {"points": {}, "dns": {"timeout_seconds": 1}, "links": {"max_domains": 2, "age_new_days": 30, "age_recent_days": 180}}
    pairs = [("x", f"http://site{i}-example.com/") for i in range(5)]
    r = check_links(parsed_with(*pairs), config=cfg, now=NOW)
    assert sum(d["result"] == "not checked" for d in r["details"]) == 3


def test_points_from_config_and_failure_is_contained(zone, monkeypatch):
    cfg = {"points": {"raw_ip_link": 7}, "dns": {"timeout_seconds": 1}, "links": {"max_domains": 5, "age_new_days": 30, "age_recent_days": 180}}
    assert check_links(parsed_with(("x", "http://1.2.3.4/")), config=cfg, now=NOW)["findings"][0]["points"] == 7
    monkeypatch.setattr(links, "host_of", lambda h: 1 / 0)
    r = run(("x", "http://a.com"))
    assert r["status"] == "error" and "could not run" in r["error"]


# ---------- one hand-built .eml per finding: parser -> link check must raise EXACTLY that finding

import pytest
from pathlib import Path

from modules.parser import parse_eml

FIXTURES = Path(__file__).parent / "fixtures"
OLD = 4000


def build_world(zone, finding):
    """Make DNS/WHOIS look normal so only the intended finding can appear."""
    for good in ("srmlst.edu.in", "evil-site.com", "srmist-verify.com"):
        zone.live(good, OLD, NOW)
    zone.live("fresh-offers.com", 5, NOW)
    zone.live("midage-shop.com", 100, NOW)
    zone.created["ghost-domain.net"] = "notfound"


@pytest.mark.parametrize("finding", [
    "lookalike_domain", "domain_age_new", "link_text_mismatch", "brand_in_domain",
    "raw_ip_link", "domain_age_recent", "domain_unresolved"])
def test_fixture_email_raises_exactly_its_finding(zone, finding):
    build_world(zone, finding)
    parsed = parse_eml((FIXTURES / f"m3_{finding}.eml").read_bytes())
    result = check_links(parsed, now=NOW)
    assert ids(result) == {finding}


# ---------- regression: genuine domains that once looked like false positives

@pytest.mark.parametrize("host", ["kodak.com", "olx.com", "line.com", "mail.com", "metal.com",
                                  "nitc.ac.in", "xbox.com", "slack.com"])
def test_genuine_lookalike_neighbours_not_flagged(host):
    assert lookalike_of(host, TRUSTED) is None
    assert brand_in(host, BRANDS) is None


@pytest.mark.parametrize("host", ["live.cricbuzz.com", "homeoffice.gov.uk", "zoom.com", "ola.in", "uberfoods.com"])
def test_ordinary_words_not_treated_as_brands(host):
    assert brand_in(host, BRANDS) is None


def test_text_and_href_both_trusted_is_not_a_mismatch(zone):
    r = run(("https://www.youtube.com/paid", "https://support.google.com/youtube"))
    assert r["findings"] == []


def test_brands_other_domains_on_trusted_list_are_trusted():
    from modules.links import is_trusted
    assert is_trusted("hubspot.net", TRUSTED) and is_trusted("www.paypal.me", TRUSTED)
