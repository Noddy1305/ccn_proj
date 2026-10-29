import base64

import dkim
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from modules import sender
from modules.parser import parse_eml
from modules.sender import check_sender, org_domain, parse_auth_results


def make_eml(frm="alerts@srmist.edu.in", return_path=None, reply_to=None, ip="52.1.2.3",
             auth=None, body="Hello there.\n"):
    lines = [f"Received: from mail.example.net (mail.example.net [{ip}]) by mx.local; Mon, 26 Oct 2026 10:00:00 +0000"]
    if auth:
        lines.insert(0, f"Authentication-Results: mx.local; {auth}")
    if return_path:
        lines.append(f"Return-Path: <{return_path}>")
    lines += [f"From: Someone <{frm}>"]
    if reply_to:
        lines.append(f"Reply-To: <{reply_to}>")
    lines += ["To: me@example.org", "Subject: Test", "Date: Mon, 26 Oct 2026 15:00:00 +0530",
              "Message-ID: <t1@example.net>", "", body]
    return "\n".join(lines).encode()


def run(raw):
    return check_sender(parse_eml(raw), raw)


def ids(result):
    return {f["id"] for f in result["findings"]}


def detail(result, name):
    return next(d for d in result["details"] if d["name"] == name)


# ---------- helpers

def test_org_domain_handles_indian_suffixes():
    assert org_domain("mail.srmist.edu.in") == "srmist.edu.in"
    assert org_domain("srmist.edu.in") == "srmist.edu.in"
    assert org_domain("a.b.example.com") == "example.com"
    assert org_domain("example.co.in") == "example.co.in"


def test_auth_results_uses_topmost_header_only():
    top = "mx.local; spf=pass smtp.mailfrom=a.com; dkim=pass header.d=a.com; dmarc=fail (p=REJECT) header.from=a.com"
    planted = "evil; spf=fail; dkim=fail; dmarc=pass"
    parsed = parse_auth_results([top, planted])
    assert parsed["spf"] == "pass" and parsed["dmarc"] == "fail" and parsed["dmarc_policy"] == "reject"
    assert parsed["dkim_domain"] == "a.com"
    assert parse_auth_results([]) == {}


# ---------- SPF

def test_spf_pass_dmarc_aligned(zone):
    zone.add_txt("srmist.edu.in", "v=spf1 ip4:52.1.2.3 -all")
    zone.add_txt("_dmarc.srmist.edu.in", "v=DMARC1; p=reject")
    r = run(make_eml())
    assert detail(r, "SPF")["result"] == "pass"
    assert detail(r, "DMARC")["result"] == "pass"
    assert detail(r, "SPF")["source"] == "live"
    assert ids(r) == {"dkim_none"}          # only the missing DKIM signature costs 5
    assert r["status"] == "warn"


def test_spf_fail_and_softfail(zone):
    zone.add_txt("srmist.edu.in", "v=spf1 ip4:52.9.9.9 -all")
    assert "spf_fail" in ids(run(make_eml()))
    zone.add_txt("srmist.edu.in", "v=spf1 ip4:52.9.9.9 ~all")
    assert "spf_softfail" in ids(run(make_eml()))


def test_no_records_at_all_gives_three_none_findings():
    r = run(make_eml())
    assert ids(r) == {"spf_none", "dkim_none", "dmarc_none"}
    assert sum(f["points"] for f in r["findings"]) == 15


def test_spf_checks_return_path_domain_not_from(zone):
    zone.add_txt("srmist.edu.in", "v=spf1 -all")                  # From domain would fail
    zone.add_txt("attacker.com", "v=spf1 ip4:52.1.2.3 -all")   # attacker's own domain passes
    r = run(make_eml(return_path="bounce@attacker.com"))
    assert detail(r, "SPF")["result"] == "pass"
    assert "attacker.com" in detail(r, "SPF")["evidence"]


def test_spf_pass_for_attacker_domain_still_fails_dmarc_alignment(zone):
    zone.add_txt("attacker.com", "v=spf1 ip4:52.1.2.3 -all")
    zone.add_txt("_dmarc.srmist.edu.in", "v=DMARC1; p=reject")
    r = run(make_eml(return_path="bounce@attacker.com"))
    assert detail(r, "SPF")["result"] == "pass"
    assert detail(r, "DMARC")["result"] == "fail"
    assert "dmarc_fail" in ids(r) and r["status"] == "fail"
    assert "domain_mismatch" in ids(r)


# ---------- DMARC

def test_dmarc_falls_back_to_org_domain_record(zone):
    zone.add_txt("srmist.edu.in", "v=spf1 ip4:52.1.2.3 -all")
    zone.add_txt("_dmarc.srmist.edu.in", "v=DMARC1; p=quarantine")
    zone.add_txt("mail.srmist.edu.in", "v=spf1 ip4:52.1.2.3 -all")
    r = run(make_eml(frm="x@mail.srmist.edu.in", return_path="x@mail.srmist.edu.in"))
    assert detail(r, "DMARC")["result"] == "pass"       # relaxed alignment on subdomain
    assert detail(r, "DMARC")["policy"] == "quarantine"


def test_dmarc_strict_alignment_rejects_subdomain(zone):
    zone.add_txt("mail.srmist.edu.in", "v=spf1 ip4:52.1.2.3 -all")
    zone.add_txt("_dmarc.srmist.edu.in", "v=DMARC1; p=reject; aspf=s")
    r = run(make_eml(frm="x@srmist.edu.in", return_path="x@mail.srmist.edu.in"))
    assert detail(r, "DMARC")["result"] == "fail"


# ---------- DKIM

@pytest.fixture
def signed(zone):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    pub = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    zone.add_txt("sel._domainkey.srmist.edu.in", f"v=DKIM1; k=rsa; p={pub}")
    msg = make_eml(body="Original body text\n").replace(b"\n", b"\r\n")
    sig = dkim.sign(msg, b"sel", b"srmist.edu.in", pem, include_headers=[b"from", b"subject", b"to"])
    return sig + msg


def test_dkim_valid_signature_passes_and_aligns(signed, zone):
    r = run(signed)
    assert detail(r, "DKIM")["result"] == "pass"
    assert detail(r, "DMARC")["result"] == "none"      # no policy published yet
    zone.add_txt("_dmarc.srmist.edu.in", "v=DMARC1; p=reject")
    assert detail(run(signed), "DMARC")["result"] == "pass"   # DKIM alone is enough
    assert "dkim_invalid" not in ids(run(signed)) and "dkim_none" not in ids(run(signed))


def test_dkim_tampered_body_is_invalid_not_none(signed):
    r = run(signed.replace(b"Original body", b"Changed body"))
    assert detail(r, "DKIM")["result"] == "fail"
    assert "dkim_invalid" in ids(r) and "dkim_none" not in ids(r)


def test_dkim_broken_by_forwarding_uses_mail_server_verdict(signed):
    tampered = signed.replace(b"Original body", b"Changed body")
    tampered = b"Authentication-Results: mx.local; dkim=pass header.d=srmist.edu.in\r\n" + tampered
    d = detail(run(tampered), "DKIM")
    assert d["result"] == "pass" and d["source"] == "reported by mail server"


# ---------- fallback / errors

def test_dns_down_falls_back_to_mail_server_header(zone):
    zone.broken = True
    r = run(make_eml(auth="spf=pass smtp.mailfrom=srmist.edu.in; dkim=none; dmarc=pass header.from=srmist.edu.in"))
    assert detail(r, "SPF")["source"] == "reported by mail server"
    assert detail(r, "DMARC")["result"] == "pass"
    assert detail(r, "DMARC")["source"] == "reported by mail server"


def test_dns_down_and_no_header_is_error_with_zero_points(zone):
    zone.broken = True
    r = run(make_eml())
    assert r["status"] == "error"
    assert sum(f["points"] for f in r["findings"]) == 0
    assert detail(r, "SPF")["source"] == "could not run"


def test_planted_lower_auth_results_ignored(zone):
    zone.broken = True
    raw = make_eml(auth="spf=fail; dkim=none; dmarc=fail")
    raw = raw.replace(b"\nFrom:", b"\nAuthentication-Results: evil; spf=pass; dmarc=pass\nFrom:")
    assert detail(run(raw), "SPF")["result"] == "fail"


def test_any_crash_becomes_error_not_exception(monkeypatch):
    monkeypatch.setattr(sender, "check_spf", lambda *a: 1 / 0)
    r = run(make_eml())
    assert r["status"] == "error" and "could not run" in r["error"]


# ---------- FR-2.5 and config

def test_reply_to_mismatch_flagged_but_same_org_is_fine():
    r = run(make_eml(reply_to="help@scam.com"))
    assert "domain_mismatch" in ids(r)
    assert "domain_mismatch" not in ids(run(make_eml(reply_to="help@mail.srmist.edu.in")))


def test_points_come_from_config():
    cfg = {"points": {"dkim_none": 99, "spf_none": 0, "dmarc_none": 0}, "dns": {"timeout_seconds": 1}}
    raw = make_eml()
    r = check_sender(parse_eml(raw), raw, config=cfg)
    assert {f["id"]: f["points"] for f in r["findings"]}["dkim_none"] == 99


# ---------- real-world case: third-party sending service (e.g. YouTube via Google)

YOUTUBE_AUTH = ("spf=pass smtp.mailfrom=bounces.google.com; dkim=pass header.d=youtube.com; "
                "dmarc=pass (p=REJECT) header.from=youtube.com")


def test_return_path_on_sending_service_not_penalised_when_dmarc_passes(zone):
    zone.broken = True   # use the mail server's verdict, as for a saved real email
    r = run(make_eml(frm="noreply@youtube.com", return_path="abc@scoutcamp.bounces.google.com", auth=YOUTUBE_AUTH))
    assert "domain_mismatch" not in ids(r)
    assert detail(r, "Reply-To / Return-Path")["result"] == "ok"
    assert "authorised sending service" in detail(r, "Reply-To / Return-Path")["evidence"]


def test_return_path_mismatch_still_flagged_when_dmarc_fails(zone):
    zone.broken = True
    r = run(make_eml(frm="noreply@youtube.com", return_path="abc@evil.com",
                     auth="spf=pass; dkim=none; dmarc=fail"))
    assert "domain_mismatch" in ids(r)


def test_reply_to_mismatch_flagged_even_when_dmarc_passes(zone):
    zone.broken = True
    r = run(make_eml(frm="noreply@youtube.com", reply_to="x@evil.com", auth=YOUTUBE_AUTH))
    assert "domain_mismatch" in ids(r)
