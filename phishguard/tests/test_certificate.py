import copy
import ssl
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from modules import certificate, load_config
from modules.certificate import CertError, check_certificate, name_matches
from modules.certificate import fetch_certificate as real_fetch     # captured before the fake replaces it
from modules.scoring import score_email

CFG = load_config()
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
CA_KEY = ec.generate_private_key(ec.SECP256R1())
CA_NAME = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Trusted CA")])


def make_cert(*names, issued_days_ago=100, valid_days=365, self_signed=False):
    """A real certificate, built here, for the given website names."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    start = NOW - timedelta(days=issued_days_ago)
    builder = (x509.CertificateBuilder().subject_name(subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(start)
               .not_valid_after(start + timedelta(days=valid_days))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False))
    if self_signed:
        cert = builder.issuer_name(subject).sign(key, hashes.SHA256())
    else:
        cert = builder.issuer_name(CA_NAME).sign(CA_KEY, hashes.SHA256())
    return cert.public_bytes(Encoding.DER)


def email(*hrefs):
    return {"links": [{"text": "click", "href": h} for h in hrefs]}


def run(*hrefs, config=CFG):
    return check_certificate(email(*hrefs), config, NOW)


def ids(result):
    return {f["id"] for f in result["findings"]}


# ---------- FR-4.2 / FR-4.3: reading and judging a certificate

def test_valid_certificate_passes_and_shows_its_fields(tls):
    tls.certs["shop-example.com"] = {"der": make_cert("shop-example.com"), "verify_error": ""}
    r = run("https://shop-example.com/offer")
    assert r["status"] == "pass" and r["findings"] == []
    d = r["details"][0]
    assert d["result"] == "valid" and "Test Trusted CA" in d["evidence"] and "issued 100 days ago" in d["evidence"]
    assert "covers shop-example.com" in d["evidence"]


def test_expired_certificate(tls):
    tls.certs["old-example.com"] = {"der": make_cert("old-example.com", issued_days_ago=400), "verify_error": "certificate has expired"}
    r = run("https://old-example.com")
    assert ids(r) == {"cert_expired"} and r["findings"][0]["points"] == 15 and r["status"] == "warn"


def test_self_signed_certificate_is_untrusted(tls):
    tls.certs["selfie-example.com"] = {"der": make_cert("selfie-example.com", self_signed=True),
                                       "verify_error": "self-signed certificate"}
    r = run("https://selfie-example.com")
    assert ids(r) == {"cert_untrusted"} and "itself (self-signed)" in r["details"][0]["evidence"]


def test_unknown_issuer_is_untrusted(tls):
    tls.certs["odd-example.com"] = {"der": make_cert("odd-example.com"), "verify_error": "unable to get local issuer certificate"}
    assert ids(run("https://odd-example.com")) == {"cert_untrusted"}


def test_certificate_for_another_name_is_a_mismatch(tls):
    tls.certs["paypa1-login.com"] = {"der": make_cert("*.hosting-example.com"),
                                     "verify_error": "Hostname mismatch, certificate is not valid for 'paypa1-login.com'."}
    r = run("https://paypa1-login.com/verify")
    assert ids(r) == {"cert_hostname_mismatch"}              # a name problem is not an untrusted chain
    assert "verification said: Hostname mismatch" in r["details"][0]["evidence"]


def test_brand_new_certificate_is_a_small_flag(tls):
    tls.certs["fresh-example.com"] = {"der": make_cert("fresh-example.com", issued_days_ago=2), "verify_error": ""}
    r = run("https://fresh-example.com")
    assert ids(r) == {"cert_new"} and r["findings"][0]["points"] == 5
    tls.certs["fresh-example.com"] = {"der": make_cert("fresh-example.com", issued_days_ago=10), "verify_error": ""}
    assert ids(run("https://fresh-example.com")) == set()


def test_several_problems_are_all_reported_even_though_openssl_names_only_one(tls):
    tls.certs["bad-example.com"] = {"der": make_cert("other-example.com", issued_days_ago=500, self_signed=True),
                                    "verify_error": "self-signed certificate"}
    r = run("https://bad-example.com")
    assert ids(r) == {"cert_untrusted", "cert_expired", "cert_hostname_mismatch"}
    assert r["details"][0]["result"] == "untrusted, expired, hostname mismatch"


def test_wildcard_names_cover_exactly_one_label():
    assert name_matches("a.example.com", ["*.example.com"])
    assert not name_matches("a.b.example.com", ["*.example.com"])
    assert not name_matches("example.com", ["*.example.com"])
    assert name_matches("Example.COM.", ["example.com"])


# ---------- which links are checked (FR-4.1, FR-4.4)

def test_plain_http_link_has_no_certificate_and_no_handshake(tls):
    r = run("http://srmlst.edu.in.verify-login.com/portal")
    assert r["details"][0]["result"] == "no certificate" and tls.calls == [] and r["status"] == "none"


def test_trusted_and_raw_ip_https_links_are_not_checked(tls):
    r = run("https://www.srmist.edu.in/academics", "https://203.0.113.50/login")
    assert [d["result"] for d in r["details"]] == ["trusted", "not checked"] and tls.calls == []
    assert r["status"] == "none"                         # nothing was checked, so it must not say "pass"


def test_same_host_is_checked_once(tls):
    tls.certs["shop-example.com"] = {"der": make_cert("shop-example.com"), "verify_error": ""}
    run("https://shop-example.com/a", "https://shop-example.com/b", "http://shop-example.com/c")
    assert tls.calls == ["shop-example.com"]


def test_no_links_at_all():
    r = run()
    assert r["status"] == "none" and r["details"][0]["name"] == "(no web links)"


def test_at_most_max_hosts_are_checked(tls):
    hosts = [f"site{i}-example.com" for i in range(12)]
    r = run(*[f"https://{h}" for h in hosts])
    assert len(tls.calls) == CFG["certificate"]["max_hosts"] == 10
    assert sum(d["result"] == "not checked" for d in r["details"]) == 2


# ---------- failures never cost points (NFR-3)

def test_unreachable_sites_add_zero_points_and_show_could_not_run(tls):
    r = run("https://gone-example.com")                        # the fake knows no certificate: cannot connect
    assert r["status"] == "error" and r["findings"] == [] and r["details"][0]["result"] == "could not connect"
    assert score_email([r], CFG)["not_run"] == ["certificate"]


def test_one_reachable_site_is_enough_to_not_be_an_error(tls):
    tls.certs["shop-example.com"] = {"der": make_cert("shop-example.com"), "verify_error": ""}
    assert run("https://shop-example.com", "https://gone-example.com")["status"] == "pass"


def test_a_stuck_handshake_is_cut_off_by_the_hard_time_limit(monkeypatch):
    config = copy.deepcopy(CFG)
    config["dns"]["timeout_seconds"] = 0.1                     # hard limit = 2 x 0.1 + 1 = 1.2 s

    def stuck(host, timeout=5):
        time.sleep(3)
    monkeypatch.setattr(certificate, "fetch_certificate", stuck)
    started = time.monotonic()
    r = run("https://slow-example.com", config=config)
    assert time.monotonic() - started < 2.5 and r["details"][0]["evidence"] == "No answer in time"


def test_findings_flow_into_the_score_with_config_weights(tls):
    tls.certs["bad-example.com"] = {"der": make_cert("other-example.com", issued_days_ago=500, self_signed=True), "verify_error": "x"}
    assert score_email([run("https://bad-example.com")], CFG)["score"] == 45


# ---------- the real handshake function (with the network replaced)

def test_fetch_reads_a_failed_certificate_with_a_second_unverified_handshake(monkeypatch):
    calls = []

    def handshake(host, timeout, verify):
        calls.append(verify)
        if verify:
            err = ssl.SSLCertVerificationError(1, "certificate verify failed")
            err.verify_message = "self-signed certificate"
            raise err
        return b"DER"
    monkeypatch.setattr(certificate, "_handshake", handshake)
    assert real_fetch("x-example.com") == {"der": b"DER", "verify_error": "self-signed certificate"}
    assert calls == [True, False]


def test_fetch_turns_network_failures_into_cert_error(monkeypatch):
    def down(host, timeout, verify):
        raise TimeoutError("timed out")
    monkeypatch.setattr(certificate, "_handshake", down)
    with pytest.raises(CertError):
        real_fetch("x-example.com")
