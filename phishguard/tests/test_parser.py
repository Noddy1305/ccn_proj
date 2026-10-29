from pathlib import Path

import pytest

from modules.parser import ParseError, parse_eml

FIX = Path(__file__).parent / "fixtures"
SAMPLES = Path(__file__).parent.parent / "data" / "samples"


def load(name, folder=FIX):
    return parse_eml((folder / name).read_bytes())


def test_forged_headers():
    p = load("forged.eml")
    assert p["from"] == {"name": "SRM Exam Cell", "address": "examcell@srmist.edu.in"}
    assert p["reply_to"]["address"] == "exam-help@srmlst-verify.com"
    assert p["return_path"]["address"] == "bounce@srmlst-verify.com"
    assert p["to"] == ["student@gmail.com"]
    assert p["subject"].startswith("URGENT")
    assert p["message_id"] == "<fake001@srmlst-verify.com>"


def test_sending_ip_is_first_public_hop_not_private():
    assert load("forged.eml")["sending_ip"] == "185.234.72.19"
    assert load("genuine.eml")["sending_ip"] == "209.85.220.41"


def test_received_chain_and_auth_headers():
    p = load("forged.eml")
    assert len(p["received_chain"]) == 2
    assert "dmarc=fail" in p["authentication_results"][0]
    assert p["dkim_signatures"] == []


def test_html_links_text_vs_href():
    links = load("forged.eml")["links"]
    assert {"text": "https://www.srmist.edu.in/hallticket",
            "href": "http://srmlst.edu.in.verify-login.com/portal"} in links
    assert any(l["href"] == "http://203.0.113.50/login" for l in links)


def test_html_body_converted_to_text():
    p = load("forged.eml")
    assert p["body_source"] == "html-converted"
    assert "hall ticket" in p["body_text"] and "<b>" not in p["body_text"]


def test_plain_text_urls_become_links():
    p = load("genuine.eml")
    assert p["body_source"] == "plain"
    assert p["links"] == [{"text": "https://www.srmist.edu.in/academics",
                           "href": "https://www.srmist.edu.in/academics"}]


def test_multipart_prefers_plain_and_collects_html_links():
    p = load("newsletter.eml", SAMPLES)
    assert p["body_source"] == "plain"
    hrefs = {l["href"] for l in p["links"]}
    assert "https://www.shopmart.com/unsubscribe" in hrefs


def test_attachments_listed_not_opened():
    p = load("corpus_phish.eml", SAMPLES)
    assert p["attachments"] == [{"filename": "invoice.zip", "content_type": "application/zip"}]


@pytest.mark.parametrize("raw", [b"", b"   \n", (FIX / "not_an_email.txt").read_bytes()])
def test_invalid_files_rejected(raw):
    with pytest.raises(ParseError):
        parse_eml(raw)


def test_oversize_rejected():
    with pytest.raises(ParseError):
        parse_eml(b"From: a@b.com\nSubject: x\n\n" + b"a" * (5 * 1024 * 1024))


def test_no_duplicate_link_from_html_visible_text():
    links = load("forged.eml")["links"]
    assert len(links) == 2
