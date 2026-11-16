"""M9 disguise check: each trick raises its flag, and common legitimate patterns raise nothing."""
import pytest

from modules import load_config
from modules.disguise import check_disguise, unwrap
from modules.parser import parse_eml
from modules.scoring import score_email

CFG = load_config()


def email(name="", address="someone@example.org", to=("reader@company.com",), links=(), attachments=(), list_id=""):
    return {"from": {"name": name, "address": address}, "to": list(to), "list_id": list_id,
            "links": [{"href": h, "text": ""} for h in links],
            "attachments": [{"filename": f, "content_type": "application/octet-stream"} for f in attachments]}


def ids(parsed):
    return {f["id"] for f in check_disguise(parsed, CFG)["findings"]}


# ---------- each trick raises its own flag

def test_brand_in_sender_name_from_an_unrelated_domain():
    assert ids(email("einvoice_fedex", "fedex@gori1lapapers.com")) == {"brand_display_name"}
    assert ids(email("PayPal Service", "service@pay-secure-help.net")) == {"brand_display_name"}
    assert ids(email("HDFC Bank Alerts", "alerts@hdfc-kyc-update.com")) == {"brand_display_name"}
    assert ids(email("PayPal", "service@paypal-alerts.com")) == {"brand_display_name"}      # brand + extra words


def test_different_address_inside_the_sender_name():
    assert ids(email("service@paypal.com", "x@mailer-473.example")) == {"address_in_display_name", "brand_display_name"}
    assert ids(email("billing@acme-corp.com", "x@mailer-473.example")) == {"address_in_display_name"}


def test_own_organisation_in_sender_name_from_outside():
    found = check_disguise(email("monkey.org HOSTING", "news@newspread-ie.com", to=["jose@monkey.org"]), CFG)
    assert {f["id"] for f in found["findings"]} == {"own_org_display_name"}
    assert ids(email("Monkey_Group HR_Department", "hr@diasorins.com", to=["jose@monkey.org"])) == {"own_org_display_name"}


def test_risky_attachments_by_file_name():
    for name in ("Waybilldocument386#7U465.html", "invoice.SVG", "setup.exe", "scan.iso", "report.docm"):
        assert ids(email(attachments=[name])) == {"risky_attachment"}, name
    r = check_disguise(email(attachments=["Waybill.html"]), CFG)
    assert r["findings"][0]["points"] == 20 and r["status"] == "fail"          # 20 = a heavy flag, red card


def test_free_hosting_links_including_ones_under_trusted_domains():
    for href in ("https://clinquant-kashata-6e4f81.netlify.app/#x", "https://vdm-2-g2vc.4everland.app/",
                 "https://storage.googleapis.com/bucket/login.html", "https://sites.google.com/view/verify",
                 "https://bafybeih.ipfs.dweb.link/"):
        assert ids(email(links=[href])) == {"free_hosting_link"}, href


def test_redirect_links_are_flagged_and_looked_through():
    href = "https://www.google.com/url?q=https%3A%2F%2Fvdm-2-g2vc.4everland.app%2F&sa=D"
    assert unwrap(href) == ("www.google.com", "https://vdm-2-g2vc.4everland.app/")
    assert ids(email(links=[href])) == {"redirect_link", "free_hosting_link"}    # the hidden target is checked too
    assert ids(email(links=["https://googleads.g.doubleclick.net/pcs/click?xai=AKAO&adurl=https://evil.example/x"])) \
        == {"redirect_link"}


def test_each_flag_counts_once_and_adds_up_in_scoring():
    parsed = email("einvoice_fedex", "fedex@gori1lapapers.com", attachments=["a.html", "b.html"],
                   links=["https://a.netlify.app", "https://b.netlify.app"])
    r = check_disguise(parsed, CFG)
    assert sorted(f["id"] for f in r["findings"]) == ["brand_display_name", "free_hosting_link", "risky_attachment"]
    assert score_email([r], CFG)["score"] == 20 + 15 + 10


# ---------- legitimate patterns that must NOT be flagged

@pytest.mark.parametrize("name, address", [
    ("HDFC Bank", "alerts@hdfcbank.net"),               # a brand's "twin" domain
    ("iCloud", "noreply@email.apple.com"),               # a brand sending from its parent company (trusted domain)
    ("Gmail Team", "mail-noreply@google.com"),
    ("Amazon Pay", "no-reply@amazonpay.in"),
    ("SBI", "donotreply@onlinesbi.sbi"),
    ("Microsoft 365", "msonlineservicesteam@microsoftonline.com"),
    ("FedEx Delivery", "trackingupdates@fedex.com"),
    ("Mark Appleton", "mark@gmail.com"),                 # "apple" inside a longer name is not the brand
    ("Harvard Business Review", "emails@hbr.org"),       # not on the impersonated-brands list
])
def test_real_brand_senders_are_not_flagged(name, address):
    assert ids(email(name, address)) == set()


def test_google_groups_and_mailing_lists_are_not_flagged():
    assert ids(email("'alice@paypal.com' via Team List", "team@googlegroups.com", to=["me@monkey.org"])) == set()
    assert ids(email("Monkey users", "list@lists.example.org", to=["jose@monkey.org"], list_id="<users.monkey.org>")) == set()


def test_own_organisation_rule_skips_free_mail_inside_and_brands_already_flagged():
    assert ids(email("Gmail Security", "alerts@security-gmail-help.com", to=["me@gmail.com"])) == {"brand_display_name"}
    assert ids(email("Monkey IT", "it@monkey.org", to=["jose@monkey.org"])) == set()           # same organisation
    assert ids(email("Monkey IT", "it@mail.monkey.org", to=["jose@monkey.org"])) == set()      # its subdomain
    # "SRMIST Exam Cell" from outside to an srmist reader: one fact, counted once (brand rule), not twice
    assert ids(email("SRMIST Exam Cell", "exam@srm-results.com", to=["s@srmist.edu.in"])) == {"brand_display_name"}
    assert ids(email("Monkey IT", "it@outside.example", to=[])) == set()                       # no recipient


def test_ordinary_attachments_links_and_safe_links_wrappers_are_not_flagged():
    assert ids(email(attachments=["timetable.pdf", "photo.jpg", "notes.docx", "data.zip", "(unnamed)"])) == set()
    assert ids(email(links=["https://www.srmist.edu.in/academics", "https://github.com/x", "https://example.org"])) == set()
    wrapped = "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.org%2F&data=x"
    assert unwrap(wrapped) == (None, "https://www.example.org/") and ids(email(links=[wrapped])) == set()


def test_an_html_body_part_without_a_file_name_is_not_an_attachment():
    raw = (b"From: Shop <news@shop.example>\nTo: a@b.com\nSubject: Hi\nMIME-Version: 1.0\n"
           b"Content-Type: multipart/alternative; boundary=X\n\n--X\nContent-Type: text/plain\n\nHello\n"
           b"--X\nContent-Type: text/html\n\n<p>Hello</p>\n--X--\n")
    assert ids(parse_eml(raw)) == set()


def test_parser_reads_list_id_and_nothing_found_gives_a_pass_card():
    raw = b"From: A <a@x.org>\nTo: b@y.org\nList-Id: <users.x.org>\nSubject: s\n\nbody\n"
    parsed = parse_eml(raw)
    assert parsed["list_id"] == "<users.x.org>"
    r = check_disguise(parsed, CFG)
    assert r["status"] == "pass" and r["details"][0]["result"] == "ok"


def test_never_raises():
    r = check_disguise({"from": None, "links": [{"href": None}]}, CFG)
    assert r["check"] == "disguise" and r["status"] in ("pass", "error")


def test_dashboard_and_report_show_the_disguise_check():
    from app import app
    page = app.test_client().post("/analyze", data={"sample": "forged_exam_cell.eml"}).data.decode()
    assert page.count("Disguise (sender name, attachments, hidden links)") >= 2      # the card and the report table
