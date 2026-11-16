"""M9 - Disguise check: tricks that hide who really sent the email, or where its links really go.

Added in session 7 (part 2), after the evaluation showed that much recent phishing passes SPF, DKIM and DMARC
(it is sent through real email services), but still disguises itself in other ways:

  1. the sender NAME shows a brand (for example "einvoice_fedex") that the sending domain does not belong to,
  2. the sender name shows a different email address ("service@paypal.com" <x@evil.example>),
  3. the sender name shows the reader's own organisation ("monkey.org HOSTING") but the email comes from outside,
  4. a risky attachment: a web page, program or script that can open a fake login page or run code,
  5. a link to a free website-hosting service, where anyone can put up a fake page in minutes,
  6. a link hidden behind a redirect (google.com/url?q=..., ad-click links), so the real destination is not shown.

No network is used: this check only reads the parsed email. Points come from config.yaml, never from this file.
"""
import re
from urllib.parse import parse_qs, urlparse

from modules import load_config, status_for
from modules.links import host_of, is_ip, is_trusted, load_trusted
from modules.sender import org_domain

TITLES = {
    "risky_attachment": "Risky attachment (web page, program or script)",
    "brand_display_name": "Sender name shows a brand the sending domain does not belong to",
    "address_in_display_name": "Sender name shows a different email address",
    "own_org_display_name": "Sender name shows your own organisation, but the email comes from outside",
    "free_hosting_link": "Link to a free website-hosting service",
    "redirect_link": "Link hidden behind a redirect",
}

# Brands that phishing most often pretends to be. Kept separate from trusted_domains.txt on purpose: that list
# also contains names like "harvard" or "wikipedia" that send real mail from other domains (hbr.org, wikimedia.org).
DISPLAY_BRANDS = {
    "paypal", "netflix", "microsoft", "outlook", "office365", "onedrive", "sharepoint", "apple", "icloud", "amazon",
    "google", "gmail", "youtube", "facebook", "instagram", "whatsapp", "linkedin", "dropbox", "docusign", "adobe",
    "fedex", "dhl", "usps", "mcafee", "norton", "coinbase", "binance", "metamask", "wetransfer", "spotify", "ebay",
    "flipkart", "paytm", "phonepe", "hdfcbank", "icicibank", "sbi", "axisbank", "kotak", "irctc", "incometax",
    "uidai", "aadhaar", "srmist",
}

# Free mail providers: their users are not an "organisation", so "Gmail Team" is judged by the brand rule only.
WEBMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
           "yahoo.co.in", "ymail.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
           "zoho.com", "yandex.com", "gmx.com", "mail.com", "rediffmail.com"}

# Web pages, programs, scripts, disk images and macro documents. Judged by the file NAME only (never opened, SAF-2).
RISKY_EXTENSIONS = {"html", "htm", "shtml", "xhtml", "svg", "hta", "js", "jse", "vbs", "vbe", "wsf", "ps1", "exe",
                    "scr", "com", "pif", "bat", "cmd", "msi", "lnk", "jar", "iso", "img", "vhd", "docm", "xlsm", "pptm"}

# Services where anyone can publish a web page for free in minutes. Checked BEFORE the trusted list, because
# some of them live under trusted domains (storage.googleapis.com, sites.google.com).
FREE_HOSTS = ("netlify.app", "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
              "firebasestorage.googleapis.com", "storage.googleapis.com", "appspot.com", "sites.google.com",
              "glitch.me", "4everland.app", "ipfs.io", "dweb.link", "r2.dev", "onrender.com", "herokuapp.com",
              "weebly.com", "wixsite.com", "square.site", "godaddysites.com", "mystrikingly.com", "webflow.io",
              "framer.app", "replit.app", "repl.co", "surge.sh", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
              "000webhostapp.com", "translate.goog")

EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)


def _tokens(name):
    """Words in a sender name, plus each pair of neighbours joined ("HDFC Bank" -> hdfc, bank, hdfcbank)."""
    words = [w for w in re.split(r"[^a-z]+", name.lower()) if w]
    return set(words) | {a + b for a, b in zip(words, words[1:])}


def _belongs_to(brand, domain):
    """Does the domain look like the brand's own? hdfcbank.net, amazonpay.in, onlinesbi.sbi: yes.
    security-gmail-help.com, paypal-alerts.com: no (extra hyphenated words are a classic disguise)."""
    label = domain.split(".")[0]
    if label.startswith(brand):
        rest = label[len(brand):]
    elif label.endswith(brand):
        rest = label[:-len(brand)]
    else:
        return False
    return "-" not in rest


def _is_free_host(host):
    return any(host == h or host.endswith("." + h) for h in FREE_HOSTS) or "ipfs" in host.split(".")


def unwrap(href):
    """(redirector host, real target) if the link is an open redirect that hides another address, else None.

    Mail-security wrappers (Outlook Safe Links) are unwrapped too but return redirector None: companies wrap
    every link that way, so it is not suspicious by itself."""
    try:
        parts = urlparse(href.strip())
    except ValueError:
        return None
    host, path = (parts.hostname or "").lower(), parts.path.lower()
    query = parse_qs(parts.query)
    first = lambda *keys: next((query[k][0] for k in keys if k in query and query[k][0]), "")
    if host.endswith("safelinks.protection.outlook.com"):
        target = first("url")
        return (None, target) if target else None
    if (host.startswith("google.") or host.startswith("www.google.")) and path == "/url":
        target = first("q", "url")
        return (host, target) if target.startswith("http") else None
    if host.endswith("doubleclick.net") and ("/pcs/click" in path or "/aclk" in path):
        return host, first("adurl")
    if host == "www.bing.com" and path.startswith("/ck/a"):
        return host, first("u")
    if host in ("l.facebook.com", "lm.facebook.com") and path == "/l.php":
        return host, first("u")
    if host.endswith("youtube.com") and path == "/redirect":
        return host, first("q")
    return None


def check_disguise(parsed, config=None):
    """Run M9. Never raises: any failure becomes status 'error' with 0 points (NFR-3)."""
    try:
        return _check_disguise(parsed, config or load_config())
    except Exception as exc:
        return {"check": "disguise", "status": "error", "findings": [], "details": [],
                "error": f"could not run: {type(exc).__name__}: {exc}"}


def _check_disguise(parsed, config):
    trusted, _ = load_trusted()
    found = {}                                     # finding id -> evidence texts

    def flag(fid, text):
        found.setdefault(fid, [])
        if text not in found[fid]:
            found[fid].append(text)

    sender = parsed.get("from") or {}
    name, address = (sender.get("name") or "").strip(), sender.get("address") or ""
    from_domain = org_domain(address.rsplit("@", 1)[1]) if "@" in address else ""
    via = " via " in name.lower()                  # Google Groups and mailing lists: "Alice via GroupName"
    mailing_list = bool(parsed.get("list_id"))

    # 1. A brand in the sender NAME that the sending domain does not belong to.
    brands_flagged = set()
    if name and from_domain and not via and not is_trusted(from_domain, trusted):
        for brand in sorted(_tokens(name) & DISPLAY_BRANDS):
            if not _belongs_to(brand, from_domain):
                brands_flagged.add(brand)
                flag("brand_display_name", f"sender name \"{name}\" shows {brand}, but the email comes from {from_domain}")

    # 2. A different email address written inside the sender name.
    if name and from_domain and not via:
        for shown in EMAIL_IN_TEXT.findall(name):
            if org_domain(shown) != from_domain:
                flag("address_in_display_name",
                     f"sender name shows an address at {org_domain(shown)}, but the real address is at {from_domain}")

    # 3. The reader's own organisation in the sender name, from outside it. Skipped for free mail (no
    #    organisation), mailing lists, and emails with no recipient. Only the domain counts, never the user name.
    recipients = [org_domain(a.rsplit("@", 1)[1]) for a in parsed.get("to", []) if "@" in a]
    for own in dict.fromkeys(recipients):
        label = own.split(".")[0]
        if (own in WEBMAIL or mailing_list or via or not name or not from_domain or len(label) < 4
                or from_domain == own or _belongs_to(label, from_domain) or label in brands_flagged):  # counted once
            continue
        if label in _tokens(name) or own in name.lower():
            flag("own_org_display_name", f"sender name \"{name}\" shows {own} (your organisation), "
                                         f"but the email comes from {from_domain}")

    # 4. Risky attachments, judged by file name only (they are never opened).
    for att in parsed.get("attachments", []):
        filename = (att.get("filename") or "").strip()
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext in RISKY_EXTENSIONS:
            flag("risky_attachment", f"attachment \"{filename}\" is a .{ext} file")

    # 5 and 6. Free hosting and hidden redirects, looking through redirects to the real destination.
    for link in parsed.get("links", []):
        href = link.get("href", "")
        host = host_of(href)
        if not host or is_ip(host):
            continue
        hops = [host]
        wrapped = unwrap(href)
        if wrapped:
            redirector, target = wrapped
            target_host = host_of(target) if target else ""
            if target_host:
                hops.append(target_host)
            if redirector:
                flag("redirect_link", f"link goes through {redirector} and on to "
                                      f"{target_host or 'an address that is not shown'}")
        for h in hops:
            if _is_free_host(h):
                flag("free_hosting_link", f"link goes to {h}, a free website-hosting service")

    points = config["points"]
    findings = [{"id": fid, "title": TITLES[fid], "points": points.get(fid, 0), "evidence": "; ".join(texts)}
                for fid, texts in found.items()]
    findings.sort(key=lambda f: -f["points"])
    details = [{"name": TITLES[f["id"]], "result": "found", "source": "from the email", "evidence": f["evidence"]}
               for f in findings]
    if not details:
        details = [{"name": "Sender name, attachments and links", "result": "ok", "source": "from the email",
                    "evidence": "No disguise found: the sender name matches the sending domain, no risky attachments, "
                                "no free-hosting or redirect links"}]
    return {"check": "disguise", "status": status_for(findings, config), "findings": findings, "details": details}
