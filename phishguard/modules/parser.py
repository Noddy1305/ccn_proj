"""M1 - Email parser.

Splits a raw .eml file into labelled pieces. It makes NO judgement about
whether the email is good or bad; later modules do that.
"""
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses

from bs4 import BeautifulSoup

MAX_BYTES = 5 * 1024 * 1024  # FR-1.1

IPV4_IN_BRACKETS = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")
IPV4_PLAIN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


class ParseError(ValueError):
    """Raised when the uploaded file is not a usable email (FR-1.7)."""


def _address(value):
    """Return {'name': ..., 'address': ...} for the first address in a header."""
    pairs = getaddresses([str(value)]) if value else []
    if not pairs:
        return {"name": "", "address": ""}
    name, addr = pairs[0]
    return {"name": name, "address": addr.lower()}


def _addresses(value):
    values = value if isinstance(value, list) else [value]
    return [a.lower() for _, a in getaddresses([str(v) for v in values if v]) if a]


def _is_public_ip(text):
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_global


def find_sending_ip(received_headers):
    """FR-1.3: IP of the first external hop.

    Received headers are added on TOP by each server, so the list is newest
    first. The oldest hop is at the bottom, so we walk from the bottom up and
    take the first public (non-private, non-loopback) IP address.
    """
    for header in reversed(received_headers):
        candidates = IPV4_IN_BRACKETS.findall(header) + IPV4_PLAIN.findall(header)
        for cand in candidates:
            if _is_public_ip(cand):
                return cand
    return ""


def _html_to_text(html):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = soup.get_text("\n")
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def _extract_links(html, plain):
    """FR-1.6: every link as (visible text, real destination)."""
    links = []
    seen = set()

    def add(text, href):
        key = (text, href)
        if href and not href.startswith(("#", "javascript:")) and key not in seen:
            seen.add(key)
            links.append({"text": text, "href": href})

    if html:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            text = " ".join(a.get_text(" ").split())
            add(text, a["href"].strip())
    # Bare URLs in the plain text. Skipped when the text was converted from HTML,
    # because those URLs are just the visible text of anchors already captured.
    hrefs = {l["href"] for l in links}
    for url in URL_IN_TEXT.findall(plain or ""):
        url = url.rstrip(".,;:!?")
        if url not in hrefs:
            add(url, url)
    return links


def parse_eml(raw):
    """Parse raw .eml bytes into a dict of fields. Raises ParseError if invalid."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ParseError("Expected raw email bytes.")
    if not raw.strip():
        raise ParseError("The file is empty.")
    if len(raw) > MAX_BYTES:
        raise ParseError("File is larger than 5 MB.")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(bytes(raw))
    except Exception as exc:  # parser is lenient, but never let it crash us
        raise ParseError(f"Could not read the file as an email: {exc}")

    # FR-1.7: a real email has headers. Plain text files parse with none.
    if not msg.get("From") or not (msg.get("Date") or msg.get("Subject") or msg.get("Message-ID")):
        raise ParseError(
            "This does not look like a valid email (.eml): "
            "no From header together with a Date, Subject or Message-ID."
        )

    # Bodies
    plain_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    plain = plain_part.get_content() if plain_part else ""
    html = html_part.get_content() if html_part else ""
    body_source = "plain"
    if not plain.strip() and html:
        plain = _html_to_text(html)
        body_source = "html-converted"
    elif not plain.strip():
        body_source = "empty"

    # SAF-2: attachments listed by name and type only, never opened.
    attachments = [
        {"filename": p.get_filename() or "(unnamed)", "content_type": p.get_content_type()}
        for p in msg.iter_attachments()
    ]

    received = [str(h) for h in msg.get_all("Received", [])]
    dkim = [str(h) for h in msg.get_all("DKIM-Signature", [])]
    auth_results = [str(h) for h in msg.get_all("Authentication-Results", [])]

    return {
        "from": _address(msg.get("From")),
        "reply_to": _address(msg.get("Reply-To")),
        "return_path": _address(msg.get("Return-Path")),
        "to": _addresses(msg.get_all("To", [])),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "received_chain": received,
        "sending_ip": find_sending_ip(received),
        "dkim_signatures": dkim,
        "authentication_results": auth_results,
        "body_text": plain.strip(),
        "body_source": body_source,
        "links": _extract_links(html, plain if body_source == "plain" else ""),
        "attachments": attachments,
    }
