"""M2 - Sender check: SPF, DKIM, DMARC, Reply-To / Return-Path.

Proves (or fails to prove) that the email really came from the domain it
claims. Each mechanism gets a result and a "source":
  live                  - we did the DNS lookup and test ourselves
  reported by mail server - taken from the receiving server's
                            Authentication-Results header (FR-2.4)
  could not run         - neither was possible; adds 0 points
Points come from config.yaml, never from this file.
"""
import re
from concurrent.futures import ThreadPoolExecutor

import dkim
import dns.exception
import dns.resolver
import spf

from modules import load_config, status_for

LIVE = "live"
REPORTED = "reported by mail server"
NOT_RUN = "could not run"

# Domains whose "registrable" part has three labels, e.g. srmist.edu.in.
# A plain "last two labels" rule would wrongly turn mail.srmist.edu.in into edu.in.
MULTI_SUFFIXES = {
    "edu.in", "ac.in", "co.in", "gov.in", "org.in", "net.in", "res.in", "nic.in", "firm.in",
    "co.uk", "ac.uk", "org.uk", "gov.uk", "com.au", "edu.au", "co.nz", "co.jp", "co.za", "com.br",
}


class DnsError(Exception):
    """DNS could not answer (timeout, server failure). Different from 'no record'."""


def org_domain(domain):
    """Organisational domain: mail.srmist.edu.in -> srmist.edu.in."""
    labels = (domain or "").lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    take = 3 if ".".join(labels[-2:]) in MULTI_SUFFIXES else 2
    return ".".join(labels[-take:])


def domain_of(address):
    return address.rsplit("@", 1)[1].lower() if address and "@" in address else ""


def dns_txt(name, timeout=5):
    """TXT records of a name as a list of strings. [] if none exist.

    Raises DnsError when DNS itself fails (so we can tell 'no record' from 'no internet').
    """
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception as exc:  # timeout, no nameservers, no network ...
        raise DnsError(f"{type(exc).__name__}") from exc
    return ["".join(s.decode("utf-8", "replace") for s in r.strings) for r in answers]


# ---------------------------------------------------------------- Authentication-Results

def parse_auth_results(headers):
    """Read the TOPMOST Authentication-Results header only (FR-2.4).

    Servers add their header on top, so the first one belongs to the server that
    received the mail. Lower ones may have been planted by the sender.
    Returns {} if there is none.
    """
    if not headers:
        return {}
    text = " ".join(headers[0].split())
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        found = re.findall(rf"\b{mech}=(\w+)", text, re.I)
        if found:
            out[mech] = "pass" if "pass" in [f.lower() for f in found] else found[0].lower()
    m = re.search(r"smtp\.mailfrom=([^\s;]+)", text, re.I)
    if m:
        out["spf_domain"] = domain_of(m.group(1)) or m.group(1).lower()
    m = re.search(r"header\.d=([^\s;]+)", text, re.I)
    if m:
        out["dkim_domain"] = m.group(1).lower()
    m = re.search(r"\(p=(\w+)", text, re.I)
    if m:
        out["dmarc_policy"] = m.group(1).lower()
    return out


# ---------------------------------------------------------------- SPF

def _helo_for(parsed):
    ip = parsed.get("sending_ip", "")
    for header in parsed.get("received_chain", []):
        if ip and ip in header:
            m = re.search(r"\bfrom\s+(\S+)", header, re.I)
            if m:
                return m.group(1).strip("[]()")
    return ""


def check_spf(parsed, auth, timeout):
    """FR-2.1. SPF is tested against the Return-Path (envelope) domain, not From."""
    sender = parsed["return_path"]["address"] or parsed["from"]["address"]
    domain = domain_of(sender)
    ip = parsed.get("sending_ip", "")
    result, reason = "error", ""
    if not ip or not domain:
        reason = "no sending IP or sender domain found in the email"
    else:
        try:
            result, explanation = spf.check2(
                i=ip, s=sender, h=_helo_for(parsed) or domain, timeout=timeout, querytime=timeout)
            reason = explanation
            if result in ("temperror", "permerror"):
                result = "error"
        except Exception as exc:  # DNS down etc.
            result, reason = "error", f"live lookup failed ({type(exc).__name__})"
    if result != "error":
        return {"result": result, "domain": domain, "source": LIVE,
                "evidence": f"Sending IP {ip}, envelope domain {domain}: {reason}"}
    if auth.get("spf"):
        return {"result": auth["spf"], "domain": auth.get("spf_domain", domain), "source": REPORTED,
                "evidence": f"Live check unavailable ({reason}); mail server reported spf={auth['spf']}"}
    return {"result": "error", "domain": domain, "source": NOT_RUN,
            "evidence": f"SPF could not run: {reason}"}


# ---------------------------------------------------------------- DKIM

def check_dkim(parsed, raw, auth, timeout):
    """FR-2.2. Verify every DKIM-Signature using the public key published in DNS."""
    sigs = parsed.get("dkim_signatures", [])
    if not sigs:
        return {"result": "none", "domain": "", "source": LIVE,
                "evidence": "No DKIM-Signature header in this email"}

    state = {"dns_error": False, "no_key": False}

    def dnsfunc(name, timeout=timeout):
        if isinstance(name, bytes):  # dkimpy passes bytes with a trailing dot
            name = name.decode()
        try:
            records = dns_txt(name.rstrip("."), timeout)
        except DnsError:
            state["dns_error"] = True
            return None
        keys = [r for r in records if "p=" in r]
        if not keys:
            state["no_key"] = True
            return None
        return keys[0].encode()

    verdicts = []  # (passed, domain)
    for idx, header in enumerate(sigs):
        m = re.search(r"(?:^|;)\s*d=\s*([^;\s]+)", header)
        domain = m.group(1).lower() if m else ""
        try:
            ok = bool(raw) and dkim.DKIM(raw).verify(idx, dnsfunc)
        except Exception:
            ok = False
        verdicts.append((ok, domain))

    passed = [d for ok, d in verdicts if ok]
    if passed:
        return {"result": "pass", "domain": passed[0], "source": LIVE,
                "evidence": f"Signature from {passed[0]} verified with the public key in DNS"}

    domain = verdicts[0][1]
    if state["dns_error"] or state["no_key"]:
        why = "DNS lookup of the public key failed" if state["dns_error"] else "public key not found in DNS"
        live = None
    else:
        why = "signature does not match the message"
        live = {"result": "fail", "domain": domain, "source": LIVE,
                "evidence": f"Signature from {domain} present but invalid: {why}"}
    # Live check failed or could not run: the receiving server's verdict may be more
    # reliable (e.g. forwarding rewrote the message and broke the signature) - FR-2.4.
    if auth.get("dkim") == "pass" or (live is None and auth.get("dkim")):
        return {"result": auth["dkim"], "domain": auth.get("dkim_domain", domain), "source": REPORTED,
                "evidence": f"Live check did not verify ({why}); mail server reported dkim={auth['dkim']}"}
    if live:
        return live
    return {"result": "error", "domain": domain, "source": NOT_RUN,
            "evidence": f"DKIM could not run: {why}"}


# ---------------------------------------------------------------- DMARC

def _dmarc_record(from_domain, timeout):
    """Look up _dmarc.<from domain>, then _dmarc.<organisational domain>."""
    candidates = [from_domain]
    if org_domain(from_domain) != from_domain:
        candidates.append(org_domain(from_domain))
    for dom in candidates:
        for rec in dns_txt(f"_dmarc.{dom}", timeout):
            if rec.lower().replace(" ", "").startswith("v=dmarc1"):
                return dom, rec
    return None, None


def _aligned(domain_a, domain_b, strict):
    if not domain_a or not domain_b:
        return False
    return domain_a == domain_b if strict else org_domain(domain_a) == org_domain(domain_b)


def _align_word(result, ok):
    if ok:
        return "aligned with From"
    return "passed but NOT aligned with From" if result == "pass" else "did not pass"


def fetch_dmarc(parsed, timeout):
    """Fetch the DMARC record (separate step so it can run beside the SPF and DKIM lookups)."""
    from_domain = domain_of(parsed["from"]["address"])
    try:
        return _dmarc_record(from_domain, timeout)
    except DnsError as exc:
        return "error", str(exc)


def check_dmarc(parsed, spf_res, dkim_res, auth, dmarc_lookup):
    """FR-2.3. Policy plus alignment of the From domain with SPF / DKIM domains."""
    from_domain = domain_of(parsed["from"]["address"])
    found_in, record = dmarc_lookup

    def reported(why):
        if auth.get("dmarc"):
            pol = auth.get("dmarc_policy")
            return {"result": auth["dmarc"], "policy": pol, "source": REPORTED,
                    "evidence": f"{why}; mail server reported dmarc={auth['dmarc']}"
                                + (f" (policy p={pol})" if pol else "")}
        return {"result": "error", "policy": None, "source": NOT_RUN, "evidence": f"DMARC could not run: {why}"}

    if found_in == "error":
        return reported("Live DMARC lookup failed")
    if record is None:
        return {"result": "none", "policy": None, "source": LIVE,
                "evidence": f"No DMARC record published for {from_domain}"}

    tags = {k.strip().lower(): v.strip().lower()
            for k, _, v in (p.partition("=") for p in record.split(";")) if k.strip()}
    policy = tags.get("p", "none")
    spf_strict, dkim_strict = tags.get("aspf") == "s", tags.get("adkim") == "s"
    spf_ok = spf_res["result"] == "pass" and _aligned(from_domain, spf_res["domain"], spf_strict)
    dkim_ok = dkim_res["result"] == "pass" and _aligned(from_domain, dkim_res["domain"], dkim_strict)
    detail = (f"From domain {from_domain}, policy p={policy}; "
              f"SPF {spf_res['result']} for {spf_res['domain'] or '-'} "
              f"({_align_word(spf_res['result'], spf_ok)}), "
              f"DKIM {dkim_res['result']} for {dkim_res['domain'] or '-'} "
              f"({_align_word(dkim_res['result'], dkim_ok)})")
    if spf_ok or dkim_ok:
        return {"result": "pass", "policy": policy, "source": LIVE, "evidence": detail}
    unknown = "error" in (spf_res["result"], dkim_res["result"])
    if unknown:  # cannot honestly say fail when an input is missing
        return reported(f"SPF/DKIM could not be fully checked ({detail})")
    return {"result": "fail", "policy": policy, "source": LIVE, "evidence": detail}


# ---------------------------------------------------------------- findings

def _finding(points, fid, title, evidence):
    return {"id": fid, "title": title, "points": points.get(fid, 0), "evidence": evidence}


def check_sender(parsed, raw=None, config=None):
    """Run M2. Never raises: any failure becomes status 'error' with 0 points (NFR-3)."""
    try:
        return _check_sender(parsed, raw, config or load_config())
    except Exception as exc:
        return {"check": "sender", "status": "error", "findings": [], "details": [],
                "error": f"could not run: {type(exc).__name__}: {exc}"}


def _check_sender(parsed, raw, config):
    points = config["points"]
    timeout = config["dns"]["timeout_seconds"]
    auth = parse_auth_results(parsed.get("authentication_results", []))

    # The three network lookups are independent, so run them side by side (NFR-2).
    with ThreadPoolExecutor(max_workers=3) as pool:
        job_spf = pool.submit(check_spf, parsed, auth, timeout)
        job_dkim = pool.submit(check_dkim, parsed, raw, auth, timeout)
        job_dmarc = pool.submit(fetch_dmarc, parsed, timeout)
        spf_res, dkim_res, dmarc_lookup = job_spf.result(), job_dkim.result(), job_dmarc.result()
    dmarc_res = check_dmarc(parsed, spf_res, dkim_res, auth, dmarc_lookup)

    findings = []
    r = spf_res["result"]
    if r == "fail":
        findings.append(_finding(points, "spf_fail", "SPF failed", spf_res["evidence"]))
    elif r == "softfail":
        findings.append(_finding(points, "spf_softfail", "SPF softfail", spf_res["evidence"]))
    elif r == "none":
        findings.append(_finding(points, "spf_none", "No SPF record", spf_res["evidence"]))

    r = dkim_res["result"]
    if r == "fail":
        findings.append(_finding(points, "dkim_invalid", "DKIM signature invalid", dkim_res["evidence"]))
    elif r == "none":
        findings.append(_finding(points, "dkim_none", "No DKIM signature", dkim_res["evidence"]))

    r = dmarc_res["result"]
    if r == "fail":
        findings.append(_finding(points, "dmarc_fail", "DMARC failed", dmarc_res["evidence"]))
    elif r == "none":
        findings.append(_finding(points, "dmarc_none", "No DMARC record", dmarc_res["evidence"]))

    # FR-2.5: Reply-To / Return-Path on a different organisation than From.
    # Legitimate mail often goes through a mailing service whose bounce address is on
    # another domain (e.g. YouTube mail has a google.com Return-Path). So a different
    # Return-Path is only a red flag when DMARC did NOT pass; a different Reply-To
    # (where your answer goes) is always a red flag.
    from_dom = domain_of(parsed["from"]["address"])
    differs = {}
    for label, key in (("Reply-To", "reply_to"), ("Return-Path", "return_path")):
        dom = domain_of(parsed[key]["address"])
        if dom and org_domain(dom) != org_domain(from_dom):
            differs[label] = dom
    excused = "Return-Path" in differs and dmarc_res["result"] == "pass"
    counted = {k: v for k, v in differs.items() if not (k == "Return-Path" and excused)}
    if counted:
        text = f"From domain is {from_dom} but " + " and ".join(f"{k} domain is {v}" for k, v in counted.items())
        mismatch_res = {"result": "mismatch", "source": LIVE, "evidence": text}
        findings.append(_finding(points, "domain_mismatch", "Reply-To / Return-Path differs from From", text))
    elif excused:
        mismatch_res = {"result": "ok", "source": LIVE,
                        "evidence": f"Return-Path domain {differs['Return-Path']} differs from {from_dom}, but DMARC "
                                    "passed, so this is an authorised sending service (not penalised)"}
    else:
        mismatch_res = {"result": "ok", "source": LIVE,
                        "evidence": "Reply-To and Return-Path match the From domain (or are absent)"}

    details = [{"name": n, **d} for n, d in
               (("SPF", spf_res), ("DKIM", dkim_res), ("DMARC", dmarc_res), ("Reply-To / Return-Path", mismatch_res))]

    if spf_res["result"] == "error" and dmarc_res["result"] == "error":
        # Nothing could be verified (no internet, no mail-server header). PRD section 6:
        # a check that errors adds 0 points and is shown as "could not run".
        status, findings = "error", []
    else:
        status = status_for(findings, config)
    return {"check": "sender", "status": status, "findings": findings, "details": details}
