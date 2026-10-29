"""M3 - Link and domain check.

Looks at where each link REALLY goes (the href) and whether that destination is
trustworthy. It only reads text and asks DNS / WHOIS about domain names. It never
opens, clicks or downloads a link's page (FR-3.7 / SAF-1).
"""
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import whois
from rapidfuzz import process
from rapidfuzz.distance import Levenshtein

from modules import load_config, status_for
from modules.sender import DnsError, org_domain

TRUSTED_FILE = Path(__file__).resolve().parent.parent / "data" / "trusted_domains.txt"

# Names too generic to treat as a brand.
GENERIC_BRANDS = {"mail", "www", "web", "net", "online", "news", "one", "my", "go",
                  # trusted names that are also ordinary words or too short to be safe brands
                  "live", "office", "meta", "zoom", "goo", "ola", "mit", "nic", "vit", "ugc", "uber", "youtu"}
MIN_LOOKALIKE_NAME = 6      # shorter names (kodak/kotak, olx/ola) are too easy to confuse by accident
# Bare words like "srmist.edu.in" in link text only count as a domain if the ending is a real TLD.
COMMON_TLDS = {"com", "org", "net", "edu", "gov", "in", "io", "co", "uk", "info", "biz", "app", "dev",
               "me", "us", "ai", "xyz", "online", "site", "top", "club", "shop", "store", "tech",
               "ru", "cn", "de", "fr", "au", "ca", "sbi", "ly", "be", "gle"}
TEXT_DOMAIN = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,24})", re.I)


# ---------------------------------------------------------------- trusted list

_trusted_cache = {}


def load_trusted(path=TRUSTED_FILE):
    """Return (set of trusted registered domains, set of brand names)."""
    if path not in _trusted_cache:
        domains = set()
        for line in Path(path).read_text().splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line:
                domains.add(line)
        brands = {org_domain(d).split(".")[0] for d in domains}
        brands = {b for b in brands if len(b) >= 3 and b not in GENERIC_BRANDS}
        _trusted_cache[path] = (domains, brands)
    return _trusted_cache[path]


def is_trusted(host, trusted):
    return any(host == d or host.endswith("." + d) for d in trusted)


# ---------------------------------------------------------------- network (replaceable in tests)

def dns_lookup(name, rtype, timeout=5):
    """Records of a type as strings. [] if none exist. Raises DnsError if DNS itself fails."""
    try:
        return [r.to_text() for r in dns.resolver.resolve(name, rtype, lifetime=timeout)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception as exc:
        raise DnsError(type(exc).__name__) from exc


def whois_created(domain, timeout=5):
    """Return (status, creation datetime). Status: ok / unknown / not_registered / error."""
    try:
        record = whois.whois(domain, timeout=timeout, quiet=True)
    except whois.exceptions.WhoisDomainNotFoundError:
        return "not_registered", None
    except Exception:
        return "error", None
    created = record.get("creation_date") if record else None
    if isinstance(created, list):
        created = [c for c in created if isinstance(c, datetime)]
        created = min(created) if created else None
    if not isinstance(created, datetime):
        return "unknown", None  # many registries (often .in) hide dates
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return "ok", created


# ---------------------------------------------------------------- pure helpers

def host_of(href):
    """Hostname of an http(s)/ftp link, else ''. mailto:, tel:, # etc. have none."""
    try:
        parts = urlparse(href.strip())
        if parts.scheme.lower() not in ("http", "https", "ftp"):
            return ""
        return (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered(host):
    return host if is_ip(host) else org_domain(host)


def text_domain(text):
    """Domain a link's visible text appears to show (e.g. 'www.srmist.edu.in/x'), else ''."""
    for m in TEXT_DOMAIN.finditer((text or "").lower()):
        dom = m.group(1)
        explicit = m.group(0).startswith("http") or dom.startswith("www.")
        if explicit or dom.rsplit(".", 1)[-1] in COMMON_TLDS:
            return dom[4:] if dom.startswith("www.") else dom
    return ""


def lookalike_of(host, trusted):
    """FR-3.1: closest trusted domain within edit distance 1-2, or None.

    Tests the registered domain and also runs of 2+ labels hidden in the subdomain part
    (srmlst.edu.in.verify-login.com hides 'srmlst.edu.in'). Names shorter than 6 letters are skipped and
    distance 2 is allowed only for long domains, to avoid false alarms on short real domains.
    """
    if is_ip(host):
        return None
    reg = registered(host)
    labels = host.split(".")
    sub = labels[: len(labels) - len(reg.split("."))]
    candidates = {reg}
    for i in range(len(sub)):
        for j in range(i + 2, len(sub) + 1):
            candidates.add(".".join(sub[i:j]))
    best = None
    for cand in sorted(candidates):                       # sorted: same answer every run (FR-6.4)
        name_len = len(org_domain(cand).split(".")[0])    # the part before .com / .edu.in
        if name_len < MIN_LOOKALIKE_NAME or cand in trusted:
            continue
        limit = 2 if len(cand) >= 10 else 1
        match = process.extractOne(cand, sorted(trusted), scorer=Levenshtein.distance, score_cutoff=limit)
        if match and match[1] >= 1 and (best is None or match[1] < best[2]):
            best = (cand, match[0], match[1])
    return best


def brand_in(host, brands):
    """FR-3.2: a trusted brand name inside the hostname of an unrelated domain."""
    tokens = [t for t in re.split(r"[.\-_0-9]+", host) if t]
    for brand in sorted(brands):
        for tok in tokens:
            if tok == brand or (len(brand) >= 6 and brand in tok):
                return brand
    return None


# ---------------------------------------------------------------- per-domain lookups

def inspect_domain(domain, host, cfg, now):
    """Look up age (WHOIS) and DNS for one untrusted registered domain."""
    timeout = cfg["dns"]["timeout_seconds"]
    info = {"domain": domain, "age_days": None, "created": None, "whois": "unknown",
            "resolves": None, "has_mx": None, "addresses": []}
    if is_ip(domain):
        info["resolves"] = True
        return info
    def safe(fn, *args):                  # a failed lookup is "unknown", never a crash
        try:
            return fn(*args)
        except DnsError:
            return None

    pool = ThreadPoolExecutor(max_workers=4)          # WHOIS and DNS run side by side (NFR-2)
    job_whois = pool.submit(whois_created, domain, timeout)
    job_a = pool.submit(safe, dns_lookup, host, "A", timeout)
    job_aaaa = pool.submit(safe, dns_lookup, host, "AAAA", timeout)
    job_mx = pool.submit(safe, dns_lookup, domain, "MX", timeout)
    try:
        # Some registries are slow (the library makes several 5 s queries): give up after
        # timeout + 1 s and treat the age as unknown rather than make the user wait.
        status, created = job_whois.result(timeout=timeout + 1)
    except FuturesTimeout:
        status, created = "unknown", None
    pool.shutdown(wait=False)
    info["whois"] = status
    if created:
        info["created"], info["age_days"] = created.date().isoformat(), (now - created).days
    a, aaaa, mx = job_a.result(), job_aaaa.result(), job_mx.result()
    if a is not None or aaaa is not None:             # at least one answer, even if empty
        addrs = (a or []) + (aaaa or [])
        info["addresses"], info["resolves"] = addrs[:3], bool(addrs)
    if mx is not None:
        info["has_mx"] = bool(mx)
    if status == "not_registered" and info["resolves"] is None:
        info["resolves"] = False
    return info


def describe(info):
    parts = []
    if info["whois"] == "ok":
        parts.append(f"registered {info['age_days']} days ago ({info['created']})")
    elif info["whois"] == "not_registered":
        parts.append("not registered (WHOIS has no record)")
    else:
        parts.append("registration date unknown")
    if info["resolves"] is True:
        parts.append("resolves in DNS" + (" (has mail servers)" if info["has_mx"] else ""))
    elif info["resolves"] is False:
        parts.append("does NOT resolve in DNS")
    else:
        parts.append("DNS lookup could not run")
    return "; ".join(parts)


# ---------------------------------------------------------------- the check

def check_links(parsed, config=None, now=None):
    """Run M3. Never raises: any failure becomes status 'error' with 0 points (NFR-3)."""
    try:
        return _check_links(parsed, config or load_config(), now or datetime.now(timezone.utc))
    except Exception as exc:
        return {"check": "links", "status": "error", "findings": [], "details": [],
                "error": f"could not run: {type(exc).__name__}: {exc}"}


def _check_links(parsed, config, now):
    points, lcfg = config["points"], config["links"]
    trusted, brands = load_trusted()
    found = {}       # finding id -> list of evidence strings (one finding per id per email)
    flagged = set()  # registered domains that caused a finding

    def flag(fid, text, domain=None):
        if domain:
            flagged.add(domain)
        found.setdefault(fid, [])
        if text not in found[fid]:
            found[fid].append(text)

    hosts = {}       # registered domain -> first host seen
    for link in parsed.get("links", []):
        host = host_of(link["href"])
        if not host:
            continue
        reg = registered(host)
        hosts.setdefault(reg, host)

        if is_ip(host):                                                    # FR-3.5
            flag("raw_ip_link", f"link goes to raw IP address {host}")
        shown = text_domain(link.get("text", ""))                          # FR-3.4
        if shown and registered(shown) != reg and not (is_trusted(shown, trusted) and is_trusted(host, trusted)):
            flag("link_text_mismatch", f"text shows {shown} but link goes to {host}")
        if is_trusted(host, trusted) or is_ip(host):
            continue
        look = lookalike_of(host, trusted)                                 # FR-3.1
        if look:
            flag("lookalike_domain", f"{look[0]} is {look[2]} letter(s) away from trusted {look[1]} (link host {host})", reg)
        brand = brand_in(host, brands)                                     # FR-3.2
        if brand:
            flag("brand_in_domain", f"brand name '{brand}' inside unrelated domain {host}", reg)

    untrusted = [d for d, h in hosts.items() if not is_trusted(h, trusted) and not is_ip(h)]
    skipped = untrusted[lcfg["max_domains"]:]
    untrusted = untrusted[: lcfg["max_domains"]]

    with ThreadPoolExecutor(max_workers=8) as pool:                         # lookups run in parallel
        infos = list(pool.map(lambda d: inspect_domain(d, hosts[d], config, now), untrusted))

    for info in infos:
        d = info["domain"]
        if info["age_days"] is not None:                                   # FR-3.3
            if info["age_days"] < lcfg["age_new_days"]:
                flag("domain_age_new", f"{d} registered {info['age_days']} days ago", d)
            elif info["age_days"] < lcfg["age_recent_days"]:
                flag("domain_age_recent", f"{d} registered {info['age_days']} days ago", d)
        if info["resolves"] is False:                                      # FR-3.6
            flag("domain_unresolved", f"{d} does not resolve in DNS", d)

    titles = {
        "lookalike_domain": "Lookalike of a trusted domain",
        "domain_age_new": "Domain registered less than 30 days ago",
        "link_text_mismatch": "Link text shows a different domain than where it goes",
        "brand_in_domain": "Brand name inside an unrelated domain",
        "raw_ip_link": "Link uses a raw IP address",
        "domain_age_recent": "Domain registered 30-180 days ago",
        "domain_unresolved": "Domain does not resolve in DNS",
    }
    findings = [{"id": fid, "title": titles[fid], "points": points.get(fid, 0), "evidence": "; ".join(ev)}
                for fid, ev in found.items()]
    findings.sort(key=lambda f: -f["points"])

    details = []
    for reg, host in hosts.items():
        if is_ip(host):
            details.append({"name": host, "result": "raw IP", "source": "live",
                            "evidence": "Link points to a number, not a domain name"})
        elif is_trusted(host, trusted):
            details.append({"name": reg, "result": "trusted", "source": "trusted list",
                            "evidence": "On the trusted-domain list, so no age or DNS lookup needed"})
    for info in infos:
        details.append({"name": info["domain"], "result": "suspicious" if info["domain"] in flagged else "checked", "source": "live",
                        "evidence": describe(info)})
    for d in skipped:
        details.append({"name": d, "result": "not checked", "source": "could not run",
                        "evidence": f"More than {lcfg['max_domains']} untrusted domains; this one was skipped"})
    if not hosts:
        details.append({"name": "(no web links)", "result": "ok", "source": "live",
                        "evidence": "The email contains no http/https links"})

    no_lookup = infos and all(i["whois"] in ("unknown", "error") and i["resolves"] is None for i in infos)
    status = status_for(findings, config)
    if status == "pass" and no_lookup:
        status = "error"       # nothing could be looked up (no internet) and nothing else is wrong
    return {"check": "links", "status": status, "findings": findings, "details": details}
