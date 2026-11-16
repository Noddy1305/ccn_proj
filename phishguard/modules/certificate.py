"""M4 - Certificate check (TLS).

A website using https:// proves who it is with a certificate, issued by a Certificate Authority (CA).
For every untrusted https link we do ONLY the TLS handshake on port 443 (the "hello, show me your ID"
step) and read the certificate. We never ask for the web page, run anything or download anything
(FR-4.1, SAF-1). Points come from config.yaml, never from this file.
"""
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import timedelta
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from modules import load_config, offline, status_for
from modules.links import host_of, is_ip, is_trusted, load_trusted

TITLES = {
    "cert_untrusted": "Certificate not trusted (self-signed or unknown issuer)",
    "cert_expired": "Certificate has expired",
    "cert_hostname_mismatch": "Certificate is for a different website name",
    "cert_new": "Certificate issued in the last 7 days",
}


class CertError(Exception):
    """No TLS connection could be made (no internet, no https server, timeout). Not the certificate's fault."""


# ---------------------------------------------------------------- network (replaceable in tests)

def _handshake(host, timeout, verify):
    context = ssl.create_default_context()
    if not verify:                                 # only used to READ a certificate that failed verification
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:   # the handshake happens here
            return tls.getpeercert(binary_form=True)                     # then we close: no web request


def fetch_certificate(host, timeout=5):
    """FR-4.1: handshake only. Returns {"der": certificate bytes, "verify_error": "" or the reason it failed}.

    First a normal, verified handshake. If the certificate fails verification we connect once more
    without verifying, only to read the certificate and show why it failed.
    """
    try:
        return {"der": _handshake(host, timeout, verify=True), "verify_error": ""}
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or str(exc)
    except OSError as exc:                         # includes ssl.SSLError, timeouts and DNS failures
        raise CertError(type(exc).__name__) from exc
    try:
        return {"der": _handshake(host, timeout, verify=False), "verify_error": verify_error}
    except OSError as exc:
        raise CertError(type(exc).__name__) from exc


def _not_saved():
    raise CertError("not in the offline cache")


# Offline demo mode (NFR-4): the handshake is M4's only way out to the internet.
fetch_certificate = offline.cached("tls", key=lambda host, *_, **__: [host.lower()], on_miss=_not_saved)(fetch_certificate)


# ---------------------------------------------------------------- reading a certificate

def names_in(cert):
    """The website names a certificate covers (Subject Alternative Names, else the Common Name)."""
    try:
        return [n.lower() for n in cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        return [a.value.lower() for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]


def name_matches(host, names):
    """Does the certificate cover this host? '*.example.com' covers exactly one extra label."""
    host = host.lower().rstrip(".")
    for name in names:
        name = name.rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def _issuer(cert):
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        found = cert.issuer.get_attributes_for_oid(oid)
        if found:
            return found[0].value
    return "unknown issuer"


def inspect(host, fetched, now, new_days):
    """FR-4.2 / 4.3: read one certificate. Returns (list of problem ids, evidence text)."""
    cert = x509.load_der_x509_certificate(fetched["der"])
    start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    names = names_in(cert)
    error = fetched.get("verify_error", "").lower()
    problems = []
    # OpenSSL reports only its FIRST complaint, so expiry and the name are checked by us directly.
    self_signed = cert.issuer == cert.subject
    if self_signed or (error and "expired" not in error and "hostname" not in error):
        problems.append("cert_untrusted")
    if end < now:
        problems.append("cert_expired")
    if not name_matches(host, names):
        problems.append("cert_hostname_mismatch")
    age = (now - start).days
    if 0 <= age < new_days:
        problems.append("cert_new")
    shown = ", ".join(names[:3]) + (f" (+{len(names) - 3} more)" if len(names) > 3 else "")
    evidence = (f"Issued by {'itself (self-signed)' if self_signed else _issuer(cert)}; "
                f"valid {start:%Y-%m-%d} to {end:%Y-%m-%d} (issued {age} days ago); covers {shown or 'no names'}")
    if error:
        evidence += f"; verification said: {fetched['verify_error']}"
    return problems, evidence


# ---------------------------------------------------------------- the check

def check_certificate(parsed, config=None, now=None):
    """Run M4. Never raises: any failure becomes status 'error' with 0 points (NFR-3)."""
    try:
        return _check_certificate(parsed, config or load_config(), now or offline.now())
    except Exception as exc:
        return {"check": "certificate", "status": "error", "findings": [], "details": [],
                "error": f"could not run: {type(exc).__name__}: {exc}"}


def _check_certificate(parsed, config, now):
    ccfg, timeout = config["certificate"], config["dns"]["timeout_seconds"]
    trusted, _ = load_trusted()
    https, plain = [], []
    for link in parsed.get("links", []):
        host = host_of(link["href"])
        if not host:
            continue
        target = https if urlparse(link["href"].strip()).scheme.lower() == "https" else plain
        if host not in target:
            target.append(host)

    details = []
    for host in plain:                                                     # FR-4.4
        if host not in https:
            details.append({"name": host, "result": "no certificate", "source": "from the email",
                            "evidence": "Plain http:// link: the connection is not encrypted, so there is no certificate to check"})
    to_check = []
    for host in https:
        if is_trusted(host, trusted):
            details.append({"name": host, "result": "trusted", "source": "trusted list",
                            "evidence": "On the trusted-domain list, so the certificate is not checked"})
        elif is_ip(host):
            details.append({"name": host, "result": "not checked", "source": "from the email",
                            "evidence": "Raw IP address (the link check already flags it)"})
        else:
            to_check.append(host)
    skipped, to_check = to_check[ccfg["max_hosts"]:], to_check[:ccfg["max_hosts"]]

    # All handshakes run side by side with ONE hard time limit: connect() has a timeout, but the DNS step before
    # it does not, so a stuck lookup must not hold the page. While recording we wait for every answer.
    pool = ThreadPoolExecutor(max_workers=8)
    jobs = {host: pool.submit(fetch_certificate, host, timeout) for host in to_check}
    wait(jobs.values(), timeout=None if offline.mode() == "record" else 2 * timeout + 1)
    pool.shutdown(wait=False)

    found, connected = {}, 0
    for host, job in jobs.items():
        if not job.done():
            details.append({"name": host, "result": "could not connect", "source": "could not run",
                            "evidence": "No answer in time"})
            continue
        try:
            fetched = job.result()
        except CertError as exc:
            details.append({"name": host, "result": "could not connect", "source": "could not run",
                            "evidence": f"No TLS connection on port 443 ({exc})"})
            continue
        connected += 1
        problems, evidence = inspect(host, fetched, now, ccfg["new_days"])
        for fid in problems:
            found.setdefault(fid, []).append(host)
        details.append({"name": host, "result": ", ".join(p.replace("cert_", "").replace("_", " ") for p in problems) or "valid",
                        "source": "live", "evidence": evidence})
    for host in skipped:
        details.append({"name": host, "result": "not checked", "source": "could not run",
                        "evidence": f"More than {ccfg['max_hosts']} https sites; this one was skipped"})
    if not details:
        details.append({"name": "(no web links)", "result": "ok", "source": "from the email",
                        "evidence": "The email contains no http/https links"})

    points = config["points"]
    findings = [{"id": fid, "title": TITLES[fid], "points": points.get(fid, 0), "evidence": "certificate shown by the linked website " + ", ".join(hosts)}
                for fid, hosts in found.items()]
    findings.sort(key=lambda f: -f["points"])
    status = status_for(findings, config)
    if status == "pass" and to_check and connected == 0:
        status = "error"           # nothing could be reached (no internet) and nothing else is wrong
    elif status == "pass" and not to_check:
        status = "none"            # no certificate needed checking (only http, trusted or IP links): not a "pass"
    return {"check": "certificate", "status": status, "findings": findings, "details": details}
