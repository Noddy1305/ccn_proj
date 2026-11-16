"""Every test runs against a fake, empty DNS, a fake TLS handshake and a fake AI, so tests never touch the internet."""
import pytest
import spf

from modules import certificate, links, llm_client, offline, sender

# The real network functions (already wrapped for offline mode), captured before any fake replaces them.
# Only the offline replay tests put these back, and those tests block the network first.
REAL = {(sender, "dns_txt"): sender.dns_txt, (spf, "DNSLookup"): spf.DNSLookup,
        (links, "dns_lookup"): links.dns_lookup, (links, "whois_created"): links.whois_created,
        (certificate, "fetch_certificate"): certificate.fetch_certificate,
        (llm_client, "complete_json"): llm_client.complete_json}


@pytest.fixture(autouse=True)
def live_mode():
    """Tests always start in live mode, whatever config.yaml or PHISHGUARD_MODE say."""
    offline.reset()
    offline.set_mode("live")
    yield
    offline.reset()


class FakeZone:
    """Tiny pretend DNS. Unknown names behave like NXDOMAIN (no records)."""

    def __init__(self):
        self.txt, self.a, self.mx, self.created, self.broken = {}, {}, {}, {}, False

    def add_txt(self, name, *records):
        self.txt[name.lower()] = list(records)

    # used by modules.sender.dns_txt
    def dns_txt(self, name, timeout=5):
        if self.broken:
            raise sender.DnsError("Timeout")
        return self.txt.get(name.lower(), [])

    # used by modules.links.dns_lookup (A / AAAA / MX)
    def dns_lookup(self, name, rtype, timeout=5):
        if self.broken:
            raise sender.DnsError("Timeout")
        table = {"A": self.a, "MX": self.mx}.get(rtype, {})
        return table.get(name.lower(), [])

    # used by modules.links.whois_created: a datetime, "notfound", or missing = unknown
    def whois_created(self, domain, timeout=5):
        if self.broken:
            return "error", None
        value = self.created.get(domain.lower())
        if value == "notfound":
            return "not_registered", None
        return ("ok", value) if value else ("unknown", None)

    def live(self, domain, age_days=None, now=None):
        """Make a domain exist in DNS, optionally registered N days before `now`."""
        from datetime import datetime, timedelta, timezone
        self.a[domain] = ["198.51.100.7"]
        self.mx[domain] = ["10 mail." + domain + "."]
        if age_days is not None:
            self.created[domain] = (now or datetime.now(timezone.utc)) - timedelta(days=age_days)

    # used by pyspf (module-level spf.DNSLookup)
    def spf_lookup(self, name, qtype, strict=True, timeout=None):
        if self.broken:
            raise spf.TempError("DNS timeout")
        name = name.lower()
        if qtype == "TXT":
            return [((name, qtype), (r.encode(),)) for r in self.txt.get(name, [])]
        if qtype in ("A", "AAAA"):
            return [((name, qtype), ip) for ip in self.a.get(name, [])]
        return []


class FakeAI:
    """Pretend AI. By default it is 'unreachable'; a test sets `.answers` (a function of system, user) to make it reply."""

    def __init__(self):
        self.answers, self.calls = None, []

    def complete_json(self, system, user, max_tokens, config=None):
        self.calls.append({"system": system, "user": user, "max_tokens": max_tokens})
        if self.answers is None:
            raise llm_client.LLMError("The AI service could not be reached.", unreachable=True)
        result = self.answers(system, user)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture(autouse=True)
def ai(monkeypatch):
    """Safety net: no test can reach a real AI (and so none can spend or leak anything)."""
    fake = FakeAI()
    monkeypatch.setattr(llm_client, "complete_json", fake.complete_json)
    return fake


class FakeTLS:
    """Pretend TLS handshakes. `.certs[host]` = {"der": ..., "verify_error": ...}; any other host cannot be reached."""

    def __init__(self):
        self.certs, self.calls = {}, []

    def fetch(self, host, timeout=5):
        self.calls.append(host)
        if host not in self.certs:
            raise certificate.CertError("no network in tests")
        return self.certs[host]


@pytest.fixture(autouse=True)
def tls(monkeypatch):
    fake = FakeTLS()
    monkeypatch.setattr(certificate, "fetch_certificate", fake.fetch)
    return fake


@pytest.fixture
def real_network_functions(monkeypatch, zone, ai, tls):
    """Undo the fakes: put back the real (offline-wrapped) lookups. Use only together with a blocked network."""
    for (module, name), fn in REAL.items():
        monkeypatch.setattr(module, name, fn)


@pytest.fixture(autouse=True)
def zone(monkeypatch):
    z = FakeZone()
    monkeypatch.setattr(sender, "dns_txt", z.dns_txt)
    monkeypatch.setattr(spf, "DNSLookup", z.spf_lookup)
    monkeypatch.setattr(links, "dns_lookup", z.dns_lookup)
    monkeypatch.setattr(links, "whois_created", z.whois_created)
    return z
