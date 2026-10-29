"""Every test runs against a fake, empty DNS so tests never touch the internet."""
import pytest
import spf

from modules import links, sender


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


@pytest.fixture(autouse=True)
def zone(monkeypatch):
    z = FakeZone()
    monkeypatch.setattr(sender, "dns_txt", z.dns_txt)
    monkeypatch.setattr(spf, "DNSLookup", z.spf_lookup)
    monkeypatch.setattr(links, "dns_lookup", z.dns_lookup)
    monkeypatch.setattr(links, "whois_created", z.whois_created)
    return z
