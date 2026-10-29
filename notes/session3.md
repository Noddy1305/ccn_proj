# Session 3 Notes — Link and Domain Check (M3)

## 1. The big picture

This session added the **link and domain check (M3)**. It looks at every link in the email and asks: "Where does this link really go, and can that place be trusted?" It catches lookalike websites, brand-new domains, links that hide their real destination, and links that use a raw number instead of a name.

In the PhishGuard-AI flow, M3 gets its list of links from the parser (M1) and runs **at the same time as** the sender check (M2). Both hand their findings, with points, to the page. The scoring engine (M6, built in session 4) adds everything up for the verdict.

## 2. New terms

- **M1, M2, ... M8 (Module)**: the PRD numbers the project's building blocks. M1 = email parser, M2 = sender check, M3 = link and domain check, M4 = certificate check, M5 = tone analysis (AI), M6 = risk scoring engine, M7 = report generator, M8 = dashboard. The number also matches the file in `modules/` (for example `links.py` is M3).
- **URL (Uniform Resource Locator)**: a web address, like `https://www.srmist.edu.in/exams`.
- **Hostname**: the machine-name part of a URL: `www.srmist.edu.in`.
- **Registered domain**: the part you actually buy from a registry: `srmist.edu.in`. The `www.` in front is a **subdomain**, which the owner can create freely.
- **Top-level domain (TLD)**: the ending, such as `.com` or `.in`.
- **Trusted-domain list**: our own file (`data/trusted_domains.txt`) of well-known safe domains: big sites, Indian banks, government sites and universities.
- **Edit distance (Levenshtein distance)**: the number of single-letter changes (add, delete, swap) needed to turn one word into another. `srmlst` to `srmist` is 1.
- **Typosquatting**: registering a misspelt version of a real domain, hoping people won't notice.
- **Combosquatting**: registering a real brand name plus extra words, like `srmist-verify.com`.
- **Lookalike domain**: a domain very close to a trusted one (a typosquat).
- **WHOIS**: a public registry lookup that tells you when a domain was registered, and by whom.
- **Registrar**: a company that sells domain names.
- **Domain age**: how long ago the domain was registered. Phishing sites are often only days old.
- **DNS A record**: DNS entry that turns a name into an IPv4 address. **AAAA** does the same for IPv6.
- **MX record (Mail Exchanger)**: DNS entry naming a domain's mail servers.
- **NXDOMAIN**: the DNS answer "this domain does not exist".
- **Resolve**: to successfully turn a domain name into an address through DNS.
- **Raw IP link**: a link like `http://185.234.72.19/login` that uses numbers instead of a domain name.
- **Link text vs href**: the words you see on a link versus the address it really opens.
- **The `@` trick**: in `http://srmist.edu.in@evil.com/`, everything before the `@` is ignored by the browser. The real host is `evil.com`.
- **Timeout**: how long we wait for an answer before giving up. Ours is 5 seconds.
- **Thread / in parallel**: doing several lookups at the same moment instead of one after another.

## 3. How it works

First, a key rule: **we never open, click or download any link** (rule FR-3.7). We only read the address as text and ask DNS and WHOIS about the domain name. That is like checking the address on a parcel at the post office desk rather than going to the house.

### Feature A: lookalike domains (typosquatting)

**Analogy.** A fake shop sign reading "SRMIST Bookshop" versus "SRMLST Bookshop". At a glance they look identical, but one letter is swapped.

**What happens.** For each link we take its registered domain and compare it to every domain on the trusted list using edit distance. If it is **1 letter off** (or **2 for long domains**) but not identical, it is a lookalike: `srmlst.edu.in` is 1 letter from `srmist.edu.in`. We also look for a lookalike **hidden inside the subdomain** (explained twice below). To avoid false alarms, names shorter than 6 letters are skipped, because `kodak` and `kotak` are different real companies, and 2-letter differences only count for long domains.

**Why it matters.** This is the most common phishing trick. It scores 25 points.

**Edit distance, explained twice.** (1) Think of it as "how many keystrokes to fix the typo": `srmlst` to `srmist` needs one keystroke, so the distance is 1. (2) Or think of two spelling tests: the more letters you got wrong, the bigger the distance. A distance of 0 means the exact same word, which means trusted, not fake.

### Feature B: brand names inside unrelated domains (combosquatting)

**Analogy.** A stranger wearing a badge reading "Bank X Official". The badge is real text, but it doesn't make him a Bank X employee.

**What happens.** We take brand names from the trusted list (srmist, paypal, hdfcbank ...) and look for them as whole words inside the link's hostname, for example `srmist-verify.com` or `paypal.com.evil.net`. If the domain is not itself on the trusted list, it is flagged (15 points). Everyday words that happen to be brands (live, office, zoom, uber) are excluded so normal sites are not flagged.

**Why it matters.** Scammers love adding words like "verify", "secure" or "login" to a real brand name.

### Feature C: domain age (WHOIS)

**Analogy.** A shop with a painted-yesterday sign and no history versus one that has been on the street for 20 years.

**What happens.** We ask WHOIS when the domain was registered. Less than 30 days old is a heavy red flag (20 points). 30 to 180 days is a medium one (10 points). If the registry hides the date (common for `.in`) or WHOIS is slow, the age is **unknown** and adds **0 points**, because we never punish for missing information.

**Why it matters.** Phishing domains are bought, used for a few days and thrown away. Real companies' domains are usually years old.

### Feature D: link text that shows a different domain than where it goes

**Analogy.** A road sign says "Bank X, 1 km", but the arrow points to a back alley.

**What happens.** If the visible text of a link contains a domain (like `https://www.srmist.edu.in/hallticket`) and the real href goes to a different registered domain, we flag it (15 points). Text like "Help Center" has no domain, so it is ignored. If both the text domain and the real destination are on the trusted list (for example text `youtube.com`, href `google.com`), that is normal for big companies and is not flagged.

**Why it matters.** The reader sees a trusted address but the click goes elsewhere. This is exactly what the parser's saved (text, href) pairs make possible.

### Feature E: raw IP address in a link

**Analogy.** A letter asking you to deliver money to "house at GPS point 185.234.72.19", with no street name or company.

**What happens.** If a link's host is a number like `185.234.72.19`, we flag it (15 points).

**Why it matters.** Real organisations use domain names. A bare IP usually means a hastily set-up scam server.

### Feature F: domain does not resolve

**Analogy.** Calling a phone number and hearing "this number does not exist".

**What happens.** We ask DNS for the link host's A and AAAA records and the domain's MX records. If DNS says the name doesn't exist, we flag it (10 points). If DNS itself is broken (no internet), the result is **unknown** and adds 0 points, never a false alarm.

**Why it matters.** A link to a name that doesn't exist is either a mistake or a throwaway scam site that has already been taken down.

### Feature G: speed, safety and fairness rules

- **Trusted domains are skipped.** Links to `google.com`, `youtube.com`, `c.gle` and so on (and their subdomains) need no age or DNS lookup.
- **Each finding counts once per email**, even if many links share it, so a long newsletter isn't over-punished. The evidence lists every domain involved.
- **Lookups run in parallel.** WHOIS and DNS run side by side, and M2 and M3 run side by side. A slow WHOIS gives up after 6 seconds. At most 10 untrusted domains are looked up.
- **Failures never crash.** Any error becomes a "could not run" card with 0 points.
- **Points and limits live in `config.yaml`**, and the trusted list is a plain text file you can edit. Restart the server after editing the list, because it is read once.
- **Card colour rule (same for every card).** A card turns **red** if any single red flag is worth 20 points or more, **amber** if there are smaller flags, and **green** if there are none. The setting is `heavy_flag_points` in `config.yaml`.

## 4. Walk-through example

We follow `forged_exam_cell.eml`. After the parser, it has two links:

1. Text `https://www.srmist.edu.in/hallticket`, href `http://srmlst.edu.in.verify-login.com/portal`.
2. Text "our backup portal", href `http://203.0.113.50/login`.

**Link 1.**
- Host: `srmlst.edu.in.verify-login.com`. Its registered domain is `verify-login.com`, which is not on the trusted list.
- **Text mismatch**: the text shows `srmist.edu.in` but the link goes to `verify-login.com`. +15.
- **Lookalike**: hidden inside the subdomain is `srmlst.edu.in`, one letter from the trusted `srmist.edu.in`. +25.
- **Hidden-subdomain trick, explained twice.** (1) A web address is read from right to left, so the real owner is whatever comes just before `.com`: `verify-login.com`. Everything in front is just a decoration the scammer chose. (2) It is like writing "Bank X" on a letter to a PO Box owned by a stranger: the name in front looks right, but the box belongs to someone else.
- WHOIS and DNS are checked: `verify-login.com` is an old domain that resolves today (checked 29 Oct 2026), so no age or DNS points.

**Link 2.** The host is a raw IP address. +15.

**M3 total** = 25 + 15 + 15 = **55**. The links card is red.

**Combined with M2** (45 points from session 2): 45 + 55 = 100, so the provisional rating is **Phishing**, shown in red.

**Contrast, your real YouTube email.** Its links all point to `google.com`, `youtube.com` and `c.gle`, all on the trusted list. No lookups are needed, no findings are raised, and the total stays **0, Safe**.

**Other samples.** `corpus_phish.eml` links to `bankofsecure-alerts.net`, which WHOIS says is not registered, so DNS fails: +10. With the sender's 15 that is 25, which is still **Safe** until the tone check adds points in session 4. `newsletter.eml` links to `shopmart.com` (registered since 1998), so M3 raises nothing.

## 5. Files

- `phishguard/modules/links.py`: the whole M3 check. Point at `check_links()` for "show me where the link check starts". `lookalike_of()` does the edit-distance matching, `brand_in()` the combosquatting, `text_domain()` finds the domain shown in link text, `whois_created()` is the domain-age lookup, `dns_lookup()` is the DNS lookup, and `inspect_domain()` combines WHOIS and DNS for one domain.
- `phishguard/data/trusted_domains.txt`: the list of trusted domains. Add your own bank or college here.
- `phishguard/pipeline.py`: now runs M2 and M3 side by side. Point at `run_pipeline()`.
- `phishguard/modules/__init__.py`: `status_for()` is the shared red / amber / green rule.
- `phishguard/config.yaml`: new points (lookalike, age, mismatch, brand, raw IP, unresolved), the age limits (30 and 180 days) and `max_domains`.
- `phishguard/templates/dashboard.html`: now shows a "Link and domain check" card with one row per domain.
- `phishguard/tests/test_links.py` and `tests/fixtures/m3_*.eml`: 45 tests, including seven hand-made emails, one per finding, each of which must raise exactly its finding.
- `phishguard/tests/conftest.py`: the pretend DNS and WHOIS now cover M3 too, so tests never need the internet.
- `phishguard/modules/sender.py` (small change): its three DNS lookups now run side by side, and it uses the shared card rule.

## 6. Viva questions

1. **What does the link check do, and does it ever open the links?**
   It examines where each link really goes and whether that domain looks trustworthy, using only the address text, DNS and WHOIS. It never opens, clicks or downloads a link's page, so a malicious page can't harm us.

2. **How do you detect a lookalike domain?**
   We compare each link's registered domain with a trusted list using edit distance, which counts single-letter changes. If it is 1 letter away (2 for long domains) but not identical, such as `srmlst.edu.in` against `srmist.edu.in`, we flag it.

3. **What is the difference between typosquatting and combosquatting?**
   Typosquatting is a misspelt domain (`srmlst`). Combosquatting is the real brand plus extra words (`srmist-verify.com`). We catch the first with edit distance and the second by finding brand names inside unrelated domains.

4. **Why does domain age matter, and what if the age can't be found?**
   Phishing sites are usually only days old, so under 30 days scores 20 and 30 to 180 days scores 10. If the registry hides the date or WHOIS fails, the age is "unknown" and adds 0 points, because missing data is not evidence.

5. **What is the hidden-subdomain trick?**
   A scammer writes a trusted name at the front, as in `srmlst.edu.in.verify-login.com`. A web address is owned by the part just before `.com`, which here is `verify-login.com`. We look inside the subdomain part too, so we still catch it.

6. **What is a link-text mismatch and why is it dangerous?**
   It is when the visible text shows one domain but the href goes to another. The reader trusts what they see, but the click goes elsewhere. The parser stores both so we can compare them.

7. **Why are links to a raw IP address suspicious?**
   Real organisations use domain names. A bare number means no registered brand is behind it, which usually points to a quick scam server.

8. **How do you avoid false alarms on genuine emails?**
   Links to trusted domains and their subdomains are skipped. Each finding counts once per email. Short names and everyday words are not used for lookalike or brand matching. A missing lookup adds 0 points, and a different Return-Path is excused when DMARC passes (session 2).

9. **How does the check stay fast, and what if there's no internet?**
   WHOIS and DNS lookups for each domain run in parallel with a 5-second timeout, WHOIS gives up after 6 seconds, and only 10 untrusted domains are looked up. With no internet the lookups become "unknown", add 0 points and the card says "could not run"; it never crashes.

10. **Where do the points and the trusted list come from?**
    The points, age limits and thresholds are in `config.yaml`, and the trusted domains are in `data/trusted_domains.txt`. The code only reports what it found, so you can tune everything without changing code.

## 7. Remember this

- M3 **reads** links, **never opens** them: only DNS and WHOIS lookups.
- Lookalike = **edit distance 1-2** from a trusted domain; combosquatting = **brand name inside** an unrelated domain.
- A web address belongs to the part **just before `.com`**, so a trusted name in front of it means nothing.
- **Unknown is not guilty**: hidden WHOIS dates or no internet add **0 points**.
- Each finding counts **once per email**; trusted domains are **skipped**; card red = any single flag of **20+ points**.
