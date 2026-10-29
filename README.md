# PhishGuard-AI

An LLM-augmented, multi-layer tool that takes **one suspicious email (.eml)** and returns a verdict
(**Safe / Suspicious / Phishing**) with the evidence behind it. Course project for 21ECC402P
(Computer Communication and Network Security). Team: Kaustubh Guha, Rudraksh Dubey.

**Core principle: the code decides, the AI explains.** Only the rule-based scoring engine (M6) decides the
verdict. An LLM may add one small capped signal (tone, max 15 points) and may write the plain-English
report, but it can never decide the verdict.

> **If you are an AI coding tool (Claude Code, Codex, Cursor, Copilot, etc.): read this whole file first,
> then `CLAUDE.md` (the rules you must follow) and the relevant section of `PRD.md`. Section 9 below lists
> the rules and traps that matter most.**

---

## 1. Project status

The build is split into 8 sessions (PRD section 11). Status at the time of writing:

| # | Session | Status |
| --- | --- | --- |
| 1 | Setup + email parser (M1) | **Done** |
| 2 | Sender check: SPF, DKIM, DMARC (M2) | **Done** |
| 3 | Link and domain check (M3) | **Done** |
| 4 | Scoring (M6) + LLM tone (M5) + LLM report text (M7) | **Done** |
| 5 | Dashboard (M8): verdict badge, check cards, on-screen report, PDF download, 4 demo emails | **Done** (P0 complete) |
| 6 | Certificate check (M4) + offline cached demo mode | Not started |
| 7 | Evaluation on 100 emails, tune weights once, freeze | Not started |
| 8 | Review prep: report, slides, viva Q&A | Not started |

Optional P2 (only if time remains): batch mode, analyse a folder and export CSV.

What works today: upload a `.eml` (or pick a built-in sample) at the web page. It parses the email, runs the
sender check, link check, and tone check in parallel, scores them with M6, and shows a points table, a verdict,
per-check evidence cards, on-screen plain-English executive report, and exportable A4 incident report. **Next up (Session 6):**
certificate check (M4) and offline cached demo mode.

Note the PRD folder structure lists `modules/certificate.py`, `modules/tone.py`, `modules/report.py`,
`modules/llm_client.py`, `templates/report.html`, `scripts/evaluate.py` and `data/cache/`. These files are
**not created yet**; `scripts/` and `data/cache/` are empty directories (git does not track empty folders).

---

## 2. Quick start

Requires Python 3.10+ (developed on 3.12, Ubuntu). Run everything from the `phishguard/` folder.

```bash
cd phishguard
python3 -m venv venv              # first time only
source venv/bin/activate
pip install -r requirements.txt
python -m pytest -q               # expect: all tests pass (107 at time of writing)
python app.py                     # open http://127.0.0.1:5000
```

- The tests use a **fake DNS/WHOIS** and need **no internet**.
- The web page does **live** DNS/WHOIS lookups, so it needs internet. Offline it degrades gracefully
  (checks show "could not run" or "reported by mail server" and add 0 points; nothing crashes).
- Stop the server with Ctrl+C. After editing `data/trusted_domains.txt`, **restart** (it is cached).
- `python app.py` runs Flask with `debug=True` on 127.0.0.1:5000 (from `config.yaml`).

---

## 3. Architecture

One-way flow: parse once, check in parallel, score by rules, then explain.

```text
Email (.eml bytes)
   |
M1 parser (modules/parser.py)            -> dict of fields (no judgement)
   |
   +--> M2 sender  (modules/sender.py)   SPF / DKIM / DMARC / Reply-To       [rule-based, built]
   +--> M3 links   (modules/links.py)    lookalike, brand, WHOIS age, DNS     [rule-based, built]
   +--> M4 cert    (modules/certificate.py) TLS handshake only                [P1, NOT built]
   +--> M5 tone    (modules/tone.py)     LLM manipulation score 0-10          [NOT built]
   |
M6 scoring (modules/scoring.py)          fixed points from config.yaml -> verdict   [built; decides the verdict]
   |
   +--> M7 report  (modules/report.py)   LLM text + HTML + PDF                [NOT built]
   +--> M8 dashboard (app.py + templates/dashboard.html)                      [basic version built]
```

`pipeline.py :: run_pipeline(raw_bytes)` is the single entry point. It calls `parse_eml`, runs
`check_sender` and `check_links` in a `ThreadPoolExecutor` (NFR-2), then calls `score_email`, and returns a
dict for the template: `parsed, checks, rows, total, raw_total, band, bands, not_run, by_check`.
**New checks plug in here**: add the job to the pool and append its result to `checks`.

### Folder map

```text
CCN_Proj/
  README.md  CLAUDE.md  AGENTS.md  PRD.md  .gitignore
  notes/session1.md .. session4.md     beginner study notes (see section 8)
  chk/                                 LOCAL ONLY, git-ignored (personal real emails + screenshots)
  phishguard/
    app.py              Flask routes (M8 basic): GET /, POST /analyze
    pipeline.py         run_pipeline(): M1 -> (M2 || M3) -> M6
    config.yaml         ALL weights, thresholds, timeouts, tone settings (NFR-5)
    requirements.txt
    modules/
      __init__.py       load_config() (cached) and status_for() (shared card colour rule)
      parser.py         M1: parse_eml(), ParseError
      sender.py         M2: check_sender(), org_domain(), DnsError, dns_txt()
      links.py          M3: check_links(), lookalike_of(), brand_in(), whois_created(), dns_lookup()
      scoring.py        M6: score_email(), verdict_for(), BANDS
    data/
      trusted_domains.txt   trusted domains (edit freely; restart server after)
      samples/              4 demo .eml files (synthetic)
      cache/                empty; for offline mode (session 6)
    templates/dashboard.html
    tests/                  test_parser/sender/links/scoring/app.py, conftest.py, fixtures/
    scripts/                empty; evaluate.py comes in session 7
```

---

## 4. The module contract (important: follow it for every new check)

Every check (M2-M5) is a function returning **this dict**, and **must never raise** (NFR-3):

```python
{
  "check": "sender",                 # short name: sender | links | certificate | tone
  "status": "pass|warn|fail|error",  # card colour; "error" = could not run, adds 0 points
  "findings": [                      # red flags only
    {"id": "dmarc_fail",             # key into config.yaml -> points
     "title": "DMARC failed",
     "points": 25,                   # filled from config.yaml by the check (M6 re-reads it anyway)
     "evidence": "human-readable evidence string"}
  ],
  "details": [                       # optional: rows for the dashboard card table
    {"name": "SPF", "result": "pass", "source": "live", "evidence": "..."}
  ],
  "error": "could not run: ..."      # optional: only when status == "error"
}
```

Rules that apply to every check:
- **Never hardcode points.** Add the finding id to `points:` in `config.yaml`; look it up. M6 re-reads the
  weight by `finding["id"]` so weights can be tuned (session 7) with no code changes.
- Wrap the public function in try/except and return `status: "error"`, `findings: []` on any exception.
- One finding per id per email (put all offending items in the evidence text).
- Unknown/unavailable data (no internet, hidden WHOIS date) = **0 points, never a penalty**.
- Use `modules.status_for(findings, config)` for the status so all cards share one colour rule
  (red if any single finding >= `heavy_flag_points` (20), amber if any finding, else green).
- Network calls need a 5 s timeout (`config["dns"]["timeout_seconds"]`) and should run in parallel.
- **The tone check (M5) is special:** it returns `{"check": "tone", "status": ..., "score": 0-10, "findings": [...]}`.
  M6 reads `score` and computes `min(15, 1.5 * score)` itself (`scoring.tone_points`). Put the LLM's quoted
  tactics in `findings` for display only (their `points` are ignored).

### Parser output (`parse_eml(raw_bytes)` in `modules/parser.py`)

```python
{ "from": {"name","address"}, "reply_to": {...}, "return_path": {...}, "to": [addr, ...],
  "subject", "date", "message_id",
  "received_chain": [header strings, newest first],
  "sending_ip": "first PUBLIC hop, read bottom-up" (or ""),
  "dkim_signatures": [raw header values], "authentication_results": [raw header values],
  "body_text", "body_source": "plain|html-converted|empty",
  "links": [{"text", "href"}],            # '#' and 'javascript:' hrefs are dropped
  "attachments": [{"filename","content_type"}] }   # names only, never opened (SAF-2)
```
Raises `ParseError` (empty file, >5 MB, no From + one of Date/Subject/Message-ID).

### Scoring output (`score_email(checks, config=None)` in `modules/scoring.py`)

`{"score": int 0-100, "raw_total": float, "verdict": "safe|suspicious|phishing", "contributions": [rows largest
first], "by_check": {...}, "not_run": [...]}`. Rules: sum weights from config, halves round up, cap 100,
errored checks add 0 and go in `not_run`, each finding id counts once, ties sorted by (points desc, check order,
id) so output is deterministic (FR-6.4). Bands: 0-29 Safe, 30-59 Suspicious, 60-100 Phishing.

---

## 5. Configuration (`phishguard/config.yaml`)

| Section | Purpose |
| --- | --- |
| `app` | upload limit (5 MB), host, port |
| `dns.timeout_seconds` | 5 s per network lookup |
| `points` | weight for every finding id (sender: dmarc_fail 25, spf_fail 20, dkim_invalid 20, spf_softfail 10, domain_mismatch 10, spf_none/dkim_none/dmarc_none 5; links: lookalike_domain 25, domain_age_new 20, link_text_mismatch 15, brand_in_domain 15, raw_ip_link 15, domain_age_recent 10, domain_unresolved 10) |
| `tone` | `weight: 1.5`, `max_points: 15` (must stay below `suspicious_from`) |
| `thresholds` | `suspicious_from: 30`, `phishing_from: 60`, `heavy_flag_points: 20` |
| `links` | `max_domains: 10`, `age_new_days: 30`, `age_recent_days: 180` |

Still to add (not in the file yet): certificate points (PRD section 6: self-signed/untrusted 15, expired 15,
hostname mismatch 15, issued < 7 days 5), and an `llm:` section (see section 7).

---

## 6. How the existing checks work (what is implemented)

### M2 sender check (`modules/sender.py`)
- **SPF** (pyspf): tested against the **Return-Path (envelope) domain**, not From. Uses the sending IP from M1.
- **DKIM** (dkimpy): verifies every DKIM-Signature using the key in DNS. No signature = `dkim_none` (5);
  signature present but bad = `dkim_invalid` (20); never both.
- **DMARC**: looks up `_dmarc.<from-domain>`, then the organisational domain. Passes if SPF passes **and is
  aligned**, or DKIM passes **and is aligned** (relaxed by default; `aspf=s`/`adkim=s` = strict).
- **Fallback (FR-2.4):** if a live check cannot run (DNS down, key missing, or live DKIM fails while the mail
  server said pass), use the **topmost** `Authentication-Results` header only (lower ones can be planted), and
  label the result `reported by mail server`. Each result has `source`: `live` | `reported by mail server` |
  `could not run`.
- **Reply-To / Return-Path:** a different **Reply-To** is always flagged (`domain_mismatch`, 10). A different
  **Return-Path** is flagged **only if DMARC did not pass** (otherwise it is an authorised sending service,
  e.g. YouTube mail sent by Google). *This deliberately deviates from PRD FR-2.5* after a real YouTube email
  was wrongly flagged; to restore the literal rule, remove the "excused" logic in `_check_sender`.
- If both SPF and DMARC are `error`, status is `error` and findings are cleared (0 points).
- The three lookups run in parallel; SPF `querytime` is 5 s.

### M3 link and domain check (`modules/links.py`)
- Never opens, clicks or downloads a link (FR-3.7): only reads URLs and asks DNS/WHOIS.
- Links to a **trusted domain or any subdomain of one** (`data/trusted_domains.txt`) are skipped (no lookups).
- `lookalike_of`: edit distance (RapidFuzz Levenshtein) 1, or 2 if the string is >= 10 chars, against the
  trusted list. Name part must be >= 6 letters (avoids kodak/kotak style false positives). Also checks
  2+-label runs hidden in the subdomain (`srmlst.edu.in.verify-login.com`).
- `brand_in`: brand names from the trusted list as whole tokens (or substrings if >= 6 chars) inside an
  untrusted hostname. `GENERIC_BRANDS` excludes everyday words (live, office, zoom, uber, ...).
- `link_text_mismatch`: visible text shows a domain whose registered domain differs from the href's (skipped
  if both are trusted). `raw_ip_link`: host is an IP. `domain_unresolved`: DNS says it does not exist.
- Domain age via python-whois (`whois_created`): `< 30` days = `domain_age_new`, `30-180` = `domain_age_recent`.
  Hidden/slow WHOIS (gives up after timeout+1 s) = unknown = 0 points.
- Each finding id counts once per email. At most `max_domains` untrusted domains are looked up. WHOIS and
  DNS for a domain run side by side.

### M6 scoring: see "Scoring output" in section 4.

---

## 7. What is left to build (and the agreed design)

### Session 4 remainder: M5 tone + M7 report (LLM)
**Decision already made by the team:** use the **NVIDIA Nemotron API** as the main provider (API key read from
the environment variable **`LLM_API_KEY`**, never written in code or committed) and **Ollama with a small local
model** as the offline fallback, **switchable in `config.yaml`**. Everything goes through **one interface** in
`modules/llm_client.py` so providers can be swapped (NFR-6).
- **M5 `modules/tone.py`** (FR-5.1-5.3): send subject + body (trimmed to 4,000 chars, **email addresses masked
  first**, PRV-2) with a fixed prompt. LLM returns strict JSON: manipulation score 0-10 and a list of tactics
  (urgency, threat, credential request, reward bait, authority impersonation), each with a short quoted
  phrase. Invalid JSON or unreachable LLM -> `status: "error"`, check skipped, verdict still produced.
- **M7 `modules/report.py`** (FR-7.1-7.8): LLM input is only verdict + score + findings (not the raw email).
  Returns JSON with `summary`, `evidence_explained`, `recommended_actions`, 120-200 words total. The LLM must
  not contradict or change the verdict. If unavailable/invalid, **fill the three fields from a template built
  from the findings**. One HTML template (`templates/report.html`) is used for both the dashboard view and the
  PDF (WeasyPrint, A4, file name `phishguard_report_<YYYYMMDD>_<HHMM>.pdf`). The PDF never contains the full
  email body, and recipient addresses are masked. Footer: verdict is rule-based, explanation is AI-written.
- Add an `llm:` block to `config.yaml` (provider: nemotron|ollama, model names, base URLs, timeouts) and
  have `pipeline.py` add M5 to the parallel checks and M7 after M6.
- The **template-based report, HTML report and PDF do not need an LLM** and can be built first.

### Session 5: M8 dashboard
Verdict badge (green/amber/red) + score out of 100; one card per check (pass/warn/fail/error) with evidence;
the full report below; progress indicator while running; 3-4 built-in demo emails; "Download report (PDF)"
button. Demo emails: forged SRM exam cell (Phishing), genuine college/bank (Safe), real newsletter (Safe or
Suspicious), one public-corpus phishing email (Phishing).

### Session 6: M4 certificate check + offline mode
M4 (FR-4.1-4.4): TLS handshake only on port 443, 5 s timeout, never request the page. Record issuer, subject,
validity dates, chain trust. Flag self-signed/untrusted, expired, hostname mismatch, issued < 7 days; plain
HTTP = "no certificate". Offline mode (NFR-4): replay saved DNS, WHOIS, certificate and LLM results for the
sample emails from `data/cache/`. The injectable lookup functions (`sender.dns_txt`, `links.dns_lookup`,
`links.whois_created`) are the natural place to add a cache layer.

### Session 7: evaluation
`scripts/evaluate.py`: run the pipeline over 100 emails (50 phishing: 30 Nazario corpus + 20 recent; 50
legitimate), write a CSV (score, verdict, findings), print confusion matrix, detection rate (target >= 85%),
false-positive rate (target <= 10%), average time (target <= 15 s online). Compare with/without tone. Tune
weights in `config.yaml` **once**, then freeze. Never send spoofed emails; forged cases are local files only.

### Session 8: review prep
Final report, updated slides, viva Q&A.

---

## 8. Working rules for this repo

1. **Read `CLAUDE.md`.** It defines the **notes rule**: after every session write `notes/sessionN.md` for two
   complete beginners in networking/security (big picture, new terms with full forms, how it works with
   real-life analogies, walk-through example, files + "show me where" function, 8-10 viva questions, 3-5
   "remember this" points; no code dumps; explain tricky things twice). Existing notes: `session1.md` to
   `session4.md` (session 4 covers M6 only; **extend that file** when M5/M7 are built). Keep notes in sync with
   the code (when you move or rename something, update the notes that mention it).
2. **Build only the requested session**, follow the PRD folder structure (section 8) and requirements
   (section 5), then stop and tell the user how to run/test it and what they should see.
3. **Use the virtual environment** (`phishguard/venv`, git-ignored).
4. **Privacy and safety (PRD section 7):** never open links/attachments; process uploads in memory only;
   mask email addresses before sending anything to a cloud LLM; API keys only from environment variables.
5. Match the existing code style (short docstrings, comments explaining *why*, PRD requirement ids like
   `FR-2.4` in comments where helpful).

---

## 9. Gotchas and lessons learned (read before changing things)

- **`from` is a Jinja keyword.** In templates write `parsed['from']`, not `parsed.from`.
- **Documentation IP ranges are not "public".** `203.0.113.x`, `198.51.100.x`, `198.18.x` fail
  `ipaddress.is_global`, so `find_sending_ip` skips them. Use real-looking public IPs in samples/tests.
- **dkimpy passes the DNS name to your `dnsfunc` as `bytes` with a trailing dot.** Decode and `rstrip(".")`.
- **pyspf tests:** patch the module-level `spf.DNSLookup` (see `tests/conftest.py`), do not reimplement
  `query.dns()`. A fake TXT value is a tuple of bytes: `[((name, "TXT"), (b"v=spf1 ...",))]`.
- **Organisational domain:** never use "last two labels". Use `sender.org_domain()`, which knows `edu.in`,
  `ac.in`, `co.in`, `gov.in`, `co.uk`, etc. (needed for the Indian domains this project targets).
- **Tests must never touch the network.** `tests/conftest.py` has an **autouse** `zone` fixture (a `FakeZone`)
  that patches `sender.dns_txt`, `spf.DNSLookup`, `links.dns_lookup` and `links.whois_created`. Use
  `zone.add_txt(...)`, `zone.live(domain, age_days)`, `zone.created[d] = "notfound"`, `zone.broken = True`.
  Under the fake, an unknown domain does not resolve. Any new network function needs a seam like this.
- **Dashboard test client:** `tests/test_app.py` posts sample names to `/analyze`; all network is faked.
- **Trusted-list false positives matter.** The PRD targets <= 10% false alarms on genuine email. Short or
  dictionary-word names (kodak/kotak, olx/ola, live, office) caused false positives, so lookalike needs a name
  of >= 6 letters and everyday words are in `GENERIC_BRANDS`. Test any list change against genuine emails.
- **Real emails differ from hand-made ones.** Genuine mail often uses a third-party Return-Path (YouTube via
  Google), tracking redirects (`c.gle`) and has several `Authentication-Results`. Test with a real export
  (Gmail: open message, three dots, **Download message**).
- **Sample emails are synthetic.** Their live results depend on whatever the real domains publish today
  (`verify-login.com`, `shopmart.com`). Don't assert live numbers in tests; use the fake zone.
- **The trusted list and config are cached** (`lru_cache` / module dict). Restart after editing.
- **Never commit** `venv/`, `.env`, API keys or `chk/` (git-ignored). `chk/` holds a real personal email.

---

## 10. Testing

- `python -m pytest -q` from `phishguard/`. Test files: `test_parser.py`, `test_sender.py`, `test_links.py`
  (includes one hand-built `.eml` per finding in `tests/fixtures/m3_*.eml`, each must raise **exactly** its
  finding), `test_scoring.py`, `test_app.py`.
- PRD rule: one fixture per finding in the point table, hand-built, never sent. Add fixtures for any new check.
- When adding a finding: add its id + points to `config.yaml`, implement it, add a fixture + test, update the
  README (section 5) and the session notes.

---

## 11. Key references

- `PRD.md`: full requirements. Section 5 (functional requirements FR-x.y), 6 (points and thresholds),
  7 (NFR/SAF/PRV), 8 (architecture and module output format), 10 (testing), 11 (sessions), 12 (risks).
- `CLAUDE.md`: the rules every AI session must follow (notes rules, build rules, LLM provider plan).
- `notes/`: plain-English explanation of every module and viva questions.

**Glossary of finding ids:** `dmarc_fail, spf_fail, dkim_invalid, spf_softfail, domain_mismatch, spf_none,
dkim_none, dmarc_none` (sender); `lookalike_domain, domain_age_new, link_text_mismatch, brand_in_domain,
raw_ip_link, domain_age_recent, domain_unresolved` (links); `tone_manipulation` (synthetic row made by M6 from
the tone score); certificate ids to be added in session 6.
