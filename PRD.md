# PhishGuard-AI — Product Requirements Document

Kaustubh Guha, Rudraksh Dubey · last updated Oct 29, 2026 (v1.1: reflects sessions 1-4 as built; see section 15)

## 1. Overview

PhishGuard-AI is a laptop-based web tool that takes one suspicious email and returns a verdict — Safe, Suspicious or Phishing — with the evidence behind it and a plain-English report.

**The problem.** A phishing email can look identical to a real one: same logo, same signature, same tone. The "From" line is just typed text and proves nothing. But a forged email leaves technical traces a program can check even when a person cannot: a sender server that is not authorised, a link that points to a lookalike domain registered last week, a website certificate that does not match, and pressure-heavy wording.

**The approach.** The tool runs four independent checks on the email, combines their results with fixed rules into a risk score, and then asks a Large Language Model (LLM) to explain the result in simple words. The code decides; the AI explains.

**Project context**

| Item | Detail |
| --- | --- |
| Course | 21ECC402P – Computer Communication and Network Security |
| Team | Kaustubh Guha (RA2311004010296), Rudraksh Dubey (RA2311004010282) |
| Full title | PhishGuard-AI: An LLM-Augmented Multi-Layer Framework for Phishing Email Detection and Automated Threat Reporting |
| Platform | Runs locally on a laptop (Ubuntu); no extra hardware |
| Status | Sessions 1-3 done (M1, M2, M3); session 4 partly done (M6 scoring built; M5 tone and M7 report not yet). See section 11 and section 15. |

## 2. Goals, non-goals and success criteria

**Goals**

1. Detect forged senders using SPF, DKIM and DMARC.
2. Flag dangerous links: lookalike domains, newly registered domains and mismatched link text.
3. Inspect the TLS certificate of each linked website.
4. Score the message wording for manipulation tactics using an LLM, as one capped signal.
5. Combine all signals with fixed, explainable rules into one verdict.
6. Show every check's evidence and an LLM-written report on a simple dashboard, and as a downloadable PDF report.

**Non-goals**

- Live inbox integration (Gmail/Outlook plug-ins) — the tool works on uploaded email files.
- Scanning attachments for malware.
- Training a custom machine learning model.
- User accounts, logins or multi-user support.
- Letting the LLM make the final phishing decision.

**Success criteria** (to be measured on the test set in section 10)

| Criterion | Target |
| --- | --- |
| Phishing emails flagged as Suspicious or Phishing | ≥ 85% |
| Legitimate emails wrongly marked Phishing | ≤ 10% |
| Every verdict shows the evidence that produced it | 100% |
| Time to analyse one email (online) | ≤ 15 seconds |
| Demo runs end to end with no internet (cached mode) | Yes |

Targets are a starting point for a student prototype and can be revised after the first test run.

## 3. Users and use cases

The primary user is a non-technical person who received an email they are unsure about; the secondary user is an examiner or student who wants to see how the detection works.

| User | Wants to | So that |
| --- | --- | --- |
| Email recipient | Upload a suspicious email and get a clear verdict | They know whether to click, reply or delete |
| Email recipient | Read a short plain-English explanation | They understand why without knowing SPF or DNS |
| Examiner / student | See each check's raw evidence (records, dates, certificate fields) | They can verify the verdict is not a guess |
| Presenter (us) | Run the demo with no internet | A Wi-Fi failure cannot break the review |

**Core flow:** open dashboard → upload a .eml file → wait a few seconds → see verdict, score, four check cards with evidence, and the written report.

## 4. Scope and priorities

P0 is the minimum demonstrable project; P1 is added once P0 works end to end; P2 only if time remains.

| ID | Module | Priority | Why this priority |
| --- | --- | --- | --- |
| M1 | Email parser | P0 | Every other module depends on it |
| M2 | Sender check (SPF, DKIM, DMARC) | P0 | Core of the email-security story |
| M3 | Link and domain check | P0 | Catches the most common phishing trick |
| M5 | Tone analysis (LLM) | P0 | The project's AI component |
| M6 | Risk scoring engine | P0 | Produces the verdict |
| M7 | Report generator (LLM text + PDF export) | P0 | The plain-English output, on screen and as a PDF |
| M8 | Dashboard (results + PDF download) | P0 | The demo surface |
| M4 | Certificate check (TLS) | P1 | Strong addition, but the tool is complete without it |
| — | Offline demo mode (cached results) | P1 | Protects the live demo |
| — | Batch mode: analyse a folder of emails, export results to CSV | P2 | Needed only for larger evaluation |

## 5. Functional requirements

Each check module returns findings in the same format (section 8) so the scoring engine treats them alike.

### M1 — Email parser

Splits the raw email file into the labelled pieces the checks need. It makes no judgement.

- FR-1.1 Accept a .eml file up to 5 MB.
- FR-1.2 Extract: From (display name + address), Reply-To, Return-Path, To, Subject, Date, Message-ID.
- FR-1.3 Extract the Received chain and the sending server's IP address from the first external hop.
- FR-1.4 Extract the DKIM-Signature header and any Authentication-Results header added by the receiving mail server.
- FR-1.5 Extract the plain-text body; if only HTML exists, convert it to text.
- FR-1.6 Extract every link as a pair: visible link text and actual destination (href).
- FR-1.7 Reject files that are not valid emails with a clear error message.

### M2 — Sender check (SPF, DKIM, DMARC)

Proves whether the email really came from the domain it claims.

- FR-2.1 SPF: look up the sender domain's SPF record via DNS and test the sending IP against it. Result: pass / fail / softfail / none.
- FR-2.2 DKIM: verify the DKIM signature using the public key published in DNS. Result: pass / fail / none.
- FR-2.3 DMARC: look up the domain's DMARC policy (none / quarantine / reject) and check alignment between the From domain and the SPF/DKIM domains.
- FR-2.4 If a live check cannot run (for example, the signature was broken by forwarding), fall back to the receiving server's Authentication-Results header and label the result "reported by mail server".
- FR-2.5 Flag when the Reply-To or Return-Path domain differs from the From domain. *As built:* a different Reply-To is always flagged; a different Return-Path is flagged only when DMARC did not pass, because genuine mail often uses a sending service's bounce address (e.g. YouTube mail sent by Google). Domains are compared at organisational level (`mail.srmist.edu.in` = `srmist.edu.in`).

### M3 — Link and domain check

Finds where each link really goes and whether that destination is trustworthy.

- FR-3.1 For each unique link domain, compare against a trusted-domain list (top sites + Indian banks, government and university domains) and flag lookalikes within edit distance 1–2 (for example srmlst.edu.in vs srmist.edu.in). *As built:* distance 2 counts only for domains of 10+ characters, and the name part must be at least 6 letters, to avoid false alarms (kodak/kotak). Lookalikes hidden inside a subdomain (srmlst.edu.in.verify-login.com) are also checked.
- FR-3.2 Detect brand names inside unrelated domains (combosquatting, e.g. srmist-verify.com). *As built:* brands are taken from the trusted list; everyday-word names (live, office, zoom, uber, …) are excluded.
- FR-3.3 Look up domain age via WHOIS; flag domains younger than 30 days (high) and 180 days (medium).
- FR-3.4 Flag links whose visible text shows one domain but whose href points to another. *As built:* not flagged when both domains are on the trusted list.
- FR-3.5 Flag links that use a raw IP address instead of a domain name.
- FR-3.6 Resolve DNS (A and MX records) and flag domains that do not resolve.
- FR-3.7 Never open, click or download the link's page content.

### M4 — Certificate check (TLS) — P1

Inspects the security certificate of each linked HTTPS website.

- FR-4.1 Perform only a TLS handshake on port 443 (timeout 5 s); do not request the web page.
- FR-4.2 Record issuer, subject, validity dates, and whether the chain is trusted.
- FR-4.3 Flag: self-signed or untrusted chain, expired certificate, hostname mismatch, certificate issued in the last 7 days.
- FR-4.4 Links using plain HTTP are recorded as "no certificate".

### M5 — Tone analysis (LLM)

Reads the message wording for manipulation, which the technical checks cannot see.

- FR-5.1 Send the subject and plain-text body (trimmed to 4,000 characters) to the LLM with a fixed prompt.
- FR-5.2 The LLM returns structured JSON: a manipulation score 0–10 and a list of tactics found (urgency, threat, credential request, reward bait, authority impersonation), each with a short quoted phrase.
- FR-5.3 If the response is not valid JSON or the LLM is unreachable, mark the check as "error" and continue; the verdict is still produced from the other checks.

### M6 — Risk scoring engine

Turns all findings into one score and verdict using fixed rules (section 6). No AI.

- FR-6.1 Add up points from every finding, cap at 100.
- FR-6.2 Map the score to Safe / Suspicious / Phishing.
- FR-6.3 Output the list of findings that contributed points, largest first.
- FR-6.4 Same input always gives the same score.

### M7 — Report generator (LLM)

Explains the already-decided verdict in plain English and produces the downloadable PDF report. The LLM writes only the text; the code builds the page and the PDF.

- FR-7.1 Input to the LLM: verdict, score and the findings list — not the raw email.
- FR-7.2 The LLM returns JSON with three text fields, 120–200 words in total: `summary` (what this email is), `evidence_explained` (what gave it away), `recommended_actions` (what the reader should do).
- FR-7.3 The LLM text must not contradict or change the verdict; the dashboard and the PDF always show the verdict and score from M6.
- FR-7.4 If the LLM is unavailable or returns invalid JSON, fill the three fields from a template built from the findings list.
- FR-7.5 The report is one HTML template used for both the dashboard view and the PDF, so the two always match.
- FR-7.6 The report contains: title and date/time of analysis; verdict badge and score out of 100; email details (From, Subject, Date, sending server IP); a table of every check with its status and evidence; red flags sorted by points; the LLM's three text sections; a footer stating the verdict is rule-based and the explanation is AI-written.
- FR-7.7 The PDF is generated from that HTML with WeasyPrint, A4 size, named `phishguard_report_<YYYYMMDD>_<HHMM>.pdf`.
- FR-7.8 The PDF never includes the full email body; recipient addresses are masked.

### M8 — Dashboard

The single page the user interacts with.

- FR-8.1 Upload a .eml file (drag-and-drop or file picker).
- FR-8.2 Show the verdict as a coloured badge (green / amber / red) and the score out of 100.
- FR-8.3 Show one card per check: pass / warning / fail / error, with its evidence (records, dates, certificate fields).
- FR-8.4 Show the full report (same content as the PDF) below the cards.
- FR-8.5 Show a short progress indicator while checks run.
- FR-8.6 Include 3–4 built-in sample emails for the demo.
- FR-8.7 A "Download report (PDF)" button that downloads the PDF for the email just analysed.

## 6. Risk scoring logic

The verdict comes from adding fixed points for each red flag; the LLM's tone score can add at most 15 points, which is below the 30-point Suspicious line, so the AI can never flag an email on its own.

**Verdict thresholds**

| Score (0–100) | Verdict |
| --- | --- |
| 0–29 | Safe |
| 30–59 | Suspicious |
| 60–100 | Phishing |

**Point table** (starting weights, to be tuned on the test set)

| Check | Finding | Points |
| --- | --- | --- |
| Sender | DMARC fail | 25 |
| Sender | SPF fail | 20 |
| Sender | DKIM signature present but invalid | 20 |
| Sender | SPF softfail | 10 |
| Sender | Reply-To / Return-Path domain differs from From | 10 |
| Sender | No SPF, DKIM or DMARC at all | 5 each (each missing mechanism adds 5) |
| Link | Lookalike of a trusted domain (edit distance 1–2) | 25 |
| Link | Domain registered less than 30 days ago | 20 |
| Link | Link text shows a different domain than the href | 15 |
| Link | Brand name inside an unrelated domain | 15 |
| Link | Raw IP address in link | 15 |
| Link | Domain registered 30–180 days ago | 10 |
| Link | Domain does not resolve in DNS | 10 |
| Certificate | Self-signed or untrusted chain | 15 |
| Certificate | Expired | 15 |
| Certificate | Hostname mismatch | 15 |
| Certificate | Issued in the last 7 days | 5 |
| Tone (LLM) | Manipulation score s (0–10) | 1.5 × s, max 15 |

**Rules**

- Each link finding counts once per email, even if several links share it, so a long email with many links is not over-penalised.
- A check that errors (no internet, timeout) adds 0 points and is shown as "could not run" on the dashboard.
- The engine works the same whether or not M4 is built; without it, the maximum reachable score is simply lower.
- Halves round up (29.5 becomes 30), then the total is capped at 100. The page shows the uncapped sum when it exceeds 100.

## 7. Non-functional, safety and privacy requirements

| ID | Requirement |
| --- | --- |
| NFR-1 | Runs on one laptop (Ubuntu, Python 3.10+) with a single start command. |
| NFR-2 | One email analysed in ≤ 15 s online; network lookups run in parallel with 5 s timeouts each. |
| NFR-3 | A failure in any one check never crashes the tool; the rest still run. |
| NFR-4 | Offline demo mode replays saved DNS, WHOIS, certificate and LLM results for the sample emails. |
| NFR-5 | All weights and thresholds live in one config file, so tuning needs no code changes. |
| NFR-6 | The LLM provider sits behind one interface, so it can be swapped (cloud API or local model) by changing config. |
| SAF-1 | The tool never opens a link's web page, runs its scripts or downloads files; the certificate check stops after the TLS handshake. |
| SAF-2 | Attachments are listed by name and type only, never opened. |
| PRV-1 | Uploaded emails are processed in memory and not stored unless the user saves them as a sample. |
| PRV-2 | When a cloud LLM is used, only the subject and trimmed body (M5) or the findings list (M7) are sent; email addresses are masked first. |
| PRV-3 | API keys are read from an environment variable, never written in code or committed to GitHub. |

## 8. System architecture

The email flows one way: parsed once, checked four ways in parallel, scored by rules, then explained.

```text
Email file (.eml)
      |
M1 Email parser  (headers, links, body)
      |
      +--> M2 Sender check     (SPF, DKIM, DMARC, Reply-To)      [rule-based]
      +--> M3 Link & domain    (lookalike, WHOIS age, DNS)       [rule-based]
      +--> M4 Certificate      (TLS chain, expiry, hostname; P1) [rule-based]
      +--> M5 Tone analysis    (manipulation 0-10, max 15 pts)   [LLM]
      |
M6 Risk scoring engine  (fixed points from config -> Safe / Suspicious / Phishing)   [rule-based, decides the verdict]
      |
      +--> M7 Report generator (LLM writes text; code builds HTML report + PDF)
      +--> M8 Dashboard        (verdict, score, check cards, report, PDF download)
```

Only M6 decides the verdict. M5 contributes a capped signal and M7 only describes M6's result, so a wrong LLM answer can never turn a safe email into a phishing verdict.

**Module output format.** Every check (M2–M5) returns a list of findings in this shape, which is what the scoring engine and dashboard read:

```json
{
  "check": "sender",
  "status": "fail",
  "findings": [
    {
      "id": "dmarc_fail",
      "title": "DMARC failed",
      "points": 25,
      "evidence": "From domain srmist.edu.in, policy p=reject; mail sent from 185.x.x.x, not in SPF record"
    }
  ]
}
```

`status` is one of pass / warn / fail / error. Points come from the config file, not from the check itself, so weights can be tuned in one place.

**Folder structure**

```text
phishguard/
  app.py              Flask app and routes (M8)
  config.yaml         points, thresholds, LLM settings
  pipeline.py         runs M1, then M2–M5 in parallel, then M6, M7
  modules/
    parser.py         M1
    sender.py         M2
    links.py          M3
    certificate.py    M4
    tone.py           M5
    scoring.py        M6
    report.py         M7
    llm_client.py     one interface for any LLM provider
  data/
    trusted_domains.txt
    samples/          demo .eml files
    cache/            saved lookups for offline mode
  templates/          dashboard.html, report.html (also used for the PDF)
  tests/fixtures/     hand-built .eml test files
  scripts/evaluate.py batch evaluation over the test set
```

## 9. Tech stack

Everything is Python and free; the LLM choice is still open.

| Layer | Tool | Used by |
| --- | --- | --- |
| Language | Python 3.10+ | All |
| Editor | Visual Studio Code | All |
| Email parsing | Python `email` library (built in), BeautifulSoup for HTML-to-text | M1 |
| SPF and DMARC lookups | dnspython, pyspf | M2 |
| DKIM verification | dkimpy | M2 |
| Domain age | python-whois | M3 |
| Lookalike matching | RapidFuzz (edit distance) | M3 |
| Certificate inspection | Python `ssl` and `cryptography` libraries | M4 |
| LLM | NVIDIA Nemotron API (key in env var `LLM_API_KEY`), Ollama small local model as offline fallback; switchable in `config.yaml` | M5, M7 |
| Report template and PDF | Jinja2 (built into Flask), WeasyPrint | M7, M8 |
| Web dashboard | Flask, HTML/CSS | M8 |
| Version control | Git and GitHub | All |

The tech stack slide in the 0th review lists a subset of this; the rest is added as each module is built.

## 10. Testing and evaluation plan

We evaluate on 100 emails — 50 phishing, 50 legitimate — and report detection rate, false-positive rate and average time per email.

**Test data**

| Set | Source | Size | Note |
| --- | --- | --- | --- |
| Phishing (public) | Nazario phishing email corpus | 30 | Older emails; many link domains may no longer resolve |
| Phishing (recent) | Phishing/spam emails from our own inboxes, exported as .eml | 20 | Most realistic; headers intact |
| Legitimate | Our own inbox emails (college, banks, shopping, newsletters) exported as .eml | 50 | Gmail "Download message" gives a .eml with authentication headers |
| Unit-test fixtures | Hand-built .eml files with chosen headers and links, never sent | \~15 | One per finding in the point table |

We never send spoofed emails to test the system; forged cases are built as local files only.

**How we test**

1. Unit tests: each module run on its fixtures, checking it raises exactly the expected findings.
2. Batch evaluation: a script runs the full pipeline over the 100 emails and writes a CSV of score, verdict and findings.
3. Report: confusion matrix (actual vs predicted), detection rate, false-positive rate, average time; compare with and without the tone signal to show what the LLM adds.
4. Tune the weights in config once, then freeze them before the final review.

**Demo emails** (built into the dashboard)

- A forged "SRM exam cell" email: fails DMARC, links to a lookalike domain registered recently, urgent tone → Phishing.
- A genuine college or bank email → Safe.
- A real newsletter with a marketing link and mild urgency → Safe or Suspicious, to show the tone signal cannot convict alone.
- One phishing email from the public corpus → Phishing.

## 11. Milestones and build sessions

The build runs in eight sessions; after session 5 the project is complete at P0 and demonstrable, so later sessions only add strength. Dates depend on the review schedule (open question 1).

1. **Setup and parser (M1).** Project folder, virtual environment, Flask page that uploads an email and lists its parsed fields. *Done when:* a sample .eml shows sender, IP, links and body.
2. **Sender check (M2).** SPF, DKIM, DMARC with fallback to Authentication-Results. *Done when:* a forged fixture fails and a real college email passes.
3. **Link and domain check (M3).** Lookalike, combosquatting, WHOIS age, link-text mismatch, DNS. *Done when:* every M3 fixture raises its finding.
4. **LLM layer (M5, M7) and scoring (M6).** Pick the LLM, tone prompt, scoring from config, report prompt with template fallback. *Done when:* an email gets a score, a verdict and a report.
5. **Dashboard (M8) — P0 complete.** Verdict badge, check cards, on-screen report, PDF download, built-in sample emails. *Done when:* all four demo emails run end to end and each downloads a PDF report.
6. **Certificate check (M4) and offline mode — P1.** *Done when:* demo runs with Wi-Fi off.
7. **Evaluation.** Collect the 100 emails, run the batch script, tune weights once, freeze. *Done when:* results table and confusion matrix exist.
8. **Review prep.** Final report, updated slides, likely viva questions with answers.

## 12. Risks and mitigations

| Risk | Effect | Mitigation |
| --- | --- | --- |
| College Wi-Fi fails during the demo | DNS, WHOIS, TLS and cloud LLM checks fail | Offline demo mode (NFR-4); local LLM as backup |
| WHOIS lookups blocked or rate-limited, or the registry hides dates (common for .in) | Domain age unknown | Treat as "unknown", 0 points; cache results |
| DKIM fails on forwarded or edited emails | Real email looks forged | Fall back to the receiving server's Authentication-Results (FR-2.4) |
| Old corpus emails point to dead domains | Link checks give misleading results | Use recent inbox emails for the main evaluation; report the two sets separately |
| LLM returns malformed output or invents tactics | Wrong tone score or report | Strict JSON format, validation, 15-point cap, template fallback |
| Too many false alarms on newsletters | Users stop trusting the verdict | Tune weights on the test set; tone alone cannot reach Suspicious |
| Team cannot explain the code in the viva | Low marks despite a working tool | Each session ends with a short plain-English note per module; viva Q&A in session 8 |
| Deadline pressure | Unfinished project | P0 complete by session 5; M4 and offline mode are optional extras |

## 13. Open questions

- [ ] What are the dates of the 1st, 2nd and final reviews, and what must be shown at each?
- [x] Which LLM: decided: cloud API (NVIDIA Nemotron) with a local backup (Ollama).
- [ ] Does the department have rules on AI-assisted code that we must state in the report?
- [ ] How are tasks split between Kaustubh and Rudraksh?
- [ ] Is a written project report required, and in what format?
- [ ] Will the certificate check (M4) be committed for the final review, or kept optional?

## 14. Glossary

| Term | Full form | In one line |
| --- | --- | --- |
| SPF | Sender Policy Framework | DNS list of servers allowed to send mail for a domain |
| DKIM | DomainKeys Identified Mail | Cryptographic signature proving the email came from the domain and was not altered |
| DMARC | Domain-based Message Authentication, Reporting and Conformance | Domain's policy for emails that fail SPF/DKIM: none, quarantine or reject |
| DNS | Domain Name System | The internet's phonebook: turns names into server addresses and stores records like SPF |
| WHOIS | — (not an acronym) | Public registry showing when a domain was registered |
| TLS | Transport Layer Security | The encryption behind HTTPS; the site proves its identity with a certificate |
| HTTPS | HyperText Transfer Protocol Secure | Web traffic protected by TLS |
| CA | Certificate Authority | Trusted organisation that issues website certificates |
| LLM | Large Language Model | AI model that reads and writes text |
| IP | Internet Protocol (address) | Numeric address of a machine on the internet |
| MX | Mail Exchanger (record) | DNS record naming a domain's mail servers |
| URL | Uniform Resource Locator | A web address |
| .eml | — | Standard file format for one saved email |
| JSON | JavaScript Object Notation | Simple structured text format modules use to pass results |
| PRD | Product Requirements Document | This document |
| Edit distance | — | Number of single-letter changes between two words (srmlst vs srmist = 1) |
| Typosquatting / combosquatting | — | Registering a misspelt domain, or a brand plus extra words, to fool users |

## 15. Changes since v1 (as built, sessions 1-4)

Status: M1, M2, M3 and M6 are built; M5, M7, M8 (full dashboard), M4 and offline mode are not. Decisions and deviations made during the build:

| Area | v1 said | As built / decided | Why |
| --- | --- | --- | --- |
| Return-Path (FR-2.5) | Flag any difference | Excused when DMARC passes; Reply-To always flagged | A real YouTube email (Return-Path on a Google domain) was wrongly penalised |
| Lookalike (FR-3.1) | Edit distance 1-2 | Distance 2 only for domains of 10+ characters; name part at least 6 letters; subdomain-hidden lookalikes also checked | Avoid false alarms on short real domains |
| Brands (FR-3.2) | Any brand in an unrelated domain | Everyday-word brands excluded | Avoid false alarms (live, office, zoom, uber) |
| Text mismatch (FR-3.4) | Any difference | Skipped when both domains are trusted | Big companies use several of their own domains |
| LLM provider | Undecided | Nemotron (`LLM_API_KEY`) + Ollama fallback, switchable in config | Team decision |
| Missing SPF/DKIM/DMARC | "5 each" | 5 points per missing mechanism; if SPF and DMARC both cannot run, the check is "error" with 0 points | Missing data is never guilt |
| Check card colour | Not specified | Red if any single flag is 20+ points, amber if any flag, green if none (`heavy_flag_points`) | One rule for all cards |
| Rounding and cap | Cap at 100 | Halves round up; uncapped sum shown when capped | Predictable at the 30/60 lines; table always adds up |
| Scoring weights | Fixed in check output | M6 re-reads weights from `config.yaml` by finding id | Session 7 can re-tune and re-score with no code changes |
| Extra files | Section 8 structure | Added `README.md`, `AGENTS.md`, `notes/`, `modules/__init__.py`; not yet created: `certificate.py`, `tone.py`, `report.py`, `llm_client.py`, `report.html`, `evaluate.py` | Documentation and shared config helpers |
| Performance | 5 s per lookup, parallel | M2 and M3 run side by side; WHOIS gives up after 6 s; at most 10 untrusted domains looked up | Keep one email under 15 s |
