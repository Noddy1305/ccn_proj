# Session 2 Notes — Sender Check (M2: SPF, DKIM, DMARC)

## 1. The big picture

This session added the **sender check (M2)**. It asks one question: "Did this email really come from the domain it claims to come from?" It answers using three public checks (SPF, DKIM, DMARC) plus a quick look at whether Reply-To or Return-Path point to a different organisation.

In the PhishGuard-AI flow, M2 runs right after the parser (M1) and uses the headers, sending IP and DKIM signature M1 extracted. Its findings (with points) will be added up by the scoring engine (M6) in session 4. Right now the dashboard shows a "Sender check" card with the evidence, but still no final verdict.

## 2. New terms

- **M1, M2, ... M8 (Module)**: the PRD numbers the project's building blocks. M1 = email parser, M2 = sender check, M3 = link and domain check, M4 = certificate check, M5 = tone analysis (AI), M6 = risk scoring engine, M7 = report generator, M8 = dashboard. The number also matches the file in `modules/` (for example `parser.py` is M1).
- **Domain**: the part of an address after the @ (srmist.edu.in). Like the name of a company.
- **DNS (Domain Name System)**: the internet's phonebook. It also stores small notes about a domain, called records.
- **TXT record**: a DNS note made of plain text. SPF, DKIM keys and DMARC policies are all published as TXT records.
- **SPF (Sender Policy Framework)**: a TXT record listing which servers (IP addresses) may send mail for a domain.
- **DKIM (DomainKeys Identified Mail)**: a digital signature added to the email by the sending server. It proves the email came from that domain and was not changed on the way.
- **DMARC (Domain-based Message Authentication, Reporting and Conformance)**: the domain's rule saying "if SPF and DKIM don't line up with the From address, do this".
- **Policy (p=)**: what DMARC tells receivers to do with failures: `none` (just report), `quarantine` (spam folder) or `reject` (refuse).
- **Alignment**: the domain that passed SPF or DKIM must match the domain shown in From. Without this, a scammer could pass SPF with their own domain.
- **Envelope sender / Return-Path**: the technical "return address" used by mail servers. SPF checks this one, not the From line.
- **Public key / private key**: a matched pair. The sender signs with the private key (kept secret). Anyone can check the signature using the public key (published in DNS).
- **Selector**: a label that says which public key to fetch for a DKIM signature, for example `sel._domainkey.srmist.edu.in`.
- **Organisational domain**: the "main" registered domain. `mail.srmist.edu.in` belongs to `srmist.edu.in`.
- **Authentication-Results**: a header the *receiving* mail server writes, saying whether SPF, DKIM and DMARC passed when it received the mail.
- **Pass / fail / softfail / none**: SPF outcomes. Pass = allowed. Fail = not allowed. Softfail = "probably not allowed, but don't be strict". None = the domain published no SPF.
- **Fallback**: a backup plan used when the main method can't run.
- **Bounce address**: the address where "delivery failed" messages go. It is the same as the Return-Path.
- **Sending service**: a company that sends email on behalf of another (Google sends YouTube's mail). Its bounce address is on its own domain, not the brand's.
- **Band**: a score range with a name (Safe, Suspicious, Phishing).
- **Provisional**: "for now". The rating is not final until every check has run.

## 3. How it works

### Feature A: SPF — "is this server on the guest list?"

**Analogy.** A company posts a list at the front desk: "Only these delivery vans may collect parcels in our name." When a van arrives, the guard checks its number plate against the list.

**What happens.** We take the sending IP found by the parser (the van's number plate) and the Return-Path domain (the company name on the paperwork). We fetch that domain's SPF record from DNS and test whether the IP is allowed. The result is pass, fail, softfail or none. If the domain has no SPF at all, we note "none".

**Why it matters.** A scammer's server is not on the real college's list, so SPF fails. One catch: SPF checks the **Return-Path** domain, not the From line. A scammer can use their own domain there and pass SPF, which is why DMARC (below) exists.

### Feature B: DKIM — "is the wax seal unbroken?"

**Analogy.** Old letters were closed with a wax seal pressed with the sender's private ring. Anyone who knows what the real seal looks like can check it. If someone opens the letter and changes it, the seal breaks.

**What happens.** The email carries a signature made with the domain's private key. We read which domain and selector signed it, fetch the public key from DNS, and check the signature against the message. Possible results: pass, fail (a signature exists but doesn't match), or none (the email has no signature).

**Why it matters.** A valid signature proves the domain's own server sent and approved this message. An invalid one is suspicious because it means either forgery or tampering.

### Feature C: DMARC — "does the name on the envelope match the name on the seal?"

**Analogy.** Imagine a parcel claims to be from "Bank X". The guard checks that the van was authorised (SPF) or the seal is genuine (DKIM), **and** that the company named on that proof is really Bank X, not some other firm. Passing with a different company's papers doesn't count.

**What happens.** We look up `_dmarc.<From domain>` in DNS (and the organisational domain if needed). DMARC **passes** if SPF passed and its domain is aligned with From, **or** DKIM passed and its domain is aligned with From. Otherwise it **fails**. We also record the policy (none, quarantine, reject). Alignment is "relaxed" by default, so `mail.srmist.edu.in` matches `srmist.edu.in`. Strict mode (`aspf=s` / `adkim=s`) needs an exact match.

**Why it matters.** This is the check that catches real forgeries. A scammer can pass SPF for `attacker.com`, but the From line says `srmist.edu.in`, so alignment fails and DMARC fails.

### Feature D: the fallback — "ask the guard who already checked"

**Analogy.** If the phone line to the registry is down, you can read the note the front-desk guard wrote when the parcel arrived: "van checked, OK".

**What happens.** If a live check cannot run (no internet, DNS timeout, key missing), or if DKIM fails live but the receiving server said `dkim=pass` (for example, forwarding changed the message and broke the signature), we use the receiving server's **Authentication-Results** header instead. Every result is labelled with its source: *live*, *reported by mail server*, or *could not run*. We read **only the topmost** Authentication-Results header, because lower ones could have been planted by the sender.

**Why it matters.** It stops real forwarded emails looking forged and keeps the tool working when Wi-Fi fails. If nothing can be verified, the check is shown as "could not run" with 0 points. It never crashes.

### Feature E: Reply-To / Return-Path mismatch

**Analogy.** A letter says "From: Bank X" but "please reply to: PO Box 99, Somebody Else". That is suspicious. But a parcel from a shop may legitimately say "returns go to the courier's depot". That is normal if the shop's own signature is on the parcel.

**What happens.** We compare the main domain of Reply-To and Return-Path with the From domain.
- A different **Reply-To** is **always** a red flag (+10). It sends your answer somewhere else.
- A different **Return-Path** is a red flag (+10) **only if DMARC did not pass**. If DMARC passed, the email is proven to be signed or authorised for the From domain, so the different Return-Path is just a sending service. We show it in the table as "ok" with 0 points and explain why.

We changed the PRD's literal rule (FR-2.5) on purpose, after testing a real YouTube email. YouTube's mail is sent by Google, so its Return-Path is `...scoutcamp.bounces.google.com`, which differs from `youtube.com`. Flagging that would punish a genuine email. (To go back to the literal rule, remove the "excused" lines in `_check_sender`.)

**Why it matters.** Scammers often keep a trusted From but collect replies elsewhere, while big companies often use sending services. This rule catches the first without punishing the second.

### Feature F: points come from config.yaml

Each finding gets its points from `config.yaml` (for example `dmarc_fail: 25`), never from the code. This lets us tune weights later without touching the code.

### Feature G: points table and provisional rating

**Analogy.** A school report card. Each mistake costs marks, the total is added up, and a legend says what the total means: 0-29 is green, 30-59 is amber, 60 and above is red.

**What happens.** The page now shows a **Points breakdown** table: one row per red flag with its points and evidence, then a **Total so far** out of 100 and a rating badge. Below it is a **How to read the score** table with the three bands and what each means:
- **Safe (0-29)**: looks genuine, normal caution still applies.
- **Suspicious (30-59)**: some warning signs, confirm the sender another way before clicking.
- **Phishing (60-100)**: strong evidence of forgery, do not click or reply.

The band limits (30 and 60) are read from `config.yaml`. The rating was **provisional** at this point because only the sender check existed; later checks add more points. This now lives in the real scoring engine (M6, `modules/scoring.py`, built in session 4).

**Card colour vs rating.** These are two different things. The coloured **card** judges *one check* (the sender check): red means a serious sender problem was found. The **rating** judges the *total points*. The forged sample shows a red sender card but only "Suspicious" overall, because 45 points is below 60. Links and tone will push it higher.

**Why it matters.** The user sees *why* an email got its rating, not just a label, and an examiner can check every point.

## 4. Walk-through example

We follow `forged_exam_cell.eml`. The real domain `srmist.edu.in` publishes SPF ending in `~all` and a DMARC record with `p=none` (checked on 29 Oct 2026). The email's Return-Path is `bounce@srmlst-verify.com`, and the sending IP is `185.234.72.19`.

1. **SPF.** We look up the SPF record of `srmlst-verify.com` (the Return-Path domain). The domain publishes none, so result = **none**. Finding: *No SPF record*, +5.
2. **DKIM.** The email has no DKIM-Signature, so result = **none**. Finding: *No DKIM signature*, +5. (Never both "none" and "invalid".)
3. **DMARC.** We fetch `_dmarc.srmist.edu.in`, which says `p=none`. SPF did not pass and DKIM did not pass, so nothing lines up with the From domain. Result = **fail**. Finding: *DMARC failed*, +25. The policy `none` only tells receivers not to block; we still count the failure as a red flag.
4. **Mismatch.** Reply-To and Return-Path are on `srmlst-verify.com` but From says `srmist.edu.in`. Finding: *Reply-To / Return-Path differs from From*, +10.
5. **Header ignored.** The email contains an Authentication-Results header, but all live checks worked, so it is not used.
6. **Output.** The sender card is red (**fail**). Points = 5 + 5 + 25 + 10 = **45**, so the provisional rating is **Suspicious** (30-59), not Phishing. The links (a lookalike domain and a raw IP) and the urgent tone will add more points in sessions 3 and 4, which should lift it to Phishing.

A real email, tested live: a YouTube Premium reminder (From `youtube.com`). SPF **passes** for `scoutcamp.bounces.google.com`, but that is Google's domain, so it is **not aligned** with `youtube.com`. DKIM **passes** and **is aligned** (signed by `youtube.com`), so DMARC passes (policy `reject`). The Return-Path is on Google's domain, but because DMARC passed it costs **0 points**. Total **0**, rating **Safe**, green. This shows why DMARC needs only one aligned pass (SPF or DKIM).

For contrast, `genuine_college.eml` is sent from a Google server (209.85.220.41), which `srmist.edu.in` authorises through its SPF `include:_spf.google.com`. SPF passes and aligns, so DMARC passes. Only the missing DKIM adds +5 (total 5, still Safe), because this hand-made sample has no signature. A real exported college email will normally include one.

## 5. Files

- `phishguard/modules/sender.py`: the whole M2 check. Point at `check_sender()` for "show me where the sender check starts". `check_spf()`, `check_dkim()` and `check_dmarc()` are the three tests. `parse_auth_results()` is the fallback. `org_domain()` finds the main domain.
- `phishguard/pipeline.py`: runs the parser, then the checks, then hands the findings to the scoring engine. Point at `run_pipeline()`. The points total, the verdict and the legend text (`BANDS`) now live in `phishguard/modules/scoring.py` (`score_email()`, `verdict_for()`), added in session 4.
- `phishguard/config.yaml`: now also holds the DNS timeout (5 s), the points table and the band limits (30 and 60).
- `phishguard/modules/__init__.py`: `load_config()`, which reads config.yaml.
- `phishguard/app.py` and `templates/dashboard.html`: call the pipeline and show the points table, the legend and a coloured "Sender check" card. The dropdown has a "choose a sample" placeholder and remembers your pick.
- `phishguard/modules/parser.py` (small change): links that only go to `#` or `javascript:` are no longer listed, because they are not real destinations.
- `phishguard/tests/test_sender.py`: 21 tests for SPF, DKIM, DMARC, fallback, errors and the YouTube-style case. (42 tests in total across the project.)
- `phishguard/tests/conftest.py`: a pretend DNS so tests never need the internet.
- `phishguard/requirements.txt`: added dnspython, pyspf, dkimpy and cryptography.

## 6. Viva questions

1. **What does the sender check prove?**
   It checks whether the email really came from the domain it claims, using SPF, DKIM and DMARC. The From line is only text, so these DNS-based checks give actual evidence.

2. **What is SPF and which address does it check?**
   SPF is a DNS record listing the servers allowed to send mail for a domain. We test the sending IP against the SPF record of the Return-Path (envelope) domain, not the From address.

3. **What is DKIM and why does it need DNS?**
   DKIM is a digital signature added by the sending server. The matching public key is published in DNS, so anyone can verify that the message came from that domain and was not changed.

4. **What does DMARC add on top of SPF and DKIM?**
   DMARC requires alignment: the domain that passed SPF or DKIM must match the From domain. It also publishes a policy (none, quarantine, reject). Without it, a scammer could pass SPF using their own domain.

5. **Can a scammer pass SPF and still be caught?**
   Yes. They can pass SPF for their own domain, but the From line shows the victim's domain. Alignment then fails, so DMARC fails and we flag it.

6. **What is alignment, and what are relaxed and strict modes?**
   Alignment means the SPF or DKIM domain matches the From domain. Relaxed lets a subdomain match its main domain (mail.srmist.edu.in matches srmist.edu.in). Strict needs an exact match.

7. **Why do we need a fallback to Authentication-Results?**
   Forwarding can break a DKIM signature, and Wi-Fi can fail during a demo. In those cases we use the receiving server's own verdict and label it "reported by mail server".

8. **Why do you read only the topmost Authentication-Results header?**
   The receiving server adds its header on top. Headers lower down could have been written by the sender to fake a pass, so we ignore them.

9. **The forged email has a red sender card but only a "Suspicious" rating. Why?**
    The card judges only the sender check; the rating judges the total points. The sender check alone gave 45, which is in the Suspicious band (30-59). Links and tone will add more points later.

10. **Why isn't YouTube's different Return-Path (a Google domain) a red flag?**
    Because DMARC passed: the email was signed by youtube.com itself, so Google is just an authorised sending service. We only penalise a different Return-Path when DMARC does not pass. A different Reply-To is always penalised.

## 7. Remember this

- SPF = **which servers** may send. DKIM = **signature** proving it is unchanged. DMARC = **do they line up with From**, plus a policy.
- SPF checks the **Return-Path** domain; DMARC is what ties it back to the **From** domain.
- A **missing** DKIM signature is "none" (+5); a **bad** signature is "invalid" (+20); never both.
- Every result says its **source**: live, reported by mail server, or could not run.
- Points and band limits live in **config.yaml**; failures give 0 points and never crash the tool.
- **Card colour** = one check; **rating** = total points (0-29 Safe, 30-59 Suspicious, 60-100 Phishing).
- A different **Return-Path** is excused when DMARC passes (sending service); a different **Reply-To** never is.
