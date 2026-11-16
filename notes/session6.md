# Session 6: Certificate Check (M4) and Offline Demo Mode

## 1. The big picture

This session added two things. The **certificate check (M4)** looks at the security certificate of each `https://` website the email links to, and raises a flag if it is fake-looking, expired, brand new, or made out for a different website. **Offline demo mode** lets the whole demo run with the Wi-Fi switched off, by replaying internet answers that were saved earlier.

In the PhishGuard-AI flow, M4 is a fourth check that runs at the same time as the sender, link and tone checks, and its red flags go into the scoring engine (M6) like the others. Offline mode is not a check. It sits underneath every check, at the exact point where they would reach the internet.

## 2. New terms

- **HTTPS (HyperText Transfer Protocol Secure)**: the secure version of web browsing, shown as `https://` and a padlock.
- **TLS (Transport Layer Security)**: the encryption behind HTTPS. Before any page is sent, the website proves who it is.
- **TLS handshake**: the short opening conversation where the browser says "hello" and the website shows its certificate. We do this step only and then hang up.
- **Port 443**: the standard "door number" on a server for HTTPS.
- **Certificate**: a digital ID card for a website: which names it covers, who issued it, and from when until when it is valid.
- **CA (Certificate Authority)**: a trusted organisation that issues certificates, like a passport office (for example DigiCert, Let's Encrypt).
- **Chain of trust**: the website's certificate is signed by a CA that your computer already trusts. If that chain is broken, the certificate is "untrusted".
- **Self-signed certificate**: an ID card the website made for itself, with nobody vouching for it.
- **Expired**: past its "valid until" date.
- **Hostname mismatch**: the certificate is made out for a different website name than the one you visited.
- **SAN (Subject Alternative Name)**: the list of website names a certificate covers.
- **Wildcard**: a name like `*.example.com` that covers any one name in front, such as `shop.example.com`.
- **Offline mode / replay**: running the tool using saved answers instead of asking the internet.
- **Cache**: a store of saved answers. Ours is the file `data/cache/lookups.json`.
- **Record**: running once with internet and saving every answer the internet gave.
- **Hash (fingerprint)**: a short code calculated from a text. The same text always gives the same code, but the code does not reveal the text.
- **Environment variable**: a setting given to a program when you start it, like `PHISHGUARD_MODE=replay`.

## 3. How it works

### Feature A: the certificate check (M4)

**Analogy.** A bouncer at a club checks your ID card at the door. He does not let you in or follow you around. He only looks at the card: is it real, is it yours, is it out of date, was it printed yesterday?

**What happens.** For every `https://` link in the email, the program opens a connection on port 443 and does only the TLS handshake. The website shows its certificate, the program reads it and hangs up. **No web page is ever requested** (requirement SAF-1). It then checks four things:

1. **Untrusted or self-signed** (15 points): nobody trusted vouches for this ID card.
2. **Expired** (15 points): the "valid until" date has passed.
3. **Hostname mismatch** (15 points): the card is made out for a different name.
4. **Brand new** (5 points): issued in the last 7 days. Phishing sites are often set up the day before an attack.

Links that use plain `http://` have no certificate at all. They are listed as "no certificate" and get no points, because the link check already looks at those links in other ways (requirement FR-4.4). Trusted domains (like the college's own website) are not checked, the same rule as the link check.

If **no** link needed checking (only http links, trusted sites or raw IP addresses), the card says **"n/a"** in grey, not "pass" in green. "Pass" would wrongly suggest that a certificate was checked and found fine, when really there was nothing to check.

**Why it matters.** A phishing site can copy a real site perfectly, but getting a proper certificate for the real name is very hard. A certificate for the wrong name, or one that nobody trusts, is a strong sign that something is off.

### Feature B: two handshakes, and checking things ourselves

**Analogy.** If the bouncer says "this card is not valid", you still want to look at the card yourself to see why: wrong photo, wrong date, or both.

**What happens.** The first handshake is a normal, strict one. If the certificate fails it, the program connects **once more without checking**, only so it can read the certificate and show its details on the page. The system library (OpenSSL) only reports the **first** problem it finds, so the program checks the expiry date and the names itself. That way an email whose certificate is self-signed **and** expired **and** for the wrong name gets all three flags, not just one.

**Why it matters.** The examiner can see the real evidence (issuer, dates, names covered) for every flag, not just "failed".

### Feature C: failures never cost points

If a site cannot be reached (it does not exist, there is no internet, it is too slow), that row says "could not connect" and adds **0 points**. If no site at all could be reached, the whole card shows "could not run", like the other checks. All handshakes run side by side with one hard time limit, so one stuck website cannot freeze the page.

### Feature D: offline demo mode (record once, replay later)

**Analogy.** A cooking show. The chef cooks the dish once before the show and puts it aside. During the live show, if the oven breaks, they take out the ready dish. The recipe and steps are still the same; only the waiting for the oven is skipped.

**What happens.** Every place where the tool talks to the internet goes through one small wrapper:
- DNS lookups (SPF, DKIM, DMARC, A, MX records),
- WHOIS (domain age),
- the TLS handshake (certificates),
- the AI (tone score and report text).

The wrapper has three modes:
1. **live**: normal, it asks the internet.
2. **record**: it asks the internet **and saves every answer** in `data/cache/lookups.json`.
3. **replay**: it **never** touches the internet. It gives back the saved answer. If an answer was never saved, it behaves exactly like "no internet", so that check shows "could not run".

Said another way: in replay, **all the checking code still runs** (SPF rules, lookalike detection, scoring). Only the raw answers from the internet come from the file.

**Why it matters.** College Wi-Fi often fails during demos (PRD risk list). With replay mode, the demo shows exactly the same results as when it was recorded, with no internet at all. This is requirement NFR-4, and the session is done when "the demo runs with Wi-Fi off".

### Feature E: safety rules for offline mode

- **Only the samples are ever saved.** The web page can be started in `live` or `replay` only. Record mode can only be switched on by the recording script, which reads the built-in sample emails. So an uploaded email's lookups are never written to disk (privacy rule PRV-1).
- **The AI's answers are saved under a fingerprint (hash) of the question**, not the question itself, so no email text from the prompt is stored.
- **Time is frozen at the moment of recording.** A domain's age and a certificate's expiry are judged as they were when the answers were saved. Otherwise a certificate that was fine when recorded could look "expired" on the day of the review and change the verdict.
- **The page is honest.** In replay mode a purple banner says "Offline demo mode: ... replayed from saved results recorded <date>". Every row that would say "live" says "saved answer (offline)". The PDF carries the same line.
- **A typo is refused.** If the mode is misspelled (for example `replya`), the app refuses to start instead of quietly going online.

### Feature F: the recording script checks itself

`scripts/record_offline_cache.py` does two passes. First it **records** the four samples with internet. Then it **switches the network off** inside the script and **replays** them, and compares the score, verdict and report source with the recording. It prints "OK" for each match and lists any lookup that failed while recording (this laptop's DNS sometimes times out). Running it again fills those gaps, because new answers are added to the saved ones.

**Important.** If the AI prompt or the sample emails are changed, the saved AI answers no longer match (the fingerprint changes), so the script must be run again.

## 4. Walk-through example

**Certificate check, `newsletter.eml`** (a shop newsletter with a link to `https://www.shopmart.com`):

1. The link is `https://`, and `shopmart.com` is not on the trusted list, so it is checked.
2. Handshake 1 (strict) fails. OpenSSL says: "Hostname mismatch, certificate is not valid for 'www.shopmart.com'".
3. Handshake 2 (just to read) gets the certificate: issued by DigiCert, valid until March 2027, but it covers `*.squarespace.com` and similar names, **not** `www.shopmart.com`.
4. Our own checks: trusted issuer (no untrusted flag), not expired, not new, but the **name does not match**: +15 points.
5. Total for the email: certificate 15 + no DKIM 5 + no DMARC 5 + tone 7.5 (score 3 x 2.5) = 32.5, which rounds up to **33, Suspicious**. (Before the session 7 tuning the tone gave 4.5, so it was 30.)

This is a real result: the domain belongs to someone else and its server shows a hosting company's certificate. A browser would show a warning for this link too.

**Offline mode, `forged_exam_cell.eml`, Wi-Fi off:**

1. Start the app with `PHISHGUARD_MODE=replay`. The purple offline banner appears.
2. Pick the sample. The sender check asks for `_dmarc.srmist.edu.in`. The wrapper finds the saved answer and returns it. No network is used.
3. The link check asks WHOIS for `verify-login.com`. The saved answer says "registered 2018-09-19". The age is worked out from the recording date.
4. The links are plain `http://`, so the certificate check records "no certificate" without any handshake.
5. The tone check asks the AI. The wrapper calculates the fingerprint of the prompt, finds the saved answer (score 8, "will be cancelled in 24 hours") and returns it.
6. Scoring gives **100, Phishing**, the same as when recorded, and the report is the AI's saved text. The PDF downloads normally.

## 5. Files

- `phishguard/modules/certificate.py` (M4): point at `check_certificate()` for the check, `fetch_certificate()` for "show me the handshake, and that it never asks for the page", and `inspect()` for the four flags.
- `phishguard/modules/offline.py`: point at `cached()` for "how does offline mode work" (the wrapper with live, record and replay), `mode()` for how the mode is chosen safely, and `now()` for the frozen time.
- `phishguard/scripts/record_offline_cache.py`: records the samples and checks that replay matches.
- `phishguard/data/cache/lookups.json`: the saved answers. You can open it and read the DNS records, WHOIS dates and AI answers.
- `phishguard/config.yaml`: new certificate points, a `certificate:` section, and `offline: mode`.
- `phishguard/modules/sender.py`, `links.py`, `llm_client.py`: each network function is wrapped with `offline.cached(...)` in one line.
- `phishguard/pipeline.py`: runs four checks side by side and marks rows "saved answer (offline)" in replay.
- `phishguard/tests/test_certificate.py` (19 tests, using certificates built inside the test) and `test_offline.py` (15 tests, including the whole demo with every network call blocked).

## 6. Viva questions

1. **What does the certificate check do?**
   For each https link it does only the TLS handshake on port 443, reads the website's certificate and hangs up. It flags a self-signed or untrusted certificate, an expired one, one made out for a different name, and one issued in the last 7 days.

2. **Does your tool visit the phishing website?**
   No. It stops after the handshake, which is only the "show me your ID" step. It never asks for the page, runs scripts or downloads anything. This is our safety rule SAF-1.

3. **What is a hostname mismatch, and why is it suspicious?**
   The certificate is made out for a different website name than the link. A real company gets a certificate for its own name. A mismatch means the server is pretending, or is not the site it claims to be.

4. **Why do you connect twice when a certificate fails?**
   The first, strict handshake only tells us that it failed. The second one skips the checks so we can read the certificate and show the issuer, dates and names as evidence. We never send anything else over that connection.

5. **What happens to plain http links?**
   They have no certificate, so they are recorded as "no certificate" with no points. The link check already judges those links in other ways.

6. **What is offline demo mode?**
   Every internet answer (DNS, WHOIS, certificates and the AI) is recorded once into a file. In replay mode the tool reads the answers from that file instead of the internet. The checking and scoring code still runs normally, so the demo gives the same results with Wi-Fi off.

7. **How do you know replay gives the same results?**
   The recording script switches the network off and replays the samples, comparing score, verdict and report source with the recording. A test also blocks every network call and runs all four samples, checking they match.

8. **Why is the time frozen in replay mode?**
   Domain age and certificate expiry depend on today's date. If we used the real date, a certificate that was valid when recorded might look expired at the review and change the verdict. So replay uses the date of recording.

9. **Does offline mode store users' emails?**
   No. Only the recording script can save answers, and it only reads our own sample emails. The web app can only run in live or replay mode. The AI answers are filed under a fingerprint of the prompt, so the prompt text is not stored.

10. **What if someone uploads a new email in offline mode?**
    Its answers were never saved, so those lookups behave like "no internet". Those checks show "could not run" and add 0 points, the report comes from the template, and a verdict is still shown.

## 7. Remember this

- M4 does **only the TLS handshake** on port 443: never the web page.
- Four certificate flags: **untrusted 15, expired 15, wrong name 15, new (under 7 days) 5**. Plain http means "no certificate", 0 points.
- Offline mode: **record once with internet, replay with Wi-Fi off**. The checking code still runs; only the internet's answers come from `lookups.json`.
- Replay uses the **time of recording**, and only the **sample emails** are ever recorded.
- Changing the AI prompt or a sample means **running the recording script again**.
