# Session 7: Evaluation (testing the tool on 100 real emails)

> **Read this first.** Session 7 has three parts, in the order things happened. **Part 1**: the first test (54% caught) and the one tuning step. **Part 2**: the new disguise check (M9). **Part 3**: a review that corrected a mistake in the SPF check. The **final numbers to quote** are in Part 3: **74% of phishing caught** on 100 unseen emails, and **6 of 6** of our own recent emails rated Safe. Numbers in Part 1 are what we measured at that stage.

## 1. The big picture

This session did not add a new check. It **measured** how well PhishGuard-AI works, by running it on 100 real emails (50 phishing, 50 normal) and counting how often it was right. It also made the **one tuning change** the plan allows, fixed a bug the test found, and then froze the weights.

In the PhishGuard-AI flow, nothing changes for the user. The new scripts sit outside the app and push many emails through the same pipeline the dashboard uses.

## 2. New terms

- **Evaluation**: testing a tool on emails whose real answer we already know, and counting how often it agrees.
- **Dataset / corpus**: a collection of emails used for testing. "Corpus" is Latin for "body", meaning a body of text.
- **Nazario phishing corpus**: a public collection of real phishing emails, gathered by security researcher Jose Nazario. We used his 2025 emails. Licence: CC BY 4.0 (free to use if you credit him).
- **SpamAssassin public corpus**: a public collection of normal emails ("ham") and spam from 2002-2003, made by the SpamAssassin anti-spam project.
- **Ham**: the nickname for a normal, wanted email (the opposite of spam).
- **True positive (TP)**: a phishing email that the tool warned about. Correct.
- **False negative (FN)**: a phishing email the tool called Safe. A miss.
- **False positive (FP)**: a normal email the tool warned about. A false alarm.
- **True negative (TN)**: a normal email the tool called Safe. Correct.
- **Confusion matrix**: a small table of those four counts, showing where the tool gets "confused".
- **Detection rate**: out of all phishing emails, the share it caught. TP / (TP + FN).
- **False-positive rate**: out of all normal emails, the share it wrongly flagged. FP / (FP + TN).
- **Accuracy**: out of all emails, the share it got right.
- **Tuning**: adjusting the point weights to get better results.
- **Overfitting**: tuning so closely to your test emails that the numbers look better than the tool really is.
- **Tuning half / test half**: we split the emails in two. We chose the weights using only one half, and report the other half as the honest result.
- **Seed**: a fixed starting number for random picking, so the same "random" emails are picked every time.
- **CSV (Comma-Separated Values)**: a simple table file that opens in Excel.

## 3. How it works

### Feature A: getting the test emails

**Analogy.** A driving examiner does not test you only on your own street. They take you on roads you have never seen. We test the tool on emails it has never seen.

**What happens.** `scripts/fetch_eval_emails.py` downloads two public collections and picks 100 emails with a fixed seed:
- 50 phishing emails from the **Nazario corpus, 2025**: recent, real attacks.
- 50 normal emails from the **SpamAssassin corpus**: 40 ordinary emails and 10 "hard" ones (marketing mail that looks a bit like spam).

The emails are **not** put on GitHub, because they belong to the people who wrote them. Anyone can rebuild the same 100 by running the script, as long as the public files have not been changed since.

**Why it matters.** A test on emails we wrote ourselves would prove nothing. Real emails show how the tool does in real life.

### Feature B: running them all and counting

**Analogy.** A teacher marking 100 exam papers with an answer key, then working out the class average.

**What happens.** `scripts/evaluate.py` sends each email through the same pipeline as the dashboard. It skips only the AI report text, which is not needed for a score. For every email it saves the score, the verdict, which red flags fired, the AI tone score and the time taken. It saves this in `results/evaluation.csv`. Then it writes `results/evaluation.md` with:
- the confusion matrix and the rates,
- the same numbers **without the AI tone check**, to show what the AI adds,
- which red flags fired how often in phishing vs normal emails,
- the time per email.

If the AI service says "too many requests", the script waits and asks again, so a busy service does not quietly remove the tone check from the comparison.

### Feature C: the results, explained simply

Counting "Suspicious or Phishing" as "the tool warned you":

| | Caught / correct | Missed / false alarm |
| --- | --- | --- |
| 50 phishing emails | 27 caught | 23 missed |
| 50 normal emails | 24 called Safe | 26 false alarms |

- **Detection rate 54%** (34% without the AI). **False-positive rate 52%.** **Average time 3.2 seconds** per email.
- Almost every catch is **Suspicious**, not Phishing: only **2 of 50** phishing emails reached the Phishing band (60+). The tool says "be careful" far more often than "this is definitely fake".
- These are below the plan's targets (85% and 10%). The two reasons below are the important part to explain.

**Reason 1: modern phishing often looks "properly sent".** Many 2025 phishing emails are sent through real email companies (for example a marketing service) or from hacked real accounts. So SPF, DKIM and DMARC **pass**, because the email really was sent by an allowed server. Our sender check, the strongest part of the tool, has nothing to catch. One example passed every single check.

**Reason 2: the normal emails are from 2002.** There is no public collection of recent normal emails with full headers, because people's inboxes are private. In 2002, SPF, DKIM and DMARC **did not exist yet**. Our tool checks them against **today's** internet. So the old emails "fail" for being old, not for being fake: 42 of 50 have no DKIM, and 35 of 50 passed through the collector's own mail server, which often looks like a sender mismatch. When we leave the sender check out for both sets, the false-alarm rate drops to **0%**, but detection also drops to **10%**. So the sender check is still the main thing catching phishing; it just cannot judge 2002 email fairly.

**Analogy for reason 2.** Checking a 2002 passport against 2025 rules: it has no chip, so it "fails", but that does not make it a fake.

### Feature D: the one tuning change (and how we kept it honest)

**Analogy.** Adjusting a recipe using only half of your taste-testers, then asking the other half whether it is better. The second half's opinion is the fair one.

**What happens.** The results showed that the **AI tone score is the best clue** for recent phishing: 38 of 50 phishing emails got a tone of 3 or more, but only 6 of 50 normal ones. But tone was capped at 15 points and the Suspicious line is 30, so many phishing emails stopped at 20-29, just short.

We tried a few settings on the **odd-numbered emails only** and picked the smallest change that helped: tone points = **2.5 x score, capped at 20** (it was 1.5 x score, capped at 15). On the **even-numbered emails**, which we did not use for choosing, detection went from 48% to 56%, and false alarms **did not go up** (56% before and after, when we score the same saved flags with the new weights).

The safety rule still holds: 20 is below 30, so **the AI can never flag an email on its own**. At least 10 points must come from the real technical checks. The tone card stays amber at most, never red.

After this, the weights are **frozen**: we do not change them again before the review.

### Feature E: a bug the test found

The test flagged the real company **redhat.com** as a fake **reddit.com**. They are only 2 letters apart, and the old rule allowed a 2-letter difference for any domain of 10+ characters, counting the ".com". Now a 2-letter difference is allowed only when the **name itself** has 7 or more letters. In a 6-letter name like "redhat", 2 changes are a third of the word, so real companies end up that close by chance. Single-letter tricks like srm**l**st vs srm**i**st are still caught.

### Feature F: honest about randomness

We ran the test twice (before and after the tuning). In 13 of 100 emails something changed **on its own**: a DNS lookup that timed out once and answered the other time, or the AI scoring the same text 5 one time and 7 the next. The results file lists these, so nobody can say we hid them.

## 4. Walk-through example

Follow **phish_047.eml**, a 2025 phishing email:

1. **Parse (M1).** Sender, links and text are pulled out.
2. **Sender (M2).** SPF is "softfail", meaning the server is probably not allowed: +10. The sender's domain has no DMARC record: +5.
3. **Links (M3) and certificate (M4).** Nothing suspicious found.
4. **Tone (M5).** The AI scores the wording 7/10, with quotes that really are in the email.
5. **Before tuning:** 10 + 5 + (1.5 x 7 = 10.5) = 25.5, which rounds to **26, Safe**. A miss.
6. **After tuning:** 10 + 5 + (2.5 x 7 = 17.5) = 32.5, which rounds to **33, Suspicious**. Caught.
7. The real checks gave 15 points of evidence, and the AI's opinion tipped it over the line. The AI alone (17.5) could not have done it.

**Update from Part 3.** The "softfail" in step 2 turned out to be our own mistake: the receiving server had recorded `spf=pass` for this email, and we had tested the wrong computer. With the SPF check corrected, this email gets 5 + 17.5 = 22.5, which rounds to **23, Safe**: a miss again. The arithmetic above still shows how the tuning works, but this email is now an example of phishing that really does pass the sender checks.

## 5. Files

- `phishguard/scripts/fetch_eval_emails.py`: downloads the 100 public test emails with a fixed seed. Point at `phishing_emails()` and `ham_emails()`.
- `phishguard/scripts/evaluate.py`: runs every email and writes the results. Point at `run_one()` for "how do you test one email", `matrix()` for "how is the confusion matrix counted", and `rescore()` for "how did you try other weights without re-running everything".
- `phishguard/results/evaluation.md`: **the results to show the examiner**: confusion matrix, rates, before/after tuning, flag counts and timing.
- `phishguard/results/evaluation.csv` and `evaluation_before.csv`: one row per email, after and before the tuning (file name, scores, flags; no email text).
- `phishguard/config.yaml`: the `tone:` section now says 2.5 and 20, with a comment explaining why.
- `phishguard/modules/links.py`: the lookalike fix, in `lookalike_of()`.
- `phishguard/data/cache/lookups.json`: re-recorded, because the new weights change what the AI report is told. Demo results are now: forged 100 Phishing, genuine 5 Safe, newsletter 33 Suspicious, corpus 40 Suspicious.

## 6. Viva questions

1. **How did you evaluate your tool?**
   We ran it on 100 real emails: 50 recent phishing emails from the public Nazario corpus and 50 normal emails from the public SpamAssassin corpus. We counted caught, missed, false alarms and correctly safe, and measured the time per email.

2. **What were your results?**
   It caught 54% of phishing emails (34% without the AI) and wrongly flagged 52% of normal ones, at about 3 seconds per email. Almost all catches were Suspicious: only 2 of 50 reached Phishing. These are below our targets, and we can explain both reasons.

3. **Why is the detection rate low?**
   Much recent phishing is sent through real email services or hacked real accounts, so SPF, DKIM and DMARC pass, because the server really was allowed. Our strongest check has nothing to catch. Catching these needs the content and link clues, which is why the AI tone signal helped most.

4. **Why are there so many false alarms?**
   The only public normal emails with full headers are from 2002, before SPF, DKIM and DMARC existed. Checked against today's internet they look like they fail. With the sender check left out for both sets, false alarms fell to 0%, but detection also fell to 10%, so the sender check is still essential. A fair test needs recent normal emails, for example from our own inboxes.

5. **What is a confusion matrix?**
   A 2 by 2 table: phishing caught, phishing missed, normal emails flagged by mistake, and normal emails correctly called safe. It shows exactly where the tool goes wrong, not just one overall number.

6. **What did you tune, and how did you avoid cheating?**
   We changed one thing: tone points became 2.5 times the score, capped at 20 (from 1.5 and 15). We chose it using only the odd-numbered emails and report the even-numbered ones as the honest result: detection went from 48% to 56% with no extra false alarms.

7. **Doesn't a bigger tone weight let the AI decide?**
   No. The cap is 20 and Suspicious starts at 30, so at least 10 points must come from real technical checks. The verdict is still made by fixed rules in code.

8. **Did testing find any bugs?**
   Yes. redhat.com was flagged as a fake reddit.com, because they are 2 letters apart. Now a 2-letter difference only counts for names of 7 or more letters, and redhat.com is in our regression tests.

9. **Why don't you get exactly the same numbers each run?**
   Live DNS lookups sometimes time out, and the AI can score the same text slightly differently. In 13 of 100 emails something changed between our two runs, and we list them in the results. For the demo, offline mode replays saved answers, so the demo is always the same.

10. **What would you do with more time?**
    Test on recent normal emails from our own inboxes, add content clues that do not depend on the sender (like "asks for a password"), and check where links really lead. The weights would then be tuned once more on that fairer data.

## 7. Remember this

- 100 public emails: **50 recent phishing (Nazario 2025)**, **50 normal (SpamAssassin 2002)**.
- Results: **54% caught, 52% false alarms, 3.2 s per email**; only **2 of 50** reached Phishing. The AI tone check raised detection from 34% to 54%.
- Low detection: **modern phishing passes SPF/DKIM/DMARC**. High false alarms: **2002 emails are older than SPF/DKIM/DMARC**.
- One tuning change, chosen on half the emails: **tone 2.5 x score, cap 20**. The AI still can't flag an email alone.
- Testing found and fixed a bug: **redhat.com is not a fake reddit.com**.

---

# Session 7, Part 2: the disguise check (M9) and the final test

## 1. The big picture

Part 1 showed the tool missed about half of recent phishing, because modern scams often pass SPF, DKIM and DMARC. Part 2 added a new check, **M9, the disguise check**, which looks for the other ways a scam hides who sent it or where its links go. It was then tested on 100 emails the tool had never seen: it catches **74%** of phishing, up from 40% without the new check. (The first run said 84%; Part 3 explains why that number was too high and was corrected.)

M9 runs side by side with the other checks, like M2 to M5, and its red flags go into the scoring engine (M6). It uses **no internet**: it only reads the email.

## 2. New terms

- **Display name**: the name shown next to an email address, for example "PayPal Service" in `"PayPal Service" <x@evil.com>`. The sender can type anything here.
- **Brand impersonation**: pretending to be a well-known company (PayPal, FedEx, a bank).
- **Free website hosting**: services such as Netlify or Google Sites where anyone can publish a web page in minutes, for free. Scammers put fake login pages there.
- **Redirect link**: a link that first goes to one website (for example google.com) which then sends you on to another. It hides the real destination.
- **Unwrap**: reading the real destination hidden inside a redirect link.
- **File extension**: the ending of a file name (.pdf, .html, .exe) that says what kind of file it is.
- **Mailing list**: one address that forwards mail to many people. It adds a `List-Id` header.
- **Held-out set**: a second group of test emails kept aside and used only once, at the very end, so the result is honest.

## 3. How it works

### Feature A: the sender name does not match the sender

**Analogy.** A letter signed "Your Bank" but posted from a stranger's home address.

**What happens.** M9 looks at the display name in three ways:
1. **A brand in the name** ("einvoice_fedex", "PayPal Service") while the sending domain does not belong to that brand: +15. A domain counts as the brand's own if it starts or ends with the brand name with no extra hyphenated words, so `hdfcbank.net` is HDFC but `paypal-alerts.com` is not.
2. **A different email address in the name** (`"service@paypal.com" <x@evil.com>`): +15.
3. **Your own organisation in the name** ("monkey.org HOSTING" sent to someone at monkey.org, from an outside domain): +15. This is the classic "IT helpdesk" or "HR department" scam.

**Why it matters.** Most people read the name, not the address. Scammers know this.

### Feature B: risky attachments

**Analogy.** A parcel labelled "documents" that is actually a key to a fake door.

**What happens.** If an attachment's file name ends in .html, .svg, .exe, .js, .iso, .docm and similar, M9 adds **+20**. These files can open a fake login page or run a program. The file is **never opened**; only its name is read.

**Why it matters.** A "Waybill.html" attachment that opens a fake FedEx login page is one of the most common tricks today.

### Feature C: links on free hosting, or hidden behind a redirect

**Analogy.** A shop with a hand-written sign in a rented stall, or a signpost that says "Bank" but points down an alley.

**What happens.** A link to a free hosting service (netlify.app, sites.google.com, storage.googleapis.com ...) adds **+10**. A link through google.com/url?q=... or an advert-click address adds **+10**, and M9 **unwraps** it to check the real destination too. Company email-security wrappers (Outlook "Safe Links") are unwrapped but not flagged, because companies wrap every link that way.

### Feature D: designed not to cause false alarms

The old 2002 test emails cannot show false alarms from modern habits, so these were designed out in advance and written as tests:
- Google Groups and mailing lists ("Alice via Team", or a `List-Id` header) are skipped.
- Real brand addresses such as `hdfcbank.net`, `amazonpay.in`, `onlinesbi.sbi` and Apple sending as "iCloud" are not flagged.
- Gmail, Outlook or Yahoo users are not treated as an "organisation".
- A name like "Mark Appleton" is not the brand "Apple".
- One fact never counts twice.

M9 was also run on real recent emails from our own inbox (Part 3): no flags.

### Feature E: the honest final test (held-out set)

**Analogy.** Practising on past papers is fine, but your real mark comes from the exam paper you have never seen.

**What happens.** Before building M9 we put aside a **second 100 emails** (2024 phishing and a different archive of normal emails), shared with nothing we had looked at. M9's points were fixed **before** that test, by comparison with similar flags (for example an HTML attachment is as strong as an SPF fail, 20). The test was run **once**.

## 4. Walk-through example

**phish_041.eml**, sent to jose@monkey.org from `news@newspread-ie.com`, display name "monkey.org HOSTING":

1. **Sender (M2).** The domain has no DMARC record: +5. Nothing else, so SPF and DKIM do not help.
2. **Before M9:** with the AI tone this was only **23, Safe**. A miss.
3. **M9, sender name.** "monkey.org HOSTING" shows the reader's own organisation, but the email comes from newspread-ie.com: +15.
4. **M9, links.** The link is `google.com/url?q=...`, a redirect: +10. Unwrapped, the real destination is `vdm-2-g2vc.4everland.app`, a free hosting service: +10.
5. **Without the AI** this is already 5 + 15 + 10 + 10 = **40, Suspicious**: caught by rules alone.
6. **Tone (M5).** The email threatens that "access to your email will soon be closed" within 24 hours. The AI scores the wording 8/10: +20.
7. **Total 60: Phishing.**

## 5. Files

- `phishguard/modules/disguise.py` (M9): point at `check_disguise()` for the whole check, `_belongs_to()` for "how do you know hdfcbank.net is really HDFC", and `unwrap()` for "how do you find where a redirect really goes".
- `phishguard/tests/test_disguise.py`: one test per trick, plus tests for the legitimate patterns that must not be flagged.
- `phishguard/modules/parser.py`: now also reads the `List-Id` header.
- `phishguard/config.yaml`: six new point values, with a comment saying they were set before the final test.
- `phishguard/scripts/fetch_eval_emails.py --heldout` and `evaluate.py --set heldout`: build and run the separate final test.
- `phishguard/results/heldout.md`: **the final results to show the examiner.**

## 6. Viva questions

1. **What does the disguise check do?**
   It looks for ways a scam hides who sent it or where its links go: a brand or another address in the sender name, your own organisation's name from an outside sender, risky attachments, links to free hosting, and links hidden behind redirects. It uses no internet and only reads the email.

2. **Why did you add it?**
   Our first evaluation showed that much recent phishing passes SPF, DKIM and DMARC, because it is sent through real email services. Those emails still disguise themselves in other ways, and M9 looks for exactly those.

3. **What is your final detection rate?**
   74% on 100 emails the tool had never seen (40% without M9). Our target was 85%. Without the "own organisation" rule it would be 58%; that rule is strong here because all these phishing emails went to one person.

4. **And the false-positive rate?**
   86% on the old normal emails. 40 of the 43 false alarms are made only of flags caused by age: the emails are from 2002, before SPF, DKIM and DMARC existed, and many link to websites that no longer exist. With the sender check left out, false alarms are 2%, and M9 itself caused none. On 6 recent genuine emails from our own inbox, all 6 were rated Safe.

5. **How do you know you did not just fit the tool to your test emails?**
   We kept a separate 100 emails aside and never used them to design or tune anything. M9's points were fixed before that test. It was run once (84%), and once more after we corrected a mistake in the SPF check that was found by reviewing the code, not by looking at those emails (74%). We report both.

6. **Why is an HTML attachment dangerous?**
   It opens in the browser and can show a perfect fake login page, saved on your own computer, so no website has to be visited first. That is why it gets 20 points, as strong as an SPF fail.

7. **How do you avoid flagging real bank emails from a different domain?**
   If the sending domain starts or ends with the brand name, like `hdfcbank.net`, it is treated as the brand's own. Extra hyphenated words, like `paypal-alerts.com`, are a classic disguise and still flagged.

8. **What about Google Groups, which also show another address in the name?**
   They add "via" to the name and mailing lists add a `List-Id` header. M9 skips both, and we have tests for it.

9. **Does M9 open attachments or visit links?**
   No. It reads the file name and the link text only. Nothing is opened, downloaded or visited (SAF-1, SAF-2).

10. **What would still improve the results?**
    A fair false-positive number needs recent normal emails, for example from our own inboxes. After that, the weights could be tuned once more on that fairer data.

## 7. Remember this

- **M9, the disguise check**: sender name tricks, risky attachments, free hosting, hidden redirects. No internet.
- **Final test on 100 unseen emails: 74% caught** (40% without M9; 58% without the one-mailbox rule). The first run said 84%, before the SPF correction in Part 3.
- The 86% false alarms come from **2002 emails meeting 2025 checks**: without the sender check it is **2%**, and **M9 added none**. Our own 6 recent emails: **all Safe**.
- M9's points were **fixed before** the final test. Nothing was ever tuned on the final test emails.

---

# Session 7, Part 3: the cross-check review

## 1. The big picture

Before calling the evaluation finished, the whole of session 7 was reviewed again with fresh eyes, and the tool was run on **recent genuine emails from our own inbox**. The review found **one real mistake in the SPF check** and **one in the AI-report safety filter**, and fixed both. The corrected final result is **74% of phishing caught** on unseen emails (the earlier 84% was too high), and **6 of 6** of our own recent emails rated Safe.

Nothing new was added to the flow. The fixes are inside M2 (sender check) and M7 (report text).

## 2. New terms

- **Relay**: a mail server in the middle that passes an email along, like a sorting office between two post offices.
- **Connecting IP**: the address of the computer that actually handed the email to the receiving mail server. This is the one SPF is about.
- **Delivery time**: the moment the email arrived. SPF is a fact about that moment.
- **Authentication-Results header**: the note the receiving server (for example Gmail) writes on the email, with its SPF, DKIM and DMARC verdicts.
- **False contradiction**: when our safety filter wrongly thinks the AI's report disagrees with the verdict.
- **Correction vs tuning**: a correction fixes something that was wrong; tuning adjusts numbers to get better results. Only tuning needs a separate test set.

## 3. How it works

### Feature A: SPF now trusts the guard who was at the door

**Analogy.** A parcel travels: sender, courier van, sorting office, your building's front desk. The front-desk guard checks the **van that pulled up at the door** against the company's list of approved vans, and writes "van OK" on the parcel. Weeks later, we try to redo that check from the stamps on the parcel, and we pick the **first** stamp, which is the sender's own office, not the van. The office is not on the list of vans, so we shout "not approved!" even though the guard saw the right van.

**What happened.** Our SPF check took the IP of the **first** computer in the Received headers. But SPF is about the **last** one, the computer that handed the email to the receiving server. When an email passed through a relay, we tested the wrong computer. On 17 of 50 test emails our IP was not the one the receiving server saw, and we reported "SPF failed" for emails the server had recorded as **pass**.

**The fix.** If the receiving server wrote an SPF verdict in the Authentication-Results header, **we use that verdict**. It saw the real computer, at delivery time. Only when an email has no such verdict do we redo the check ourselves, as before. DKIM is still verified live by us, because a signature travels with the email and can be checked at any time.

**Why it matters.** The tool must not say "SPF failed" when it did not. An examiner who knows SPF would ask "which IP do you test?", and "the first hop" is the wrong answer.

### Feature B: an honest drop from 84% to 74%

Those false "SPF failed" flags had been **adding points to phishing emails**, so the detection rate looked better than it really was. With the mistake corrected, detection on the unseen set went from 84% to **74%** (and on the first set from 74% to 64%). This is a **correction, not tuning**: we did not adjust anything to fit the emails, we removed a wrong reading. We report both numbers.

Said another way: 84% was partly luck from a bug. 74% is what the tool really does.

### Feature C: recent emails from our own inbox

**Analogy.** After testing a metal detector on old coins from a museum, you finally try it on the coins in your own pocket.

**What happens.** `evaluate.py --set inbox` runs emails we downloaded from our own Gmail. They are private, so they are never put on GitHub, the results list them only as inbox_01 to inbox_06, and the **AI tone check is switched off** so no email text leaves the laptop. Result: **6 of 6 Safe**. Five scored 0. One scored 15, because a button's text showed one website while the link went through an email-marketing tracking service; 15 is still Safe.

**Why it matters.** It is the first evidence on **modern** genuine email: SPF, DKIM and DMARC all passed on all 6. Six emails is too few to call it a false-positive rate, but it supports our explanation that the 86% comes from the age of the public test emails.

### Feature D: the AI-report safety filter was too jumpy

**What happened.** The filter that rejects AI text which contradicts the verdict looked for "is legitimate" anywhere. A perfectly good report said "...no DMARC record to prove the email **is legitimate**", and was thrown away in favour of the plainer template.

**The fix.** The filter now reads sentence by sentence, and only objects when a sentence plainly says **the email** (or the verdict) is safe, genuine, legitimate or harmless. Sentences with "prove", "confirm", "verify", "whether", "if" or "not" are not claims.

### Feature E: smaller fixes

- HubSpot's own tracking links (`hubspotlinks.com`) were flagged as a fake "hubspot" domain. That domain is now on the trusted list, next to HubSpot's others.
- The AI report was told the tone flag was called "Manipulative wording (AI)" and wrote "AI-generated pressure tactics". It now sees "Manipulative wording".
- The AI is now told the score measures **risk** (it once called 5 out of 100 a "low safety score"), and that it has not seen the email, so it must not describe what the email says.
- Our notes said "41 of 44 false alarms come only from the sender check". Counting again, that included two other age-related flags (dead websites, renewed certificates). The notes now say so.
- A trial run of the test script (`--limit`) can no longer overwrite the real results.

## 4. Walk-through example

A phishing email in the test set was written on one computer and sent out through the real mail server of a hacked account:

1. **Old behaviour.** We took the first IP in the Received headers (the scammer's computer) and tested it against the sending domain's SPF list. Not on the list: "SPF failed", +20, and DMARC failed too, +25.
2. **What really happened at delivery.** The receiving server saw the hacked account's **real mail server** hand the email over. That server is on the list, so it wrote `spf=pass`.
3. **New behaviour.** We read `spf=pass` from the Authentication-Results header. No SPF points, and DMARC passes.
4. **Result.** The email loses 45 points it never deserved. If nothing else is wrong with it, the tool now misses it, which is honest: this kind of phishing genuinely passes the sender checks, and has to be caught by the disguise check or the tone check instead.

## 5. Files

- `phishguard/modules/sender.py`: point at `check_spf()`. The first lines use the receiving server's verdict; the rest is the live backup.
- `phishguard/modules/report.py`: point at `contradicts_verdict()` for the safety filter.
- `phishguard/scripts/evaluate.py`: `--set inbox` for our own emails (AI off), and a table showing how each change moved the results.
- `phishguard/results/heldout.md`: **the final results**, with both the first run (84%) and the corrected one (74%).
- `phishguard/results/inbox.md`: our own 6 recent emails.
- `phishguard/results/heldout_first.csv`, `evaluation_m9.csv`: the earlier runs, kept so the history can be checked.
- `phishguard/data/cache/lookups.json`: the offline demo, recorded again. Demo scores are unchanged: 100, 5, 33, 40.

## 6. Viva questions

1. **Which IP address should SPF be checked against?**
   The IP of the computer that handed the email to the receiving mail server. Only the receiving server sees it, at delivery time, and it writes its verdict in the Authentication-Results header.

2. **So how does your tool check SPF?**
   If the email carries the receiving server's SPF verdict, we use it. If not, we re-check ourselves with the IP found in the Received headers and today's DNS, and label the result "live".

3. **Why not always re-check SPF yourselves?**
   Afterwards we can only guess the connecting computer from the Received headers, and the guess is wrong when the email went through a relay. Also DNS records change over time. The receiving server's verdict is the real one.

4. **Then why do you still verify DKIM yourselves?**
   A DKIM signature is inside the email, so anyone can verify it later with the public key in DNS. SPF depends on something outside the email: who delivered it.

5. **Your detection rate dropped from 84% to 74%. Why did you accept that?**
   Because 84% was wrong. A mistake in our SPF check gave phishing emails points for failures that never happened. We fixed the mistake and report the true number, with the old one beside it.

6. **Is re-running the final test after a fix cheating?**
   No, because the fix was a correction found by reviewing the code and the first test set, not an adjustment made to score better on the final set. The result also went down, not up. We keep both runs in the results folder.

7. **What happened when you tested your own emails?**
   All 6 recent genuine emails from our inbox were rated Safe, and SPF, DKIM and DMARC passed on every one. It is a small sample, so we call it supporting evidence, not a false-positive rate.

8. **Did you send your private emails to the AI?**
   No. For that run the AI tone check was switched off, the emails stay out of GitHub, and the results list them by number only.

9. **Can someone fake the Authentication-Results header?**
   A sender can add a fake one, but the receiving server puts its own on top, and we read only the topmost. This is safe for emails downloaded from a real mailbox like Gmail. For a hand-made file it cannot be guaranteed, which is a known limit.

10. **What did the review teach you?**
    That a good-looking number can hide a bug. Checking our own results against what the receiving servers had recorded showed the mistake, and the honest number is lower but explainable.

## 7. Remember this

- SPF is about **the computer at the door**; only the receiving server saw it, so **its verdict comes first**.
- Fixing that removed false "SPF failed" flags: unseen-set detection is **74%**, not 84%.
- Our own 6 recent genuine emails: **all Safe**, with the AI off and nothing private shared.
- The AI-report filter now only rejects text that says **the email itself** is safe.
- A fix found by review is a **correction**; we still never tuned on the final test emails.

