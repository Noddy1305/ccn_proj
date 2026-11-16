# PhishGuard-AI evaluation results

100 emails: 50 phishing, 50 legitimate. Weights as in config.yaml.

**Test emails** (public research sets, rebuilt with `scripts/fetch_eval_emails.py`):

- Nazario phishing corpus 2025: 50
- SpamAssassin easy_ham (2002-03): 40
- SpamAssassin hard_ham (2002-03): 10

Phishing emails: Jose Nazario's phishing corpus, https://monkey.org/~jose/phishing/ (CC BY 4.0). Legitimate emails: the SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/.

## Verdicts (with the AI tone check)

| Actual \ Verdict | Safe | Suspicious | Phishing |
| --- | --- | --- | --- |
| Phishing (50) | 18 | 27 | 5 |
| Legitimate (50) | 24 | 24 | 2 |

## Verdicts (without the AI tone check)

| Actual \ Verdict | Safe | Suspicious | Phishing |
| --- | --- | --- | --- |
| Phishing (50) | 23 | 26 | 1 |
| Legitimate (50) | 24 | 24 | 2 |

## Confusion matrix and rates

*Counted as caught* says which verdicts count as "the tool warned the user".

| Tone check | Counted as caught | Caught (TP) | Missed (FN) | False alarm (FP) | Correctly safe (TN) | Detection rate | False-positive rate | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| With AI | Suspicious or Phishing | 32 | 18 | 26 | 24 | 64% | 52% | 56% |
| With AI | Phishing only | 5 | 45 | 2 | 48 | 10% | 4% | 53% |
| Without AI | Suspicious or Phishing | 27 | 23 | 26 | 24 | 54% | 52% | 51% |
| Without AI | Phishing only | 1 | 49 | 2 | 48 | 2% | 4% | 49% |

## How the results on these emails changed

Each row is a full run on the same emails. Counted as caught: Suspicious or Phishing.

| Run | Detection rate | False-positive rate |
| --- | --- | --- |
| First run | 44% | 50% |
| After the one tuning step (tone 2.5 x, cap 20; lookalike fix) | 54% | 52% |
| After adding the disguise check (M9) | 74% | 52% |
| **Now** (SPF verdict taken from the receiving mail server when it recorded one) | **64%** | **52%** |

The last step is a correction, not a tuning: the tool used to re-check SPF against an IP address guessed from the Received headers, which is the wrong computer whenever an email passed through a relay. It reported "SPF failed" for emails the receiving server had recorded as SPF pass. Those false failures had been adding points to phishing emails, so the earlier detection rates were too high. The 2002 legitimate emails carry no server verdict, so their results hardly change.

## Tuning (done once, then frozen)

The weights were tuned once, on the odd-numbered emails only (the tuning half). The even-numbered emails (the test half) were not used to choose anything, so their numbers are the honest ones. Before: tone 1.5 x score, cap 15, and the old lookalike rule. After: tone 2.5 x score, cap 20, and the lookalike fix (redhat.com was flagged as a fake reddit.com). Counted as caught: Suspicious or Phishing.

| | Tuning half: detection | Tuning half: false-positive | Test half: detection | Test half: false-positive | All: detection | All: false-positive |
| --- | --- | --- | --- | --- | --- | --- |
| Before (first run, old weights) | 40% | 44% | 48% | 56% | 44% | 50% |
| New weights only (first run's flags, rescored) | 52% | 44% | 56% | 56% | 54% | 50% |
| After (second run: new weights + lookalike fix) | 52% | 44% | 56% | 60% | 54% | 52% |

**Run-to-run differences.** In 13 of 100 emails the second run found different red flags or a different AI tone score, independent of the tuning (a DNS lookup that timed out in one run but answered in the other, or the AI scoring the same text differently):

- phish_002.eml (phishing): safe 11 -> safe 20; tone 7.0 -> 8.0; flags +[] -[]
- phish_005.eml (phishing): safe 18 -> safe 10; tone 5.0 -> 0.0; flags +[] -[]
- phish_014.eml (phishing): phishing 61 -> suspicious 50; tone 7.0 -> 0.0; flags +[] -[]
- phish_018.eml (phishing): safe 18 -> safe 28; tone 5.0 -> 7.0; flags +[] -[]
- phish_020.eml (phishing): safe 29 -> suspicious 38; tone 6.0 -> 7.0; flags +[] -[]
- phish_021.eml (phishing): safe 21 -> safe 28; tone 4.0 -> 5.0; flags +[] -[]
- phish_029.eml (phishing): suspicious 46 -> suspicious 48; tone 7.0 -> 5.0; flags +[] -[]
- phish_033.eml (phishing): safe 5 -> safe 13; tone 0.0 -> 3.0; flags +[] -[]
- easy_014.eml (legitimate): safe 25 -> suspicious 30; tone 0.0 -> 0.0; flags +[dmarc_none] -[]
- easy_030.eml (legitimate): safe 0 -> safe 10; tone 0.0 -> 0.0; flags +[dkim_none, dmarc_none] -[]
- easy_033.eml (legitimate): safe 0 -> safe 10; tone 0.0 -> 0.0; flags +[dkim_none, dmarc_none] -[]
- hard_001.eml (legitimate): suspicious 58 -> suspicious 58; tone 5.0 -> 3.0; flags +[] -[]
- hard_002.eml (legitimate): suspicious 55 -> suspicious 50; tone 3.0 -> 0.0; flags +[] -[]

## Without the sender check

The legitimate emails are from 2002-03, before SPF, DKIM and DMARC existed, and most passed through the corpus collector's own mail server. Checked against today's DNS, their sender check fails because of their age, not because they are fake. This view leaves the sender check out for BOTH sets, to show how the other checks do on their own.

| Actual \ Verdict | Safe | Suspicious | Phishing |
| --- | --- | --- | --- |
| Phishing (50) | 29 | 21 | 0 |
| Legitimate (50) | 50 | 0 | 0 |

| Tone check | Counted as caught | Caught (TP) | Missed (FN) | False alarm (FP) | Correctly safe (TN) | Detection rate | False-positive rate | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| With AI, no sender check | Suspicious or Phishing | 21 | 29 | 0 | 50 | 42% | 0% | 71% |
| With AI, no sender check | Phishing only | 0 | 50 | 0 | 50 | 0% | 0% | 50% |

## What the disguise check (M9) adds

Same run, scored with and without the disguise check's flags (sender name, risky attachments, free hosting and redirect links). Its points were set before the held-out test, not tuned.

| Tone check | Counted as caught | Caught (TP) | Missed (FN) | False alarm (FP) | Correctly safe (TN) | Detection rate | False-positive rate | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| With AI, with disguise check | Suspicious or Phishing | 32 | 18 | 26 | 24 | 64% | 52% | 56% |
| With AI, with disguise check | Phishing only | 5 | 45 | 2 | 48 | 10% | 4% | 53% |
| With AI, without disguise check | Suspicious or Phishing | 19 | 31 | 26 | 24 | 38% | 52% | 43% |
| With AI, without disguise check | Phishing only | 2 | 48 | 2 | 48 | 4% | 4% | 50% |

**Caveat.** All phishing emails in the Nazario corpus were sent to one person's mailbox, so the "sender name shows your own organisation" rule fired on 14 of 50 of them; real inboxes see this trick less often. Without that rule, detection (Suspicious or Phishing) would be 56%.

## Average scores

| Set | Average score | Average without AI | Average tone score (0-10) |
| --- | --- | --- | --- |
| Phishing | 36.6 | 26.1 | 4.1 |
| Legitimate | 29.6 | 28.4 | 0.4 |

## Which red flags fired

Number of emails in each set where the flag fired.

| Red flag | Points | Phishing emails | Legitimate emails |
| --- | --- | --- | --- |
| dmarc_fail | 25 | 8 | 16 |
| risky_attachment | 20 | 1 | 0 |
| spf_fail | 20 | 0 | 2 |
| address_in_display_name | 15 | 0 | 1 |
| brand_display_name | 15 | 3 | 0 |
| brand_in_domain | 15 | 6 | 1 |
| cert_expired | 15 | 1 | 0 |
| cert_hostname_mismatch | 15 | 1 | 0 |
| link_text_mismatch | 15 | 4 | 3 |
| own_org_display_name | 15 | 14 | 0 |
| domain_mismatch | 10 | 11 | 20 |
| domain_unresolved | 10 | 11 | 20 |
| free_hosting_link | 10 | 8 | 0 |
| redirect_link | 10 | 6 | 0 |
| spf_softfail | 10 | 5 | 9 |
| cert_new | 5 | 1 | 3 |
| dkim_none | 5 | 12 | 42 |
| dmarc_none | 5 | 32 | 25 |
| spf_none | 5 | 3 | 13 |
| tone score 3 or more (AI) | up to 20 | 38 | 6 |

## Checks that could not run

- certificate: 14 of 100 emails
- sender: 8 of 100 emails

## Time per email

Average 2.3 s, median 1.4 s, slowest 19.2 s (live lookups, one email at a time, AI tone check included, report text not).
