# PhishGuard-AI evaluation results: held-out set (not used to design or tune anything)

100 emails: 50 phishing, 50 legitimate. Weights as in config.yaml.

**Test emails** (public research sets, rebuilt with `scripts/fetch_eval_emails.py`):

- Nazario phishing corpus 2024: 50
- SpamAssassin easy_ham_2 (2002-03): 40
- SpamAssassin hard_ham (2002-03): 10

Phishing emails: Jose Nazario's phishing corpus, https://monkey.org/~jose/phishing/ (CC BY 4.0). Legitimate emails: the SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/.

## Verdicts (with the AI tone check)

| Actual \ Verdict | Safe | Suspicious | Phishing |
| --- | --- | --- | --- |
| Phishing (50) | 13 | 33 | 4 |
| Legitimate (50) | 7 | 31 | 12 |

## Verdicts (without the AI tone check)

| Actual \ Verdict | Safe | Suspicious | Phishing |
| --- | --- | --- | --- |
| Phishing (50) | 22 | 28 | 0 |
| Legitimate (50) | 7 | 31 | 12 |

## Confusion matrix and rates

*Counted as caught* says which verdicts count as "the tool warned the user".

| Tone check | Counted as caught | Caught (TP) | Missed (FN) | False alarm (FP) | Correctly safe (TN) | Detection rate | False-positive rate | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| With AI | Suspicious or Phishing | 37 | 13 | 43 | 7 | 74% | 86% | 44% |
| With AI | Phishing only | 4 | 46 | 12 | 38 | 8% | 24% | 42% |
| Without AI | Suspicious or Phishing | 28 | 22 | 43 | 7 | 56% | 86% | 35% |
| Without AI | Phishing only | 0 | 50 | 12 | 38 | 0% | 24% | 38% |

## How the results on these emails changed

Each row is a full run on the same emails. Counted as caught: Suspicious or Phishing.

| Run | Detection rate | False-positive rate |
| --- | --- | --- |
| First run, done once, with the disguise check (M9) | 84% | 88% |
| **Now** (SPF verdict taken from the receiving mail server when it recorded one) | **74%** | **86%** |

The last step is a correction, not a tuning: the tool used to re-check SPF against an IP address guessed from the Received headers, which is the wrong computer whenever an email passed through a relay. It reported "SPF failed" for emails the receiving server had recorded as SPF pass. Those false failures had been adding points to phishing emails, so the earlier detection rates were too high. The 2002 legitimate emails carry no server verdict, so their results hardly change.

## Without the sender check

The legitimate emails are from 2002-03, before SPF, DKIM and DMARC existed, and most passed through the corpus collector's own mail server. Checked against today's DNS, their sender check fails because of their age, not because they are fake. This view leaves the sender check out for BOTH sets, to show how the other checks do on their own.

| Actual \ Verdict | Safe | Suspicious | Phishing |
| --- | --- | --- | --- |
| Phishing (50) | 26 | 24 | 0 |
| Legitimate (50) | 49 | 0 | 1 |

| Tone check | Counted as caught | Caught (TP) | Missed (FN) | False alarm (FP) | Correctly safe (TN) | Detection rate | False-positive rate | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| With AI, no sender check | Suspicious or Phishing | 24 | 26 | 1 | 49 | 48% | 2% | 73% |
| With AI, no sender check | Phishing only | 0 | 50 | 1 | 49 | 0% | 2% | 49% |

## What the disguise check (M9) adds

Same run, scored with and without the disguise check's flags (sender name, risky attachments, free hosting and redirect links). Its points were set before the held-out test, not tuned.

| Tone check | Counted as caught | Caught (TP) | Missed (FN) | False alarm (FP) | Correctly safe (TN) | Detection rate | False-positive rate | Accuracy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| With AI, with disguise check | Suspicious or Phishing | 37 | 13 | 43 | 7 | 74% | 86% | 44% |
| With AI, with disguise check | Phishing only | 4 | 46 | 12 | 38 | 8% | 24% | 42% |
| With AI, without disguise check | Suspicious or Phishing | 20 | 30 | 43 | 7 | 40% | 86% | 27% |
| With AI, without disguise check | Phishing only | 2 | 48 | 12 | 38 | 4% | 24% | 40% |

**Caveat.** All phishing emails in the Nazario corpus were sent to one person's mailbox, so the "sender name shows your own organisation" rule fired on 17 of 50 of them; real inboxes see this trick less often. Without that rule, detection (Suspicious or Phishing) would be 58%.

## Average scores

| Set | Average score | Average without AI | Average tone score (0-10) |
| --- | --- | --- | --- |
| Phishing | 38.0 | 26.0 | 4.7 |
| Legitimate | 42.9 | 41.9 | 0.4 |

## Which red flags fired

Number of emails in each set where the flag fired.

| Red flag | Points | Phishing emails | Legitimate emails |
| --- | --- | --- | --- |
| dmarc_fail | 25 | 3 | 23 |
| lookalike_domain | 25 | 0 | 1 |
| risky_attachment | 20 | 3 | 0 |
| spf_fail | 20 | 0 | 2 |
| brand_display_name | 15 | 4 | 0 |
| brand_in_domain | 15 | 1 | 1 |
| cert_hostname_mismatch | 15 | 5 | 0 |
| link_text_mismatch | 15 | 4 | 2 |
| own_org_display_name | 15 | 17 | 0 |
| raw_ip_link | 15 | 0 | 1 |
| domain_mismatch | 10 | 7 | 38 |
| domain_unresolved | 10 | 18 | 28 |
| free_hosting_link | 10 | 10 | 0 |
| spf_softfail | 10 | 4 | 25 |
| cert_new | 5 | 4 | 7 |
| dkim_none | 5 | 16 | 48 |
| dmarc_none | 5 | 35 | 23 |
| spf_none | 5 | 7 | 19 |
| tone score 3 or more (AI) | up to 20 | 40 | 6 |

## Checks that could not run

- certificate: 16 of 100 emails
- sender: 2 of 100 emails

## Time per email

Average 2.1 s, median 1.4 s, slowest 10.8 s (live lookups, one email at a time, AI tone check included, report text not).
