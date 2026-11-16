# PhishGuard-AI: recent genuine emails from our own inbox

6 genuine emails, downloaded from Gmail as .eml. They are private, so they are not in the repository and are listed by number only. The AI tone check was switched OFF for this run, so no email text left the laptop; only the normal DNS, WHOIS and certificate lookups were made.

- Safe: **6 of 6**. Wrongly flagged (Suspicious or Phishing): **0**.
- 5 of 6 score so low that they would stay Safe even if the AI gave its maximum 20 points. The others could reach Suspicious only if the AI rated their wording as manipulative.
- This is a small sample: it shows the tool does not misjudge ordinary recent mail, but it is not a measured false-positive rate.

| Email | Score (AI off) | Verdict | Red flags |
| --- | --- | --- | --- |
| inbox_01 | 0 | safe | none |
| inbox_02 | 0 | safe | none |
| inbox_03 | 15 | safe | link_text_mismatch |
| inbox_04 | 0 | safe | none |
| inbox_05 | 0 | safe | none |
| inbox_06 | 0 | safe | none |

Checks that could not run (other than the switched-off tone check): none.
