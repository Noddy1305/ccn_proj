# Session 4: Risk Scoring Engine (M6), LLM Tone Analysis (M5), and Report Generator (M7)

## 1. The big picture

This session added the complete reasoning and explanation layer:
1. **The scoring engine (M6):** takes red flags found by all checks, adds up points from `config.yaml`, and decides the verdict (Safe, Suspicious, or Phishing).
2. **The tone analyzer (M5):** asks an LLM (NVIDIA Nemotron or Ollama) to read the email wording for artificial urgency, threats, and trickery, returning a manipulation score (0 to 10) capped at 15 points.
3. **The report generator (M7):** produces a plain-English explanation of why the email was flagged, what evidence was found, and what the reader should do. If the LLM is offline, a deterministic template fills these fields automatically.

In the PhishGuard-AI flow, M5 runs alongside the sender and link checks. Then M6 decides the verdict. Then M7 explains M6's decision. **The code decides; the AI explains.**

## 2. New terms

- **M1, M2, ... M8 (Module)**: the PRD numbers the project's building blocks. M1 = email parser, M2 = sender check, M3 = link and domain check, M4 = certificate check, M5 = tone analysis (AI), M6 = risk scoring engine, M7 = report generator, M8 = dashboard. The number also matches the file in `modules/` (for example `scoring.py` is M6).
- **Score**: the total number of risk points for one email, from 0 to 100. Higher means riskier.
- **Weight**: how many points one kind of red flag is worth (for example DMARC fail = 25).
- **Contribution**: one red flag that actually added points to the score.
- **Cap**: a ceiling. The score never goes above 100, and the AI's tone points never go above 15.
- **Threshold / band**: the score limits that separate the verdicts: 0-29 Safe, 30-59 Suspicious, 60-100 Phishing.
- **Verdict**: the final label (Safe, Suspicious or Phishing).
- **Deterministic**: the same email always gives exactly the same score. No randomness.
- **Tie-break**: a fixed rule for ordering things that are equal, so the order never changes between runs.
- **Rounding rule**: halves round **up** (29.5 becomes 30).
- **LLM (Large Language Model)**: an AI that reads and writes text. It is not built yet, but M6 already has a slot for its tone score.
- **Provisional**: "for now". The verdict will be refined as more checks are added.

## 3. How it works

### Feature A: adding up the points

**Analogy.** A teacher marking an exam in reverse: every mistake costs marks, and the total shows how bad the paper is. Each red flag is a mistake with a fixed price from a price list (the config file).

**What happens.** M6 collects every red flag from every check, looks up its price in `config.yaml`, and adds them. The total is capped at 100. Contributing flags are listed **largest first**, so the page shows the biggest reason at the top.

**Why it matters.** The page can show exactly why an email got its score, and an examiner can add the numbers up by hand.

### Feature B: the verdict bands

**Analogy.** Traffic lights. Green up to 29, amber from 30 to 59, red from 60 up.

**What happens.** The final score is compared with two limits in `config.yaml` (30 and 60). If the rows add up to more than 100, the page shows both numbers, such as "rows add up to 125, capped at 100", so the table never looks wrong. Halves round up, so a 29.5 becomes 30 and is Suspicious. This is always the same, with no surprises at the line.

**Why it matters.** Safe, Suspicious and Phishing mean different advice: carry on, be careful, or do not touch.

### Feature C: fairness rules

- **Each red flag counts once per email**, even if several links share it, so a long newsletter isn't over-punished.
- **A check that crashed or couldn't run adds 0 points** and appears as "could not run" under the table. Missing information is never treated as guilt.
- **It works with any set of checks.** With only some checks built, the maximum reachable score is simply lower. Certificate and tone checks can be added later without changing M6.

### Feature D: the weights are re-read from the config file

**Analogy.** A shop's price list pinned to the wall. A checkout till doesn't trust the price stickers on each item; it looks up the price list.

**What happens.** Each check already writes a points number on its red flags, but M6 ignores it and looks the weight up in `config.yaml` by the flag's name. A flag the config doesn't know keeps the points the check gave it.

**Why it matters.** In session 7 we will tune the weights once, using the 100 test emails. Because M6 re-reads the config, we can change a number there and re-score everything without editing any code.

### Feature E: the AI's tone score is capped at 15 (slot ready, M5 not built yet)

**Analogy.** An expert witness in court may give an opinion, but the judge, not the witness, decides the case. The AI may raise a flag, but it can never decide.

**What happens.** When the tone check exists it will give a manipulation score from 0 to 10. M6 turns it into points by multiplying by 1.5, never above 15. A score of 8 gives 12 points. A score of 10 gives 15.

**Why 15?** The Suspicious line is at 30. Even a perfect 10 only gives 15, which is **half** of what's needed. So an email can never be marked suspicious by the AI alone; it needs real technical red flags too. (Said another way: the AI's maximum is below the first warning line, so a wrong AI answer can't turn a safe email into a flagged one.)

M6 already handles this and is tested with made-up tone scores, but the real tone check (M5) is not built yet, so today the tone adds 0 points.

### Card colour vs verdict (a reminder)

The coloured **cards** judge **one check each**: red if any single flag there is worth 20 points or more. The **verdict** judges the **total**. They can differ: the sender card can be red while the verdict is only Suspicious.

## 4. Walk-through example

Four emails through M6:

1. **`forged_exam_cell.eml`.** Sender flags: DMARC fail 25, no SPF 5, no DKIM 5, mismatch 10 = 45. Link flags: lookalike 25, text mismatch 15, raw IP 15 = 55. Together 100, so the verdict is **Phishing**. The table lists them largest first, starting with the 25s.
2. **`corpus_phish.eml`.** Sender: no SPF, DKIM, DMARC = 15. Links: domain does not resolve = 10. Total **25**, below 30, so **Safe** for now. The tone check, when built, would add up to 15 more.
3. **Your real YouTube email.** No red flags at all, so the total is **0** and the verdict is **Safe**.
4. **Made-up cases to show the rules.**
   - Flags worth 125 in total show as "125, capped at 100".
   - A sender score of 25 plus tone of 3 gives 4.5 points, total 29.5, which rounds up to 30: **Suspicious**.
   - Tone 8 gives 12 points. Tone alone, even at 10, gives only 15: **Safe**.

## 5. Files

- `phishguard/modules/scoring.py`: the whole M6. Point at `score_email()` for "show me where the score is calculated". `verdict_for()` maps the score to Safe, Suspicious or Phishing. `points_for()` looks a weight up in the config. `tone_points()` is the capped tone formula. `BANDS` holds the legend text for the page.
- `phishguard/modules/llm_client.py`: unified interface for calling LLMs (NVIDIA Nemotron or Ollama) using an API key from `LLM_API_KEY`.
- `phishguard/modules/tone.py`: M5 tone analyzer. Point at `check_tone()`. Masks email addresses (PRV-2), calls LLM, and calculates capped tone points.
- `phishguard/modules/report.py`: M7 report generator. Point at `generate_report()`. Creates summary, evidence explained, and recommended actions using LLM with deterministic template fallback (FR-7.4).
- `phishguard/config.yaml`: has the `tone:` section (weight 1.5, cap 15) and `llm:` provider configuration.
- `phishguard/pipeline.py`: runs sender (M2), links (M3), and tone (M5) in parallel, then calls `score_email()` (M6), then `generate_report()` (M7).
- `phishguard/templates/dashboard.html` and `app.py`: show the on-screen executive summary, check cards, points breakdown, and link to full report.
- `phishguard/tests/test_scoring.py`: 18 tests covering scoring logic.
- `phishguard/tests/test_tone.py` & `test_report.py`: unit tests for M5 and M7 with offline fallbacks.

## 6. Viva questions

1. **What does the scoring engine (M6) do?**
   It adds up the points of every red flag from all the checks, caps the total at 100, and maps it to Safe (0-29), Suspicious (30-59) or Phishing (60-100). It uses fixed rules only, with no AI.

2. **Why is the verdict decided by code and not by the LLM?**
   Code is predictable and explainable: the same email always gets the same score, and every point can be traced to a red flag. An LLM can make mistakes, so it is only allowed to add a small capped signal and to explain the result.

3. **How does the tone check (M5) work, and how are user privacy and offline reliability protected?**
   The tone check masks all email addresses before sending the text to the LLM (PRV-2). If the LLM is unreachable or has no internet, it returns an "error" status that adds 0 points and never breaks the pipeline (NFR-3).

4. **Why is the tone score capped at 15 points?**
   The Suspicious line is 30. With a maximum of 15 the AI can never push an email into Suspicious alone, so a wrong AI answer can't wrongly flag a safe email. Real technical evidence is also needed.

5. **How does M7 generate the report, and what happens if the AI is offline?**
   M7 takes the verdict, score, and findings list (not the raw email). If the LLM is online, it writes the summary, evidence, and actions. If offline or invalid, a deterministic template fills these fields automatically (FR-7.4).

6. **What does "deterministic" mean here, and how do you guarantee it?**
   The same input always gives the same score and order. There is no randomness, and ties between equal flags are sorted by a fixed rule (check order, then name).

7. **Where do the weights come from, and why does M6 re-read them?**
   They live in `config.yaml`. M6 looks each flag's weight up there instead of trusting the number the check wrote, so we can tune the weights and re-score all test emails without changing code.

8. **What happens when a check fails or has no internet?**
   It adds 0 points and is shown as "could not run". The other checks still run and the verdict is still produced, so one failure never breaks the tool.

9. **Why do the same red flags count only once even if several links have them?**
   Otherwise a long newsletter with many links would be over-punished. Each kind of flag counts once per email, and the evidence lists everything involved.

10. **What happens if the points add up to more than 100?**
    The score is capped at 100, and the page shows both numbers, for example "rows add up to 125, capped at 100". The verdict is still Phishing.

## 7. Remember this

- M6 is the **only** module that decides the verdict, using **fixed rules**, with no AI.
- The LLM **adds one small capped signal (M5, max 15 pts)** and **explains the verdict (M7)**.
- If offline, M5 adds 0 points and M7 falls back to a **deterministic rule template** (100% demo-safe).
- Score = sum of weights from **config.yaml**, **capped at 100**; bands are **0-29 Safe, 30-59 Suspicious, 60-100 Phishing**.
- Tone is capped at **15** (below the **30** line), so the **AI can never convict alone**.
