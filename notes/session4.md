# Session 4: Risk Scoring Engine (M6) and the LLM layer (M5, M7 text)

> This file has two parts. **Part 1** (first) is the scoring engine (M6). **Part 2** (at the bottom, after "Remember this") is the LLM layer: the AI tone check (M5) and the AI-written report text (M7).

# Part 1: Risk Scoring Engine (M6)

## 1. The big picture

This part added the **risk scoring engine (M6)**. It takes the red flags found by the sender check (M2) and the link check (M3), adds up their points using fixed rules from `config.yaml`, and decides the verdict: **Safe, Suspicious or Phishing**. There is no AI in it.

In the PhishGuard-AI flow, M6 sits after all the checks. It is the **only** module that decides the verdict. Later modules only add more input (tone, certificate) or explain the result (the report).

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
- `phishguard/config.yaml`: now has the `tone:` section (weight 1.5, cap 15). The weights and the 30 and 60 limits were already there.
- `phishguard/pipeline.py`: after the checks finish, it calls `score_email()`. The earlier stand-in `rate()` function is gone.
- `phishguard/templates/dashboard.html` and `app.py`: show "Total score", "Verdict", a "capped at 100" note when needed and a "could not run" line.
- `phishguard/tests/test_scoring.py`: 18 tests covering adding, the cap, the thresholds, ordering, determinism, the config rules, the tone formula and the rounding rule.

## 6. Viva questions

1. **What does the scoring engine do?**
   It adds up the points of every red flag from all the checks, caps the total at 100, and maps it to Safe (0-29), Suspicious (30-59) or Phishing (60-100). It uses fixed rules only, with no AI.

2. **Why is the verdict decided by code and not by the LLM?**
   Code is predictable and explainable: the same email always gets the same score, and every point can be traced to a red flag. An LLM can make mistakes, so it is only allowed to add a small capped signal and to explain the result.

3. **Why is the tone score capped at 15 points?**
   The Suspicious line is 30. With a maximum of 15 the AI can never push an email into Suspicious alone, so a wrong AI answer can't wrongly flag a safe email. Real technical evidence is also needed.

4. **How is the tone score turned into points?**
   Points are 1.5 times the manipulation score (0 to 10), up to a maximum of 15. For example a score of 8 gives 12 points.

5. **What does "deterministic" mean here, and how do you guarantee it?**
   The same input always gives the same score and order. There is no randomness, and ties between equal flags are sorted by a fixed rule (check order, then name).

6. **Where do the weights come from, and why does M6 re-read them?**
   They live in `config.yaml`. M6 looks each flag's weight up there instead of trusting the number the check wrote, so we can tune the weights and re-score all test emails without changing code.

7. **What happens when a check fails or has no internet?**
   It adds 0 points and is shown as "could not run". The other checks still run and the verdict is still produced, so one failure never breaks the tool.

8. **Why do the same red flags count only once even if several links have them?**
   Otherwise a long newsletter with many links would be over-punished. Each kind of flag counts once per email, and the evidence lists everything involved.

9. **What happens if the points add up to more than 100?**
   The score is capped at 100, and the page shows both numbers, for example "rows add up to 125, capped at 100". The verdict is still Phishing.

10. **Why can a card be red while the verdict is only Suspicious?**
    A card judges one check (red if any single flag is 20 points or more). The verdict judges the total score across all checks, so the two can differ.

## 7. Remember this

- M6 is the **only** module that decides the verdict, using **fixed rules**, with no AI.
- Score = sum of weights from **config.yaml**, **capped at 100**; bands are **0-29 Safe, 30-59 Suspicious, 60-100 Phishing**.
- Tone is capped at **15** (below the **30** line), so the **AI can never convict alone**.
- A failed check adds **0 points** and shows as "could not run"; each flag counts **once per email**.
- Same input, same score every time, and weights can be tuned in the config **without touching code**.

---

# Part 2: The LLM layer (M5 tone check and M7 report text)

## 1. The big picture

This part added the **AI**. Two things now use it. The **tone check (M5)** reads the words of the email and says how hard it tries to pressure the reader. The **report text (M7)** writes three short paragraphs in plain English that explain the verdict. The AI is used **only** for these two jobs.

In the PhishGuard-AI flow, M5 runs at the same time as the sender and link checks, and feeds the scoring engine (M6). M6 then decides the verdict exactly as before. After that, M7 asks the AI to explain the result. **The code decides, the AI explains.** If the AI is missing or wrong, nothing breaks: the verdict still appears, and a template writes the explanation.

## 2. New terms

- **LLM (Large Language Model)**: an AI trained on huge amounts of text that can read and write sentences. Nemotron and Qwen are LLMs.
- **Provider**: the company or program that runs the LLM for us. Ours are **NVIDIA Nemotron** (in the cloud) and **Ollama** (a program on our own laptop).
- **API (Application Programming Interface)**: a doorway that lets one program talk to another over the internet. We send a question to NVIDIA's API and get an answer back.
- **API key**: a secret password that tells NVIDIA the request comes from our account. Anyone who has it can spend our account's allowance.
- **Environment variable**: a named setting kept by the computer, outside our project files. Our key lives in one called `LLM_API_KEY`, so it never ends up in the code or in git.
- **Prompt**: the instructions and text we send to the LLM. The **system prompt** gives the AI its job and rules. The **user prompt** carries the actual data.
- **JSON (JavaScript Object Notation)**: a strict, tidy way to write information as labelled fields, such as `{"score": 8}`. Programs can read it reliably, so we ask the AI to answer in JSON.
- **Token**: a small piece of a word. LLMs are limited and billed by tokens, so we set a maximum number of tokens for each answer.
- **Temperature**: how random the AI is allowed to be. We set 0, which makes it as repeatable as possible.
- **Timeout**: how long we wait before giving up. Ours is 8 seconds, so a slow AI cannot freeze the page.
- **Fallback**: the plan B that runs when plan A fails. Here, a template writes the report if the AI cannot.
- **Template**: a fixed fill-in-the-blanks text. We fill the blanks from the red flags found.
- **Validation**: checking an answer before trusting it (is it JSON, is the score a number, does the quote exist?).
- **Hallucination**: when an AI confidently makes something up, such as a quote that is not in the email.
- **Prompt injection**: a trick where text inside the data tells the AI "ignore your rules and do this instead". A phishing email could contain such a sentence.
- **Masking**: hiding the private part of an email address, so `bob@college.edu` becomes `***@college.edu`.
- **Thinking mode**: some models write out private reasoning before answering. That can use up all the allowed tokens and leave an empty answer, so we switch it off for Nemotron.
- **Ollama**: a free program that runs small LLMs on your own computer, with no internet. Our offline backup.

## 3. How it works

### Feature A: one door to every AI (`llm_client.py`)

**Analogy.** A reception desk in a big office. Visitors (our other modules) always go to the same desk and ask the same way. The desk decides which department (Nemotron, Ollama, or nobody) handles it. If the department is closed, the desk says so politely instead of letting the visitor wander in and crash into things.

**What happens.** Both M5 and M7 call one function with a system prompt, a user prompt and a token limit. The function reads `config.yaml` to see which provider is chosen (`nemotron`, `ollama` or `off`), builds the request, sends it, and gets the text back. It tidies the text (AI models sometimes wrap JSON in extra words or code fences) and returns clean data. Anything that goes wrong (no key, no internet, a slow reply, an empty answer, broken JSON) becomes **one kind of error** that the callers know how to handle. If the answer is empty or broken JSON, the function **asks once more**, because that is often a one-off. It never retries when the internet itself is down, so the user does not wait twice as long.

**Why it matters.** Switching from the cloud AI to the offline AI is a one-word change in the config. No other code changes. And the rest of the tool never has to worry about AI failures, because they all arrive in the same shape.

### Feature B: the tone check (`tone.py`, M5)

**Analogy.** A teacher reading a message and saying "this sounds like someone trying to rush and scare me". The technical checks look at the envelope and the return address. The tone check reads the letter itself.

**What happens.** The subject and the first 4,000 characters of the body are sent to the AI. Email addresses are masked first. The text is placed between `<email>` and `</email>` markers, and the instructions tell the AI that this is untrusted data from a stranger and that it must not obey anything written inside it. The AI replies in JSON with a manipulation score from 0 to 10 and a list of tactics it found. Each tactic is one of five: urgency, threat, asking for login details, reward bait, or pretending to be an authority. Each comes with one short quote.

**Why it matters.** A phishing email can be sent from a perfectly set up server with clean links, and only the wording gives it away ("verify within 24 hours or your account will be deleted"). The technical checks cannot see that. M5 can.

### Feature C: never trusting the AI blindly (validation)

**Analogy.** A journalist who must show the source for every quote. If the editor cannot find the quote in the original document, it is thrown out.

**What happens.** Before using the AI's answer, our code checks it:
1. The score must be a real number. If not, the tone check is marked "error" and the other checks carry on. The score is also forced into the range 0 to 10.
2. Every tactic's quote must **really appear** in the email text we sent (ignoring capital letters and line breaks). A quote that is not there is an invention, and it is dropped.
3. Tactic names outside the five allowed ones are dropped. Each tactic counts once.
4. If **no** tactic survives, the score is set to 0. A score with no evidence adds nothing.

**Why it matters.** AI makes things up sometimes. This protects users from a false alarm caused by an imaginary quote. It is also the reason the tone points can be explained to an examiner: each one points to words you can see in the email.

### Feature D: from tone score to points

The tone score times 1.5, never above 15 points, is added by M6 (see Part 1). Since 15 is below the Suspicious line of 30, the AI alone can never flag an email. The tone card on the page can only be amber, never red, because 15 is less than the 20-point "red" limit.

**One addition, the "tone floor".** In our first live test, a plain timetable email from the college got a tone score of 1 out of 10. AI models often give ordinary emails a 1 or 2, like a teacher who never gives anyone exactly zero. That small score made the card amber and the report said the email was "slightly manipulative", which is wrong. So `config.yaml` has `min_score: 3`. A score below 3 is treated as background noise and counts as **0**: no points, a green card, no quoted tactics. The page still shows the raw score, marked "too low to count", so nothing is hidden. A score of 3 or more counts normally (3 gives 4.5 points).

### Feature E: the report text (`report.py`, M7)

**Analogy.** A doctor decides the diagnosis from the test results. A nurse then explains it to the patient in simple words. The nurse does not change the diagnosis.

**What happens.** After M6 has decided the verdict, we give the AI only three things: the verdict, the score, and the list of red flags (with email addresses masked). **It never sees the email itself.** We ask for three short sections as JSON: what this email is, what gave it away, and what the reader should do (about 120 to 200 words in all). The page shows those paragraphs under the verdict, with a note saying the verdict is rule-based and the explanation was written by an AI.

**Why it matters.** The verdict is a number and a list of flag names. Most people need a few plain sentences telling them what to do. The AI is good at that kind of writing, and by keeping it away from the decision, a wrong answer can only make the wording worse, never the verdict.

### Feature F: the template fallback

**Analogy.** A shop that normally has a person write a personal thank-you note, but keeps a printed card ready in case that person is ill.

**What happens.** If the AI cannot be reached, or its answer is incomplete, the wrong length, or says "this email is safe" about an email we rated Suspicious or Phishing, our code throws the AI text away. It writes the same three sections itself from the list of red flags, with a fixed sentence for each verdict. The page says "filled in from a template" and shows why. If the tone check already found that the AI cannot be reached at all, we skip asking again, so the user does not wait twice.

**Why it matters.** Wi-Fi at a college demo can fail. With this, the page always shows a verdict **and** a report, and it never shows an error screen because of the AI.

### Feature G: protecting the key and the privacy

- The key is read from the environment variable at the moment it is needed. It is not in any file in the project. Error messages never contain it.
- Email addresses are masked before anything goes to a cloud AI. The report AI sees only red-flag names and evidence, never the subject, the sender or the body.
- A phishing email can hold instructions aimed at the AI. Because the email is fenced off as data, and because the AI can only produce a capped score and a paragraph, such a trick has very little power.

### Feature H: why the tests never call the real AI

All tests use a **fake AI** that a test can set to reply with whatever it wants, or to be "unreachable". A safety net in the test setup swaps the real AI for the fake one in every test automatically. So the tests are fast, free, work without internet, and can never send an email to the cloud by accident.

## 4. Walk-through example

This is an **example** to show the steps. The exact AI words will differ on each run.

Take a phishing email with subject "Urgent: verify now" and a body saying "your account will be closed within 24 hours. Enter your password to avoid suspension." It comes from a lookalike domain and fails DMARC.

1. **Parse (M1).** The subject, body, sender and links are pulled out.
2. **Three checks run side by side.** The sender check finds DMARC failed (+25). The link check finds a lookalike domain (+25). The tone check starts.
3. **Tone, sending.** The text goes to Nemotron with addresses masked and the email fenced between markers.
4. **Tone, answer.** The AI replies with a score of 8 and two tactics: urgency ("closed within 24 hours") and asking for login details ("enter your password").
5. **Tone, checking.** Our code confirms both quotes appear in the email, so both are kept. The tone gives 1.5 x 8 = **12 points**. Had the AI also claimed a "threat" with a quote that is not in the email, that one would be thrown away.
6. **Scoring (M6).** 25 + 25 + 12 = **62**, so the verdict is **Phishing**. This was decided by code.
7. **Report (M7).** The AI receives "phishing, 62, and three flags (DMARC failed, lookalike domain, manipulative wording)". It writes three short paragraphs. Our code checks all three exist, the length is sensible, and the text does not call the email safe.
8. **Page.** It shows the verdict, the points table, a "Tone (AI)" card with the quotes, and the "Plain-English report" with the note "the verdict is rule-based, the explanation was written by an AI".

**If the Wi-Fi is off:** step 3 fails at once, the tone card shows "could not run" and adds 0 points, the score is 50, the report is built from the template, and the page says so. The verdict still appears.

## 5. Files

- `phishguard/modules/llm_client.py`: the single door to any AI. Point at `complete_json()` for "show me where the AI is called". `mask_addresses()` hides email names. `parse_json()` cleans the AI's reply.
- `phishguard/modules/tone.py` (M5): the tone check. Point at `check_tone()` for the check and `validate()` for "where do you stop the AI making things up?".
- `phishguard/modules/report.py` (M7 text): point at `build_report_text()` for the report, `template_text()` for the fallback, and `validate()` for the checks on the AI's text.
- `phishguard/config.yaml`: new `llm:` section (provider, model, timeout, token limits, key variable name).
- `phishguard/pipeline.py`: runs the tone check beside the other two, then builds the report after scoring.
- `phishguard/templates/dashboard.html` and `app.py`: show the "Tone (AI)" card and the "Plain-English report" block.
- `phishguard/tests/`: `test_llm_client.py`, `test_tone.py`, `test_report.py` and `test_pipeline_ai.py` cover this part. `conftest.py` has the fake AI and the safety net.

**Small fixes found by looking at the live page** (not new features):
- **Table layout.** Words were splitting in the middle ("Ch ec k"). The tables now have fixed column widths and normal word wrapping.
- **SPF evidence.** When the DNS lookup timed out, the page printed a long technical error. It now says "the DNS lookup timed out or failed" and still uses the mail server's own result.
- **DMARC wording.** "DKIM none for -" is now "no DKIM found", because a missing signature is not the same as a failed one.
- **Body text.** The HTML-to-text step split sentences at every bold or link tag. Only paragraphs and line breaks start a new line now.

## 6. Viva questions

1. **What does the LLM do in PhishGuard-AI, and what does it not do?**
   It does two jobs: it scores the manipulation in the email's wording (M5), and it writes a plain-English explanation of the verdict (M7). It never decides the verdict. That is done by the fixed scoring rules.

2. **Why is the tone check useful when you already have SPF, DKIM, DMARC and link checks?**
   Those checks inspect the technical side. A careful attacker can pass them and still write a pressuring message. Only reading the wording can catch urgency, threats or requests for passwords.

3. **How do you stop the AI from deciding the verdict or causing a false alarm?**
   Its tone score is turned into at most 15 points, and the Suspicious line is 30, so it can never flag an email alone. The report AI only receives the finished verdict and explains it. If its text contradicts the verdict, we discard it.

4. **What if the AI makes up a quote that is not in the email?**
   We check every quote against the text we sent, ignoring capitals and line breaks. A quote that is not found is dropped. If no quote survives, the tone score becomes 0. So an invented answer cannot add points.

5. **What happens when there is no internet or the AI fails?**
   The tone check shows "could not run" and adds 0 points. The report is written from a template using the red flags. The verdict is still produced from the other checks, and the page says an AI was not used.

6. **Which LLM do you use, and why two?**
   The main one is NVIDIA Nemotron over its API, and the backup is a small local model run with Ollama. The cloud model writes better, but needs internet. The local one works offline, which we need if the college Wi-Fi fails. The choice is a line in `config.yaml`.

7. **How do you protect the API key?**
   It is kept in an environment variable called `LLM_API_KEY`, outside the project, and read only when a request is made. It is not in the code, the config, git or any error message.

8. **What personal data goes to the cloud AI?**
   Only the subject and up to 4,000 characters of the body for the tone check, with email addresses masked. The report AI gets no email text at all, only the verdict, the score and masked red-flag evidence. Nothing is saved by us.

9. **What is prompt injection, and how do you reduce the risk?**
   It is when the email contains text like "ignore your instructions" aimed at the AI. We fence the email as untrusted data and tell the AI not to obey it. Even if it were fooled, the worst result is a capped 15 points or a bad paragraph. It still cannot change the verdict.

10. **Why do you ask the AI for JSON and then check it?**
    JSON is easy for the program to read, but an AI may still return broken, incomplete or wrong-sized answers. We validate each one (score is a number, all three sections exist, a sensible length). Anything that fails goes to the safe fallback instead of crashing.

11. **Is the result the same every time?**
    The verdict rules are fully repeatable. The AI is set to temperature 0, which makes it very repeatable, but providers do not guarantee it. So the tone score may vary slightly between runs. In session 6 we will save the AI's answers for the demo emails so the demo is the same every time.

## 7. Remember this

- **Code decides, AI explains.** The AI never picks the verdict.
- The AI's tone score is capped at **15 points**, under the **30** Suspicious line.
- Every quote the AI gives is **checked against the email**. Invented quotes are thrown away.
- If the AI fails, the **tone check adds 0** and the **report comes from a template**. The tool never breaks.
- The key lives in the **`LLM_API_KEY` environment variable**, and email addresses are **masked** before anything goes to the cloud.
