# Session 5: The Dashboard (M8) and the PDF Report (M7)

## 1. The big picture

This session turned the page into a real **dashboard** and added the **PDF report**. The page now has a big coloured verdict badge with the score, a "checking" message while it works, drag-and-drop upload, the check cards, and a full report. A **Download report (PDF)** button gives the same report as a file.

In the PhishGuard-AI flow, this is the last step. The checks, the scoring (M6) and the AI text (M5, M7) are already done. This session only **shows** the result in a clear way and packages it as a PDF. With this session, the project is complete at its main level and can be demonstrated.

## 2. New terms

- **Dashboard (M8)**: the single web page the user works with: upload, verdict, evidence, report.
- **Verdict badge**: the coloured label (green Safe, amber Suspicious, red Phishing) next to the score.
- **PDF (Portable Document Format)**: a file that looks the same on every computer. Good for sending or printing a report.
- **WeasyPrint**: a Python library that turns an HTML page into a PDF. It is the tool the PRD names.
- **HTML template**: a web page with blanks (like "score: ___") that the program fills in. Ours uses Flask's Jinja templates.
- **Partial template**: a small template that is included inside other templates. Ours is `_report.html`, used by both the page and the PDF.
- **Route**: a web address the app answers. `/analyze` runs an email. `/report.pdf` gives the PDF.
- **Token**: a long random string used as a ticket number. The PDF link carries one so the app knows which report you mean.
- **In-memory storage**: data kept in the program's working memory only. It is never saved to disk and disappears when the app stops.
- **Masking**: hiding the private part of an email address, so `student@gmail.com` becomes `***@gmail.com`.
- **A4**: the standard paper size (210 x 297 mm).
- **Lazy import**: loading a library only at the moment it is needed, so if it is missing only that one feature fails.
- **Drag-and-drop**: dragging a file from your folder onto the page instead of using a file picker.
- **Progress indicator**: a message or spinner that tells the user "I'm working, please wait".
- **HTTP 404**: the standard web reply meaning "not found".

## 3. How it works

### Feature A: the verdict banner and the check cards

**Analogy.** A hospital report. The doctor's conclusion is at the top in big letters, and the detailed test results follow below for anyone who wants them.

**What happens.** After an email is analysed, the top of the page shows a banner with the verdict badge (colour matches the verdict), the score out of 100, and the download button. Below it, one card per check (sender, links, tone) with a green, amber or red edge, listing every test, its result and its evidence.

**Why it matters.** A person should understand the answer in two seconds (red, Phishing, 100) and then be able to check **why** by reading the evidence.

### Feature B: drag-and-drop and the progress message

**Analogy.** Dropping a letter in a post box instead of walking to the counter. And a "please wait" sign while the clerk checks it.

**What happens.** The upload box accepts a dropped `.eml` file and starts the analysis right away. A file with another ending is politely refused. When any "Parse" button is pressed, the button turns into "Checking..." and a message with a small spinner appears. The checks do real internet lookups and ask the AI, so they take a few seconds.

**Why it matters.** Without the message, a user might think the page froze and click again. This is requirement FR-8.5.

### Feature C: one report, used twice

**Analogy.** A single master copy of a form, photocopied for two uses: pinned on the notice board (the web page) and handed out on paper (the PDF). Because it is the same master, the two copies can never disagree.

**What happens.** The report content lives in **one** template, `_report.html`. The web page includes it. A second tiny template, `report.html`, wraps it with the A4 page settings and is what WeasyPrint turns into the PDF. The report shows: title and the time of analysis, the verdict and score, the three plain-English paragraphs, the email details, a table of every check with its status and evidence, the points table (largest first) with the total, and a footer saying the verdict comes from fixed rules and the explanation was written by an AI. The footer sentence is written once (`_footer.html`). The page prints it under the report. The PDF prints it in the **bottom margin of every page**, like a page footer in a book, so it can never end up alone on an almost empty page.

**Why it matters.** This is requirement FR-7.5. If we had written two separate reports, a change in one would be forgotten in the other, and the examiner could catch them saying different things.

### Feature D: what is deliberately left out of the report (privacy)

**Analogy.** A hospital sends a summary to a relative, with the patient's home address blacked out and without the full medical file.

**What happens.** One function, `build_report_context()`, collects everything the report needs into a plain dictionary. It **never** includes the email body. The recipient's address is masked (`***@gmail.com`). The report also never shows links as clickable (nobody can accidentally click a phishing link from our report).

**One honest detail.** The tone check's evidence can show a **short quoted phrase** from the email (at most about 15 words, such as "verify your login credentials"). That is evidence, like a witness quoting one sentence, and it is allowed. What is never included is the **full body** of the email.

**Why it matters.** Requirements FR-7.8 and SAF-1. A phishing email may contain private text, and a PDF gets forwarded and stored. We also never open or visit any link in the email.

### Feature E: how the Download button knows which report

**Analogy.** A cloakroom ticket. You hand in your coat and get a numbered ticket. Later you show the ticket and get exactly your coat, and nobody else's.

**What happens.** When an email is analysed, the finished report (not the email itself) is stored in the app's memory under a random ticket number (the token). The Download button's address contains that token. When pressed, the app finds the report, builds the PDF from it, and sends the file named `phishguard_report_<date>_<time>.pdf`, using the time of the analysis. Only the last 20 reports are remembered, and nothing is written to disk. If the token is unknown (for example the app was restarted), the user sees a friendly "no longer available, please analyse again" message.

**Why it matters.** The PDF can be made later without storing the email or asking the user to upload it again, and the privacy rule (nothing saved on disk) still holds.

### Feature F: the PDF library can fail without breaking the page

**Analogy.** A shop's card machine breaks. You can still shop, and you are told "card payment unavailable".

**What happens.** WeasyPrint is only loaded when someone presses the PDF button. If it is not installed, or a system part (Pango) is missing, the user sees a clear message, and the dashboard and verdict still work. A crash while building a PDF also shows a plain message and not a technical error.

**Why it matters.** WeasyPrint is hard to install on some computers (especially Windows). The demo laptop might not have it, and we do not want that to break the whole tool.

### Feature G: making the AI text more accurate

**Analogy.** A student paraphrasing a textbook and accidentally adding a reason that is not in the book.

**What happens.** In real runs the AI wrote things like "DMARC failed *because the policy is none*", and "scaled to 15 points". Those are wrong or confusing. So we changed what the AI is shown: the DMARC "policy" wording and the tone arithmetic are removed from its input, and the instructions give a wrong and a right example. The AI is still never trusted, so the verdict stays rule-based and the footer says the explanation may contain mistakes.

**Why it matters.** A report with a wrong reason would look careless in a viva. Giving the AI less to misread is more reliable than only telling it to be careful.

## 4. Walk-through example

Take `forged_exam_cell.eml` (the fake exam-cell email).

1. **Analyse.** The user picks the sample and presses "Parse sample". The button changes to "Checking..." and the spinner message appears.
2. **Pipeline runs.** The sender, link and tone checks run side by side. Scoring adds 25 + 25 + 20 + 15 + 15 + 12 + 10 + 5 = 127, capped at **100**. The verdict is **Phishing**. The AI then writes three short paragraphs.
3. **Report is gathered.** `build_report_context()` collects the verdict, score, email details and check evidence. The body is not included, and the recipient `student@gmail.com` becomes `***@gmail.com`.
4. **Ticket issued.** The report is stored in memory under a random token, such as `Xk3...`.
5. **Page shows.** A red "Phishing 100 / 100" banner and a "Download report (PDF)" button. Below it: three check cards, then the report (plain-English text, email details, checks table, points table with "rows add up to 127, capped at 100"), then a "How to read the score" legend. The raw parsed email is in a collapsed section at the bottom.
6. **Download.** The user presses the button. The app finds the report by the token, renders `report.html` with WeasyPrint, and sends `phishguard_report_20261116_1348.pdf` (the analysis time). It is 2 A4 pages (a short report like the genuine sample fits on 1).
7. **What is not in the PDF.** The full email body ("Immediate action required. Your examination hall ticket...") and the full recipient address. A short quote such as "verify your login credentials" does appear, in the Tone row, as evidence.

**If the Wi-Fi is off:** the tone check says "could not run", the report text comes from a template, and the PDF is still produced. The footer says "filled in from a template".

## 5. Files

- `phishguard/app.py`: the web routes. Point at `report_pdf()` for "show me where the PDF is made" and `_remember()` for "how does the button find the report". `analyze()` runs the pipeline.
- `phishguard/modules/report.py`: point at `build_report_context()` for "what goes into the report and what is left out". `build_report_text()` is the AI text with the template fallback from session 4.
- `phishguard/templates/_report.html`: the one report body, used by the page and the PDF. It carries its own styles.
- `phishguard/templates/report.html`: a tiny wrapper that sets A4 and includes `_report.html`. This is what becomes the PDF.
- `phishguard/templates/dashboard.html`: the full page: upload box, drag-and-drop script, progress message, banner, cards, report, legend, and the collapsed technical details.
- `phishguard/requirements.txt`: now lists `weasyprint`.
- `phishguard/templates/_footer.html`: the one footer sentence, shared by the page and the PDF margin.
- `phishguard/tests/test_dashboard_pdf.py`: 24 tests. Every sample downloads a real PDF, the body and the full recipient are absent, a missing PDF library gives a clear message, and the in-memory store keeps only 20.

## 6. Viva questions

1. **What does the dashboard show, and in what order?**
   First a coloured verdict badge with the score out of 100 and the PDF button. Then one card per check with its evidence, then the full report, then the score legend. The raw parsed email details are collapsed at the bottom.

2. **How is the PDF made?**
   Our code fills in an HTML report template and WeasyPrint converts that HTML into an A4 PDF. The AI is not involved in making the PDF. It only wrote three paragraphs of text that our code places in the template.

3. **Why do the page and the PDF use the same template?**
   So they can never disagree. The report body lives in one file (`_report.html`), and the page and the PDF both include it. This is requirement FR-7.5.

4. **How does the Download button know which report to give?**
   When an email is analysed, the finished report is kept in memory under a random token, and the button's address carries it. The app looks the report up by that token. It is like a cloakroom ticket.

5. **Where is the report stored, and for how long?**
   Only in the app's memory, never on disk, and only the last 20 are kept. It disappears when the app stops. This follows our privacy rule that emails are not saved.

6. **What is left out of the PDF for privacy?**
   The full email body is never included, and recipient addresses are masked, for example `***@gmail.com`. Only short quoted phrases from the tone check (about 15 words at most) appear, as evidence. Links are shown as plain text, never as clickable links, so nobody can click a phishing link from our report.

7. **What happens if WeasyPrint is not installed?**
   It is loaded only when the PDF button is pressed. If it is missing, the user sees a clear message and the rest of the dashboard and the verdict still work.

8. **What does the progress indicator do, and why is it needed?**
   When "Parse" is pressed, the button shows "Checking..." and a spinner message appears. The checks do internet lookups and call the AI, so they take a few seconds. Without it users might think the page froze.

9. **Why is the verdict still reliable if the AI text is sometimes wrong?**
   The verdict and score come from fixed rules, and the report footer says so. The AI only explains. We also remove the details it tends to misread from its input, and we fall back to a template if its text is unusable.

10. **What did you do to show that the whole thing works?**
    Automated tests run all four sample emails end to end, download a real PDF for each, and check the PDF has no email body and a masked recipient. Everything is tested with a fake AI and fake DNS, so no test needs the internet.

## 7. Remember this

- **One template, two uses**: the page and the PDF share `_report.html`, so they always match.
- The PDF is made by **our code with WeasyPrint**. The AI only supplies three paragraphs.
- The report **never contains the full email body** (only short quoted evidence phrases), masks recipients, and shows no clickable links.
- The report is kept **in memory only**, under a random token, for the last 20 emails.
- A missing PDF library or a failed AI **never breaks the verdict page**.
