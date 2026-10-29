# Session 5: Dashboard Polish (M8) and Incident Report Export (M7)

## 1. The big picture

This session completed the user-facing presentation layer (**M8 Dashboard**) and the forensic export system (**M7 Incident Report**). It brings together all the technical modules (parser, sender check, link analysis, tone score, and scoring engine) into an intuitive web dashboard with an on-screen plain-English report and a printable/downloadable incident report.

In the PhishGuard-AI flow, M8 is the surface the user sees and interacts with. When you upload or pick an email, it runs the pipeline and displays the verdict badge, check cards, points table, and an executive incident report you can print or save as a PDF.

## 2. New terms

- **Dashboard (M8)**: the main web page where users upload emails and view graphical security results.
- **Incident Report**: a formal document detailing what an email is, what technical red flags were found, and what actions the recipient should take.
- **Executive Summary**: a high-level, non-technical overview designed for regular users or managers.
- **Forensic Evidence**: the concrete technical traces (failing SPF, mismatched domains, recent WHOIS creation dates) that prove deception.
- **Print Stylesheet (`@media print`)**: CSS rules that format a web page specifically for paper or PDF export (hiding navigation buttons, setting A4 page size).
- **Data Redaction / Masking**: replacing sensitive parts of an email address (like `s*****t@srmist.edu.in`) so private addresses aren't exposed in reports.

## 3. How it works

### Feature A: The Executive Summary on the Dashboard

**Analogy.** A doctor's diagnosis. A blood test might have complicated numbers that only a lab technician understands, but at the top of the report, the doctor writes a simple summary: "You have a bacterial infection; do not go to work, take this medicine."

**What happens.** Directly under the upload form and verdict badge, the dashboard now shows an Executive Summary with three clear sections:
1. *Summary:* what the email is pretending to be and its overall risk level.
2. *Forensic Evidence:* the plain-English explanation of which technical layers failed.
3. *Recommended Actions:* clear, numbered next steps (e.g. "Do not click links; report to IT").

**Why it matters.** Non-technical users cannot decipher DKIM cryptographic hashes or WHOIS timestamps. They need immediate, actionable advice.

### Feature B: Standalone Incident Report & PDF Export

**Analogy.** An official police FIR or inspection certificate stamped with a date, reference ID, and official verdict.

**What happens.** Users can click "Download / Print Report (PDF)" on the dashboard or visit `/report`. This opens a dedicated, beautifully formatted report page (`templates/report.html`) complete with:
- An official Report ID (e.g. `PG-20261029-152200`) and timestamp.
- Prominent color-coded verdict badge (Safe, Suspicious, or Phishing) and score out of 100.
- Redacted email headers (protecting user privacy).
- Point contribution table sorted largest-first.
- Print-ready A4 formatting with a single-click "Print / Save as PDF" button.

**Why it matters.** For organizational security, incident response teams need an exportable artifact to archive or attach to a security ticket.

### Feature C: Privacy-Preserving Recipient Redaction

**Analogy.** Black marker on sensitive court documents.

**What happens.** Before rendering the report or sending metadata, recipient email addresses are masked (e.g. `student@srmist.edu.in` becomes `s*****t@srmist.edu.in`).

**Why it matters.** Ensures student and employee email addresses are never accidentally leaked when sharing incident reports.

## 4. Walk-through example

Follow `forged_exam_cell.eml` through the dashboard:

1. **Pick Sample:** The user chooses `forged_exam_cell.eml` from the dropdown and clicks "Parse sample".
2. **Pipeline Execution:** The server parses the email, runs sender (M2), links (M3), and tone (M5) checks in parallel, and scores it with M6 (100 / 100, Phishing).
3. **Report Synthesis (M7):** The report generator produces the three text sections. Since this is an exam cell forgery, it explains that DMARC failed and the link points to a lookalike domain.
4. **Dashboard Render (M8):**
   - A bright red badge shows **PHISHING** with score **100 / 100**.
   - An Executive Summary card displays the threat description and warns the user not to enter login credentials.
   - Points breakdown shows DMARC fail (+25), Lookalike domain (+25), etc.
   - Check cards show individual status: Sender (FAIL), Links (FAIL).
5. **PDF Export:** The user clicks "Download / Print Report (PDF)". A dedicated report opens with print CSS, ready to save as an A4 PDF.

## 5. Files

- `phishguard/templates/dashboard.html`: main UI template. Shows the banner, executive summary, points grid, and check cards.
- `phishguard/templates/report.html`: standalone printable report template with A4 print styling and print button.
- `phishguard/modules/report.py`: M7 report generator. Point at `generate_report()` and `template_fallback_report()`.
- `phishguard/modules/tone.py`: M5 tone analyzer. Point at `check_tone()` and `mask_email_addresses()`.
- `phishguard/modules/llm_client.py`: unified interface for LLM calls with Nemotron and Ollama support.
- `phishguard/app.py`: Flask web application. Point at `index()`, `analyze()`, and `view_report()`.
- `phishguard/tests/test_report.py` & `test_app_report.py`: unit and route tests verifying report generation and fallback.

## 6. Viva questions

1. **What was added in Session 5?**
   Session 5 completed the dashboard (M8) and incident report generator (M7), adding on-screen executive summaries, check cards, and a standalone printable/exportable incident report with A4 styling.

2. **Why does the dashboard have both a technical points table and an executive summary?**
   Different audiences need different information. Technical examiners and security analysts want to see exact DNS and header points, while everyday users need simple plain-English instructions on whether to trust the email.

3. **How does PDF export work without installing heavy third-party binary libraries?**
   The report uses standardized CSS `@media print` and `@page { size: A4 }` rules with a one-click browser print hook (`window.print()`). This lets users save clean, pixel-perfect A4 PDFs on any operating system without complex dependencies.

4. **How are recipient email addresses protected in the report?**
   Recipient addresses are redacted (e.g. `s*****t@domain.com`) using `mask_recipient()` before the report is displayed or exported, adhering to privacy requirement PRV-2.

5. **Where does the report text come from if the computer is offline during the viva?**
   `modules/report.py` has a built-in deterministic template generator (`template_fallback_report()`) that synthesizes the exact findings into professional summary, evidence, and action text without needing internet or an AI API.

6. **What built-in demo emails are available on the dashboard?**
   Four realistic samples: `forged_exam_cell.eml` (Phishing), `genuine_college.eml` (Safe), `newsletter.eml` (Safe marketing), and `corpus_phish.eml` (Public corpus phishing).

7. **How does the dashboard communicate the final verdict?**
   Through a high-contrast color-coded badge: Green for Safe (0-29), Amber for Suspicious (30-59), and Red for Phishing (60-100), accompanied by the exact score out of 100.

8. **Can the AI report text contradict the verdict badge?**
   No. The report prompt and template generator strictly receive the M6 verdict and score as fixed constraints. The AI is only allowed to explain the verdict, never change it.

## 7. Remember this

- **M8 is the demo face of the project:** it integrates all previous modules into one unified web page.
- **The code decides; the report explains:** the verdict badge is 100% computed by M6, and the report translates that verdict for humans.
- **Printable A4 report (`/report`):** fully styled with `@media print` for single-click PDF saving.
- **100% offline-safe:** if Wi-Fi drops, the template fallback ensures the viva presentation never breaks.
