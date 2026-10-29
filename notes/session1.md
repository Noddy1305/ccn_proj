# Session 1 Notes — Setup and Email Parser (M1)

## 1. The big picture

This session built the project folder, a Python virtual environment, a small web page, and the **email parser (M1)**. The parser takes one saved email file and splits it into labelled pieces: who sent it, which server it came from, what links it holds, and what it says. It does **not** decide if the email is good or bad.

In the PhishGuard-AI flow, M1 is the very first step. Every later check (sender, links, certificate, tone) reads the pieces M1 produces, so if M1 is wrong, everything after it is wrong.

## 2. New terms

- **M1, M2, ... M8 (Module)**: the PRD numbers the project's building blocks. M1 = email parser, M2 = sender check, M3 = link and domain check, M4 = certificate check, M5 = tone analysis (AI), M6 = risk scoring engine, M7 = report generator, M8 = dashboard. The number also matches the file in `modules/` (for example `parser.py` is M1).
- **Email header**: the labelled lines at the top of an email (From, To, Subject, Date). Like the writing on an envelope.
- **Email body**: the actual message text, like the letter inside the envelope.
- **.eml file**: the standard file format for one saved email, headers and body together.
- **MIME (Multipurpose Internet Mail Extensions)**: the format that lets one email hold several parts, such as plain text, HTML and attachments.
- **From**: the sender address shown to you. It is just typed text, so anyone can fake it.
- **Reply-To**: where your reply goes. A scammer can set it to a different address from From.
- **Return-Path**: where failure notices ("bounces") go. It shows the real technical sender.
- **Message-ID**: a unique serial number the sending server gives each email.
- **Received header**: a stamp added by every mail server that handles the email. Like postmarks on a parcel.
- **IP (Internet Protocol) address**: the numeric address of a machine on the internet, like 185.234.72.19.
- **Public vs private IP**: public addresses are visible on the internet. Private ones (10.x.x.x, 192.168.x.x) only exist inside one network.
- **DKIM-Signature (DomainKeys Identified Mail)**: a digital signature header that proves the email was not changed. Checked in session 2.
- **Authentication-Results**: a header the *receiving* server adds, saying whether SPF, DKIM and DMARC passed. Used in session 2.
- **HTML (HyperText Markup Language)**: the language for formatted emails and web pages.
- **href**: the real web address hidden behind a clickable link.
- **Link text**: the words you see on a link. It can show one address while the href goes somewhere else.
- **Flask**: a small Python tool for building web pages.
- **Virtual environment (venv)**: a private box of Python libraries for this project only.
- **BeautifulSoup**: a Python library that reads HTML and pulls out parts such as links and text.

## 3. How it works

### Feature A: splitting the email into parts

**Analogy.** Think of a parcel arriving at your home. The envelope has a "From" label, a "To" label, and several postmarks. Inside is a letter. The parser is a clerk who opens the parcel and writes each label and the letter text onto a neat form. The clerk never says whether the parcel is dangerous. They just copy things down.

**What happens.** The code reads the file bytes and uses Python's built-in `email` library to split headers from body. It copies out From (name and address), Reply-To, Return-Path, To, Subject, Date and Message-ID. Addresses are made lowercase so later comparisons are fair.

**Why it matters.** Phishers often make From say `examcell@srmist.edu.in` while Reply-To or Return-Path point somewhere else. We can only spot that if the pieces are separated first.

### Feature B: finding the sending server's IP

**Analogy.** A parcel gets a postmark at every sorting office. The *first* postmark, at the bottom of the pile, shows where it truly began. Later postmarks only show the middle of the trip.

**What happens.** Every mail server stamps a `Received` line on top of the others, so the newest is first and the oldest is last. The code walks from the **bottom** up and picks the first **public** IP address. It skips private addresses (like 10.0.0.5) because those are internal and tell us nothing about the outside sender.

**Why it matters.** SPF (session 2) asks "was this IP allowed to send for this domain?" For that we need the real sender's IP, not an internal hop.

### Feature C: extracting links as (text, destination) pairs

**Analogy.** Imagine a sign saying "Visit our bank" but the arrow underneath points to a stranger's house. What you read and where you are sent can differ.

**What happens.** For HTML emails, BeautifulSoup finds each `<a>` tag and records the visible words and the real `href`. For plain-text emails, any `http(s)://` address is recorded with the text equal to the address. The code only reads this text. It **never opens or visits** the link (rule SAF-1).

**Why it matters.** The classic trick is a link that *shows* `www.srmist.edu.in` but *goes to* a scam site. Session 3 compares the two. That is only possible because M1 saved both.

### Feature D: getting the body text

**Analogy.** Some letters come in fancy print and a plain copy. We prefer the plain copy. If there is only the fancy one, we copy its words by hand and ignore the decoration.

**What happens.** The parser takes the plain-text part if it exists. If only HTML exists, it strips the tags and scripts and keeps the words. It also records which way the body was obtained.

**Why it matters.** The tone check (session 4) needs clean words to judge pressure tactics like "urgent" or "cancelled in 24 hours".

### Feature E: attachments and bad files

**Analogy.** A security guard reads the label on a package but does not open it.

**What happens.** Attachments are listed by file name and type only, never opened (SAF-2). If the uploaded file is empty, bigger than 5 MB, or has no From header plus a Date, Subject or Message-ID, the parser refuses it with a clear message instead of crashing.

**Why it matters.** It keeps the tool safe and stops random files breaking later steps.

### Feature F: the Flask page

**Analogy.** A reception desk where you hand in an envelope and get back the filled-in form.

**What happens.** You open the page, choose a .eml file (or one of the built-in samples), press Parse, and the page lists all parsed fields. The file is kept in memory only and is not saved (PRV-1).

**Why it matters.** It gives us something to show an examiner right away, and it is the base for the full dashboard in session 5.

## 4. Walk-through example

We follow the sample `forged_exam_cell.eml`, a fake "SRM Exam Cell" email.

1. **Upload.** The file is read as raw bytes. It is under 5 MB and has a From and Subject, so it is accepted.
2. **Headers.** From = SRM Exam Cell, `examcell@srmist.edu.in`. Reply-To = `exam-help@srmlst-verify.com`. Return-Path = `bounce@srmlst-verify.com`. Subject = "URGENT: Your hall ticket will be cancelled in 24 hours".
3. **Received chain.** Two hops are found. The bottom one has the private address 10.0.0.5 and is skipped. The top one has 185.234.72.19, which is public, so that becomes the **sending IP**.
4. **Authentication headers.** The server's note says SPF failed and DMARC failed. M1 only stores this text for session 2.
5. **Links.** Link 1 shows `https://www.srmist.edu.in/hallticket` but really goes to `http://srmlst.edu.in.verify-login.com/portal`. Link 2 is "our backup portal" going to the raw IP `http://203.0.113.50/login`. Both are saved as pairs.
6. **Body.** The email was HTML only, so the tags are stripped and the readable text remains, marked "html-converted".
7. **Output.** The page shows all of this in tables. No verdict appears, because judging is for later sessions.

## 5. Files

- `CLAUDE.md` (project root): the rules we follow every session, including how to write these notes.
- `phishguard/modules/parser.py`: the M1 parser. Point at `parse_eml()` for "show me where the email is split up". Point at `find_sending_ip()` for the IP logic. `_extract_links()` is where link text and href are paired.
- `phishguard/app.py`: the Flask app. Point at `analyze()`, which takes an upload or sample and calls the parser.
- `phishguard/templates/dashboard.html`: the page that shows the parsed fields.
- `phishguard/config.yaml`: settings. For now only the upload limit and port.
- `phishguard/data/samples/`: four demo emails (forged exam cell, genuine college, newsletter, corpus-style phishing with an attachment).
- `phishguard/tests/`: automatic tests (`test_parser.py`, `test_app.py`) and hand-made fixture emails.
- `phishguard/requirements.txt`: list of libraries to install.
- `phishguard/venv/`: the virtual environment (not committed to Git).

## 6. Viva questions

1. **What does M1 do, and does it decide whether an email is phishing?**
   It splits a raw .eml file into labelled parts: headers, sending IP, links and body. It makes no judgement. Deciding is done later by the checks and the scoring engine.

2. **Why can't we trust the From address?**
   The From line is just text the sender types, so anyone can write any address there. That is why we look at technical evidence such as the sending IP and SPF/DKIM/DMARC.

3. **How do you find the sending server's IP?**
   Each mail server adds a Received line on top, so the oldest is at the bottom. We read from the bottom up and take the first public IP, skipping private ones like 10.x.x.x. That is the first external hop.

4. **Why skip private IP addresses?**
   Private addresses only work inside one internal network and say nothing about who sent the email from the internet. SPF needs the public address.

5. **What is the difference between link text and href?**
   Link text is what the reader sees; href is where the link really goes. Phishers show a trusted name but hide a different destination, so we store both to compare later.

6. **Do you ever open or click the links?**
   No. We only read the text of the email. Opening links could run malicious scripts, so the tool never visits a page (rule SAF-1).

7. **What do you do with attachments?**
   We only list their name and type and never open them (SAF-2). Scanning attachments for malware is outside this project's scope.

8. **How does the parser handle an HTML-only email?**
   It uses BeautifulSoup to remove tags and scripts and keeps the readable text. It also marks the body as "html-converted" so we know where it came from.

9. **What happens if someone uploads a random file?**
   The parser rejects it with a clear message if it is empty, over 5 MB, or lacks a From header with a Date, Subject or Message-ID. It never crashes.

10. **Why a virtual environment?**
    It keeps this project's libraries separate from the rest of the laptop, so versions do not clash and anyone can recreate the setup from requirements.txt.

## 7. Remember this

- M1 only **splits and labels**; it never judges.
- The sending IP is the **first public hop**, found by reading Received headers **bottom to top**.
- Every link is stored as **(visible text, real href)** so a mismatch can be caught in session 3.
- The tool **never opens links or attachments**, and keeps uploads **in memory only**.
- Bad or oversized files are **rejected politely**, not crashed on.
