"""Batch evaluation (session 7, PRD section 10): run every test email through the tool and measure it.

Run from the phishguard/ folder, WITH internet and LLM_API_KEY set (get the emails first with
scripts/fetch_eval_emails.py):

    ./venv/bin/python scripts/evaluate.py              # run all emails, then write the results
    ./venv/bin/python scripts/evaluate.py --limit 5    # quick trial on 5 emails per set
    ./venv/bin/python scripts/evaluate.py --summary    # only rewrite the results from the saved CSV
    ./venv/bin/python scripts/evaluate.py --set heldout   # the separate held-out set (results/heldout.*)
    ./venv/bin/python scripts/evaluate.py --set inbox --folder "../chk/new examples"
                                                       # your own recent, genuine emails; the AI stays OFF, so no
                                                       # email text leaves the laptop (results/inbox.*)

What it writes (no email text or addresses, only file names, scores and red-flag names):
  results/evaluation.csv   one row per email
  results/evaluation.md    the confusion matrices, detection rate, false-positive rate, timing,
                           with and without the AI tone check, and which red flags fired in each set

The AI is used only for the tone score here, not for the report text, to halve the number of AI calls.
"""
import argparse
import copy
import csv
import math
import os
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules import load_config, offline       # noqa: E402  (needs the path above)
from modules.scoring import score_email         # noqa: E402
from modules.tone import check_tone             # noqa: E402
from pipeline import run_pipeline               # noqa: E402

EVAL = ROOT / "data" / "eval"
OUT = ROOT / "results"
CSV_FILE, MD_FILE = OUT / "evaluation.csv", OUT / "evaluation.md"
BEFORE_FILE = OUT / "evaluation_before.csv"     # the first run, before the one tuning step (kept for comparison)
TUNED_FILE = OUT / "evaluation_tuned.csv"       # the run after tuning, before the disguise check (M9) was added
TITLE_SUFFIX = ""
USE_AI = True                    # False for --set inbox: private emails are never sent to the cloud AI
# Earlier runs of the same emails, kept so the results show how each change moved the numbers.
HISTORY = [("First run", OUT / "evaluation_before.csv"),
           ("After the one tuning step (tone 2.5 x, cap 20; lookalike fix)", OUT / "evaluation_tuned.csv"),
           ("After adding the disguise check (M9)", OUT / "evaluation_m9.csv")]
SETS = [("phish", "phishing"), ("legit", "legitimate")]
SOURCES = {"phish_": "Nazario phishing corpus 2025", "easy_": "SpamAssassin easy_ham (2002-03)",
           "hard_": "SpamAssassin hard_ham (2002-03)"}
FIELDS = ["file", "actual", "source", "score", "verdict", "score_no_tone", "verdict_no_tone",
          "tone_score", "flags", "not_run", "seconds"]


# ---------------------------------------------------------------- running

def source_of(name):
    return next((label for prefix, label in SOURCES.items() if name.startswith(prefix)), "other")


def flag_ids(checks):
    """Every red flag that fired, once each, in check order (tone is stored separately as a score)."""
    seen = []
    for check in checks:
        for f in check.get("findings", []):
            if check["check"] != "tone" and f["id"] not in seen:
                seen.append(f["id"])
    return seen


def run_one(path, actual):
    start = time.perf_counter()
    result = run_pipeline(path.read_bytes(), explain=False)
    checks = result["checks"]
    # "Too many requests" from the AI service looks the same as "unreachable": wait and ask again,
    # so a busy service does not quietly remove the tone check from the comparison.
    for wait in (10, 30, 60) if USE_AI else ():
        tone = next(c for c in checks if c["check"] == "tone")
        if tone["status"] != "error":
            break
        print(f"    tone check failed ({tone.get('error')}); retrying in {wait}s")
        time.sleep(wait)
        checks = [c for c in checks if c["check"] != "tone"] + [check_tone(result["parsed"])]
    seconds = time.perf_counter() - start
    full = score_email(checks)
    without = score_email([c for c in checks if c["check"] != "tone"])
    tone = next(c for c in checks if c["check"] == "tone")
    return {"file": path.name, "actual": actual, "source": source_of(path.name),
            "score": full["score"], "verdict": full["verdict"],
            "score_no_tone": without["score"], "verdict_no_tone": without["verdict"],
            "tone_score": "" if tone["status"] == "error" else tone.get("score"),
            "flags": ";".join(flag_ids(checks)), "not_run": ";".join(full["not_run"]),
            "seconds": round(seconds, 2)}


def run_all(limit=None, inbox_folder=None):
    offline.set_mode("live")              # never replay (answers missing) and never record corpus lookups
    files = []
    if inbox_folder:                      # the user's own genuine emails: AI off, and no file names in the results
        load_config()["llm"]["provider"] = "off"       # for this run only; config.yaml is not changed
        found = sorted(p for p in Path(inbox_folder).iterdir() if p.is_file())
        if not found:
            sys.exit(f"No emails in {inbox_folder}.")
        files = [(p, "legitimate") for p in found[:limit]]
    else:
        if not os.environ.get(load_config()["llm"]["nemotron"]["api_key_env"]):
            sys.exit("LLM_API_KEY is not set: the tone check would not run. Open a terminal where it is set.")
        for folder, actual in SETS:
            found = sorted((EVAL / folder).glob("*.eml"))
            if not found:
                sys.exit(f"No emails in {EVAL / folder}. Run scripts/fetch_eval_emails.py first.")
            files += [(p, actual) for p in found[:limit]]
    rows = []
    OUT.mkdir(exist_ok=True)
    for i, (path, actual) in enumerate(files, 1):
        row = run_one(path, actual)
        if inbox_folder:                  # subjects are private: call them inbox_01, inbox_02, ...
            row.update(file=f"inbox_{i:02d}.eml", source="own inbox (recent, genuine)")
        rows.append(row)
        print(f"  [{i:3}/{len(files)}] {row['file']:16} {actual:10} -> {row['verdict']:10} {row['score']:3} "
              f"(no tone {row['score_no_tone']:3})  {row['seconds']:5.1f}s  {row['flags']}")
        write_csv(rows)                     # after every email, so a crash loses nothing
    return rows


def write_csv(rows):
    with open(CSV_FILE, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def read_csv():
    with open(CSV_FILE, newline="") as fh:
        return list(csv.DictReader(fh))


# ---------------------------------------------------------------- measuring

SENDER_FLAGS = {"spf_fail", "spf_softfail", "spf_none", "dkim_invalid", "dkim_none", "dmarc_fail", "dmarc_none",
                "domain_mismatch"}


DISGUISE_FLAGS = {"risky_attachment", "brand_display_name", "address_in_display_name", "own_org_display_name",
                  "free_hosting_link", "redirect_link"}


def rescore(row, config, tone=True, sender=True, disguise=True):
    """Score an email again from its saved red flags, with the weights in `config` (no network needed).
    sender=False leaves out the sender check (M2), the fair view for emails older than SPF/DKIM/DMARC.
    disguise=False leaves out the disguise check (M9), to show what it adds."""
    points = config["points"]
    drop = (set() if sender else SENDER_FLAGS) | (set() if disguise else DISGUISE_FLAGS)
    raw = sum(points.get(f, 0) for f in row["flags"].split(";") if f and f not in drop)
    if tone and row["tone_score"] not in ("", None):
        cfg = config["tone"]
        raw += round(min(cfg["max_points"], cfg["weight"] * float(row["tone_score"])), 1)
    score = min(100, math.floor(round(raw, 1) + 0.5))
    t = config["thresholds"]
    return score, "phishing" if score >= t["phishing_from"] else "suspicious" if score >= t["suspicious_from"] else "safe"


def matrix(rows, verdict_key, flagged):
    """Confusion matrix where 'predicted phishing' means the verdict is in `flagged`."""
    m = Counter()
    for r in rows:
        predicted = r[verdict_key] in flagged
        actual = r["actual"] == "phishing"
        m[("TP" if actual else "FP") if predicted else ("FN" if actual else "TN")] += 1
    tp, fp, fn, tn = m["TP"], m["FP"], m["FN"], m["TN"]
    pct = lambda a, b: f"{100 * a / b:.0f}%" if b else "n/a"
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "detection": pct(tp, tp + fn), "false_pos": pct(fp, fp + tn),
            "accuracy": pct(tp + tn, tp + tn + fp + fn), "precision": pct(tp, tp + fp)}


def summarise(rows):
    config = load_config()
    for r in rows:                         # the saved flags must give back the same score as the live run
        assert rescore(r, config)[0] == int(r["score"]), f"rescoring differs for {r['file']}"
        assert rescore(r, config, tone=False)[0] == int(r["score_no_tone"]), f"rescoring differs for {r['file']}"
        r["verdict_no_sender"] = rescore(r, config, sender=False)[1]
        r["verdict_no_disguise"] = rescore(r, config, disguise=False)[1]
    phish = [r for r in rows if r["actual"] == "phishing"]
    legit = [r for r in rows if r["actual"] == "legitimate"]
    secs = [float(r["seconds"]) for r in rows]
    lines = [f"# PhishGuard-AI evaluation results{TITLE_SUFFIX}", "",
             f"{len(rows)} emails: {len(phish)} phishing, {len(legit)} legitimate. Weights as in config.yaml.", "",
             "**Test emails** (public research sets, rebuilt with `scripts/fetch_eval_emails.py`):", ""]
    for label, n in Counter(r["source"] for r in rows).most_common():
        lines.append(f"- {label}: {n}")
    lines += ["", "Phishing emails: Jose Nazario's phishing corpus, https://monkey.org/~jose/phishing/ (CC BY 4.0). "
              "Legitimate emails: the SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/.", ""]

    def verdict_table(key):
        out = ["| Actual \\ Verdict | Safe | Suspicious | Phishing |", "| --- | --- | --- | --- |"]
        for actual, group in (("Phishing", phish), ("Legitimate", legit)):
            c = Counter(r[key] for r in group)
            out.append(f"| {actual} ({len(group)}) | {c['safe']} | {c['suspicious']} | {c['phishing']} |")
        return out

    def metric_rows(key, label):
        out = []
        for name, flagged in (("Suspicious or Phishing", {"suspicious", "phishing"}), ("Phishing only", {"phishing"})):
            m = matrix(rows, key, flagged)
            out.append(f"| {label} | {name} | {m['TP']} | {m['FN']} | {m['FP']} | {m['TN']} | "
                       f"{m['detection']} | {m['false_pos']} | {m['accuracy']} |")
        return out

    lines += ["## Verdicts (with the AI tone check)", ""] + verdict_table("verdict")
    lines += ["", "## Verdicts (without the AI tone check)", ""] + verdict_table("verdict_no_tone")
    lines += ["", "## Confusion matrix and rates", "",
              "*Counted as caught* says which verdicts count as \"the tool warned the user\".", "",
              "| Tone check | Counted as caught | Caught (TP) | Missed (FN) | False alarm (FP) | Correctly safe (TN) "
              "| Detection rate | False-positive rate | Accuracy |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    lines += metric_rows("verdict", "With AI") + metric_rows("verdict_no_tone", "Without AI")
    past = [(label, path) for label, path in HISTORY if path.exists()]
    if past:
        lines += ["", "## How the results on these emails changed", "",
                  "Each row is a full run on the same emails. Counted as caught: Suspicious or Phishing.", "",
                  "| Run | Detection rate | False-positive rate |", "| --- | --- | --- |"]
        for label, path in past:
            with open(path, newline="") as fh:
                m = matrix(list(csv.DictReader(fh)), "verdict", {"suspicious", "phishing"})
            lines.append(f"| {label} | {m['detection']} | {m['false_pos']} |")
        m = matrix(rows, "verdict", {"suspicious", "phishing"})
        lines.append(f"| **Now** (SPF verdict taken from the receiving mail server when it recorded one) | "
                     f"**{m['detection']}** | **{m['false_pos']}** |")
        lines += ["", "The last step is a correction, not a tuning: the tool used to re-check SPF against an IP address "
                  "guessed from the Received headers, which is the wrong computer whenever an email passed through a "
                  "relay. It reported \"SPF failed\" for emails the receiving server had recorded as SPF pass. Those "
                  "false failures had been adding points to phishing emails, so the earlier detection rates were too high. "
                  "The 2002 legitimate emails carry no server verdict, so their results hardly change."]
    if BEFORE_FILE and BEFORE_FILE.exists():
        with open(BEFORE_FILE, newline="") as fh:
            before = list(csv.DictReader(fh))
        tuned = rows
        if TUNED_FILE.exists():                   # the run after tuning, before the disguise check was added
            with open(TUNED_FILE, newline="") as fh:
                tuned = list(csv.DictReader(fh))
        odd = lambda rs: [r for r in rs if int(r["file"][-7:-4]) % 2 == 1]
        even = lambda rs: [r for r in rs if int(r["file"][-7:-4]) % 2 == 0]
        caught = {"suspicious", "phishing"}
        lines += ["", "## Tuning (done once, then frozen)", "",
                  "The weights were tuned once, on the odd-numbered emails only (the tuning half). The even-numbered "
                  "emails (the test half) were not used to choose anything, so their numbers are the honest ones. "
                  "Before: tone 1.5 x score, cap 15, and the old lookalike rule. After: tone 2.5 x score, cap 20, and the "
                  "lookalike fix (redhat.com was flagged as a fake reddit.com). Counted as caught: Suspicious or Phishing.", "",
                  "| | Tuning half: detection | Tuning half: false-positive | Test half: detection | "
                  "Test half: false-positive | All: detection | All: false-positive |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]
        # The middle row isolates the weight change: the FIRST run's flags and tone scores, scored with the new
        # weights, so live-lookup and AI differences between the runs cannot affect it.
        reweighted = [dict(r, verdict=rescore(r, config)[1]) for r in before]
        for label, rs in (("Before (first run, old weights)", before),
                          ("New weights only (first run's flags, rescored)", reweighted),
                          ("After (second run: new weights + lookalike fix)", tuned)):
            cells = []
            for part in (odd(rs), even(rs), rs):
                m = matrix(part, "verdict", caught)
                cells += [m["detection"], m["false_pos"]]
            lines.append(f"| {label} | " + " | ".join(cells) + " |")
        # Not every change between the two runs comes from the tuning: live lookups and the AI vary a little.
        old = {r["file"]: r for r in before}
        drift = [r for r in tuned if r["file"] in old and (old[r["file"]]["tone_score"] != r["tone_score"] or
                 set(old[r["file"]]["flags"].split(";")) - {"lookalike_domain"} != set(r["flags"].split(";")) - {"lookalike_domain"})]
        lines += ["", f"**Run-to-run differences.** In {len(drift)} of {len(tuned)} emails the second run found different "
                  "red flags or a different AI tone score, independent of the tuning (a DNS lookup that timed out in one "
                  "run but answered in the other, or the AI scoring the same text differently):", ""]
        for r in drift:
            o = old[r["file"]]
            lines.append(f"- {r['file']} ({r['actual']}): {o['verdict']} {o['score']} -> {r['verdict']} {r['score']}; "
                         f"tone {o['tone_score'] or 'n/a'} -> {r['tone_score'] or 'n/a'}; "
                         f"flags +[{', '.join(sorted(set(r['flags'].split(';')) - set(o['flags'].split(';')) - {''}))}] "
                         f"-[{', '.join(sorted(set(o['flags'].split(';')) - set(r['flags'].split(';')) - {'', 'lookalike_domain'}))}]")
    lines += ["", "## Without the sender check", "",
              "The legitimate emails are from 2002-03, before SPF, DKIM and DMARC existed, and most passed through "
              "the corpus collector's own mail server. Checked against today's DNS, their sender check fails because of "
              "their age, not because they are fake. This view leaves the sender check out for BOTH sets, to show how "
              "the other checks do on their own.", ""] + verdict_table("verdict_no_sender")
    lines += ["", "| Tone check | Counted as caught | Caught (TP) | Missed (FN) | False alarm (FP) | Correctly safe (TN) "
              "| Detection rate | False-positive rate | Accuracy |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    lines += metric_rows("verdict_no_sender", "With AI, no sender check")

    caught_cols = "| Tone check | Counted as caught | Caught (TP) | Missed (FN) | False alarm (FP) | Correctly safe (TN) " \
                  "| Detection rate | False-positive rate | Accuracy |"
    if phish:
        lines += ["", "## What the disguise check (M9) adds", "",
                  "Same run, scored with and without the disguise check's flags (sender name, risky attachments, "
                  "free hosting and redirect links). Its points were set before the held-out test, not tuned.", "",
                  caught_cols, "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
        lines += metric_rows("verdict", "With AI, with disguise check")
        lines += metric_rows("verdict_no_disguise", "With AI, without disguise check")
        # Every Nazario email was sent to ONE mailbox (at monkey.org), which flatters the "own organisation" rule.
        no_own = copy.deepcopy(config)
        no_own["points"]["own_org_display_name"] = 0
        caught_without = sum(rescore(r, no_own)[1] != "safe" for r in phish)
        lines += ["", f"**Caveat.** All phishing emails in the Nazario corpus were sent to one person's mailbox, so the "
                  f"\"sender name shows your own organisation\" rule fired on {sum('own_org_display_name' in r['flags'] for r in phish)} "
                  f"of {len(phish)} of them; real inboxes see this trick less often. Without that rule, detection "
                  f"(Suspicious or Phishing) would be {100 * caught_without / len(phish):.0f}%."]
    lines += ["", "## Average scores", "", "| Set | Average score | Average without AI | Average tone score (0-10) |",
              "| --- | --- | --- | --- |"]
    for name, group in (("Phishing", phish), ("Legitimate", legit)):
        tones = [float(r["tone_score"]) for r in group if r["tone_score"] not in ("", None)]
        lines.append(f"| {name} | {statistics.mean(int(r['score']) for r in group):.1f} | "
                     f"{statistics.mean(int(r['score_no_tone']) for r in group):.1f} | "
                     f"{statistics.mean(tones) if tones else 0:.1f} |")

    lines += ["", "## Which red flags fired", "", "Number of emails in each set where the flag fired.", "",
              "| Red flag | Points | Phishing emails | Legitimate emails |", "| --- | --- | --- | --- |"]
    counts = {name: Counter(f for r in group for f in r["flags"].split(";") if f)
              for name, group in (("p", phish), ("l", legit))}
    for flag in sorted(set(counts["p"]) | set(counts["l"]), key=lambda f: (-config["points"].get(f, 0), f)):
        lines.append(f"| {flag} | {config['points'].get(flag, 0)} | {counts['p'][flag]} | {counts['l'][flag]} |")
    lines.append(f"| tone score 3 or more (AI) | up to {config['tone']['max_points']} | "
                 f"{sum(1 for r in phish if r['tone_score'] not in ('', None) and float(r['tone_score']) >= 3)} | "
                 f"{sum(1 for r in legit if r['tone_score'] not in ('', None) and float(r['tone_score']) >= 3)} |")

    not_run = Counter(c for r in rows for c in r["not_run"].split(";") if c)
    lines += ["", "## Checks that could not run", ""]
    lines += [f"- {check}: {n} of {len(rows)} emails" for check, n in not_run.most_common()] or ["- none"]
    lines += ["", "## Time per email", "",
              f"Average {statistics.mean(secs):.1f} s, median {statistics.median(secs):.1f} s, "
              f"slowest {max(secs):.1f} s (live lookups, one email at a time, AI tone check included, report text not).", ""]
    OUT.mkdir(exist_ok=True)
    MD_FILE.write_text("\n".join(lines))
    print("\n".join(lines))


def summarise_inbox(rows):
    """Genuine emails only, AI off: how many would be wrongly flagged, and how many are safe whatever the AI says."""
    config = load_config()
    cap, line = config["tone"]["max_points"], config["thresholds"]["suspicious_from"]
    verdicts = Counter(r["verdict"] for r in rows)
    flagged = len(rows) - verdicts["safe"]
    certain = sum(1 for r in rows if int(r["score"]) + cap < line)
    lines = ["# PhishGuard-AI: recent genuine emails from our own inbox", "",
             f"{len(rows)} genuine emails, downloaded from Gmail as .eml. They are private, so they are not in the "
             "repository and are listed by number only. The AI tone check was switched OFF for this run, so no email "
             "text left the laptop; only the normal DNS, WHOIS and certificate lookups were made.", "",
             f"- Safe: **{verdicts['safe']} of {len(rows)}**. Wrongly flagged (Suspicious or Phishing): **{flagged}**.",
             f"- {certain} of {len(rows)} score so low that they would stay Safe even if the AI gave its maximum "
             f"{cap} points. The others could reach Suspicious only if the AI rated their wording as manipulative.",
             "- This is a small sample: it shows the tool does not misjudge ordinary recent mail, but it is not a "
             "measured false-positive rate.", "",
             "| Email | Score (AI off) | Verdict | Red flags |", "| --- | --- | --- | --- |"]
    lines += [f"| {r['file'][:-4]} | {r['score']} | {r['verdict']} | {r['flags'].replace(';', ', ') or 'none'} |" for r in rows]
    not_run = Counter(c for r in rows for c in r["not_run"].split(";") if c and c != "tone")
    lines += ["", "Checks that could not run (other than the switched-off tone check): "
              + (", ".join(f"{c} on {n}" for c, n in not_run.items()) or "none") + ".", ""]
    OUT.mkdir(exist_ok=True)
    MD_FILE.write_text("\n".join(lines))
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--limit", type=int, help="only the first N emails of each set (a quick trial)")
    parser.add_argument("--summary", action="store_true", help="only rewrite results/evaluation.md from the CSV")
    parser.add_argument("--set", choices=["main", "heldout", "inbox"], default="main",
                        help="main = the 100 emails used while building; heldout = the separate final-test 100; "
                             "inbox = your own genuine emails (AI off)")
    parser.add_argument("--folder", default=str(ROOT.parent / "chk" / "new examples"),
                        help="for --set inbox: the folder holding your downloaded emails")
    args = parser.parse_args()
    global EVAL, CSV_FILE, MD_FILE, BEFORE_FILE, TITLE_SUFFIX, HISTORY, USE_AI
    if args.set == "heldout":
        EVAL, CSV_FILE, MD_FILE = EVAL / "heldout", OUT / "heldout.csv", OUT / "heldout.md"
        BEFORE_FILE, TITLE_SUFFIX = None, ": held-out set (not used to design or tune anything)"
        HISTORY = [("First run, done once, with the disguise check (M9)", OUT / "heldout_first.csv")]
        SOURCES["phish_"] = "Nazario phishing corpus 2024"
        SOURCES["easy_"] = "SpamAssassin easy_ham_2 (2002-03)"
    elif args.set == "inbox":
        CSV_FILE, MD_FILE, USE_AI = OUT / "inbox.csv", OUT / "inbox.md", False
    if args.limit and not args.summary:      # a trial must never overwrite the real results
        CSV_FILE, MD_FILE = OUT / "trial.csv", OUT / "trial.md"
    rows = read_csv() if args.summary else run_all(args.limit, args.folder if args.set == "inbox" else None)
    (summarise_inbox if args.set == "inbox" else summarise)(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
