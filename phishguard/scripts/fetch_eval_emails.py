"""Download a fixed, repeatable set of public test emails for the evaluation (session 7, PRD section 10).

Run from the phishguard/ folder, with internet:

    ./venv/bin/python scripts/fetch_eval_emails.py              # the main 100 (data/eval/phish, data/eval/legit)
    ./venv/bin/python scripts/fetch_eval_emails.py --heldout    # a SECOND, separate 100 (data/eval/heldout/...)

The held-out set is kept aside as the honest test (never used to design or tune anything): phishing from 2024 (not 2025), and normal emails from a
different SpamAssassin archive, with none of the emails in the main set.

It writes .eml files into data/eval/phish/ and data/eval/legit/ (both kept out of git: the emails belong to
their senders, so only this script is shared, never the emails).

Sources (both public, made for research):
  - Phishing: Jose Nazario's phishing corpus, https://monkey.org/~jose/phishing/ (CC BY 4.0).
    We take the newest yearly file, so the phishing is recent.
  - Legitimate: the SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/
    "easy_ham" (ordinary mail) plus some "hard_ham" (marketing mail that looks a bit like spam).
    These are from 2002-2003: there is no public set of recent normal emails, because real inboxes are private.

The same seed always picks the same emails from the same files, so anyone can rebuild our test set (as long as the
public files have not been changed upstream; phishing-2025 was last updated in February 2026).
"""
import argparse
import email
import hashlib
import mailbox
import random
import sys
import tarfile
import urllib.request
from email import policy
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "data" / "eval"
RAW = EVAL / "raw"
SEED, HELDOUT_SEED = 7, 2024
N_PHISH, N_EASY, N_HARD = 50, 40, 10
MAX_BYTES = 5 * 1024 * 1024          # same limit as the upload form

PHISH_URL = "https://monkey.org/~jose/phishing/{name}"
PHISH_FILES = ["phishing-2025", "phishing-2024"]          # newest first; the second is only used if the first is short
HAM_URL = "https://spamassassin.apache.org/old/publiccorpus/{name}"
EASY_HAM, HARD_HAM = "20030228_easy_ham.tar.bz2", "20030228_hard_ham.tar.bz2"
EASY_HAM_2 = "20030228_easy_ham_2.tar.bz2"                # held-out normal emails come from this separate archive


def download(url, dest):
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    print(f"  downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "phishguard-eval/1.0 (student project)"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as out:
        out.write(resp.read())
    return dest


def usable(raw):
    """An email we can test: a sensible size, with a From header and some text."""
    if not raw or len(raw) > MAX_BYTES:
        return False
    msg = email.message_from_bytes(raw, policy=policy.compat32)
    return bool(msg.get("From")) and bool(msg.get_payload())


def message_id(raw):
    return (email.message_from_bytes(raw, policy=policy.compat32).get("Message-ID") or "").strip()


def phishing_emails(files=PHISH_FILES, exclude=()):
    known = {message_id(p.read_bytes()) for p in (ROOT / "data" / "samples").glob("*.eml")} | set(exclude)
    known -= {""}
    pool, seen = [], set()
    for name in files:
        box = mailbox.mbox(str(download(PHISH_URL.format(name=name), RAW / name)), create=False)
        for msg in box:
            raw = msg.as_bytes(unixfrom=False)
            mid = message_id(raw)
            if usable(raw) and mid not in known and (not mid or mid not in seen):
                seen.add(mid)
                pool.append((name, raw))
        if len(pool) >= N_PHISH * 3:
            break
    return pool


def ham_emails(archive, exclude=()):
    pool = []
    with tarfile.open(download(HAM_URL.format(name=archive), RAW / archive), "r:bz2") as tar:
        for member in sorted(tar.getmembers(), key=lambda m: m.name):
            if not member.isfile() or member.name.endswith("cmds"):
                continue
            raw = tar.extractfile(member).read()
            if usable(raw) and hashlib.sha256(raw).hexdigest() not in exclude:
                pool.append((archive, raw))
    return pool


def write(pool, n, folder, prefix, rng):
    folder.mkdir(parents=True, exist_ok=True)
    for old in folder.glob(f"{prefix}*.eml"):
        old.unlink()
    for i, (_, raw) in enumerate(sorted(rng.sample(pool, n), key=lambda item: item[1]), 1):
        (folder / f"{prefix}{i:03d}.eml").write_bytes(raw)
    print(f"  {n} emails -> {folder.relative_to(ROOT)}/{prefix}*.eml (picked from {len(pool)})")


def heldout():
    """A second set that shares no email with the main set (checked by Message-ID and by exact content)."""
    main_phish = {message_id(p.read_bytes()) for p in (EVAL / "phish").glob("*.eml")}
    main_legit = {hashlib.sha256(p.read_bytes()).hexdigest() for p in (EVAL / "legit").glob("*.eml")}
    if not main_phish or not main_legit:
        sys.exit("Fetch the main set first (run without --heldout), so the held-out set can avoid it.")
    rng, out = random.Random(HELDOUT_SEED), EVAL / "heldout"
    print("Held-out phishing (Nazario corpus 2024):")
    write(phishing_emails(["phishing-2024"], exclude=main_phish), N_PHISH, out / "phish", "phish_", rng)
    print("Held-out legitimate (SpamAssassin easy_ham_2 and hard_ham):")
    write(ham_emails(EASY_HAM_2, exclude=main_legit), N_EASY, out / "legit", "easy_", rng)
    write(ham_emails(HARD_HAM, exclude=main_legit), N_HARD, out / "legit", "hard_", rng)
    print("Done. Next: ./venv/bin/python scripts/evaluate.py --set heldout")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Download the public evaluation emails.")
    parser.add_argument("--heldout", action="store_true", help="build the separate held-out set instead")
    if parser.parse_args().heldout:
        RAW.mkdir(parents=True, exist_ok=True)
        return heldout()
    RAW.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    print("Phishing (Nazario corpus):")
    write(phishing_emails(), N_PHISH, EVAL / "phish", "phish_", rng)
    print("Legitimate (SpamAssassin corpus):")
    write(ham_emails(EASY_HAM), N_EASY, EVAL / "legit", "easy_", rng)
    write(ham_emails(HARD_HAM), N_HARD, EVAL / "legit", "hard_", rng)
    print("Done. Next: ./venv/bin/python scripts/evaluate.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
