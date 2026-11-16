"""Record the internet's answers for the sample emails, for offline demo mode (NFR-4).

Run from the phishguard/ folder, WITH internet (and LLM_API_KEY set for the AI answers):

    ./venv/bin/python scripts/record_offline_cache.py

1. Record: runs every email in data/samples/ normally and saves each DNS, WHOIS, certificate and AI
   answer in data/cache/lookups.json (answers already in the file are kept, so re-running fills gaps).
2. Check: switches the network OFF inside this script, replays the same emails from the file only,
   and compares score, verdict and report source with the recording.

Only the built-in samples are ever recorded, never an uploaded email (PRV-1).
"""
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules import offline          # noqa: E402  (needs the path above)
from pipeline import run_pipeline    # noqa: E402

SAMPLES = sorted((ROOT / "data" / "samples").glob("*.eml"))


def summary(result):
    return {"score": result["total"], "verdict": result["band"], "report": result["report"]["source"],
            "not_run": result["not_run"]}


def block_network():
    def refuse(*_, **__):
        raise OSError("network switched off by record_offline_cache.py")
    socket.getaddrinfo = refuse
    socket.create_connection = refuse
    socket.socket.connect = refuse


def main():
    print(f"Recording {len(SAMPLES)} sample emails into {offline.CACHE_FILE.relative_to(ROOT)} ...")
    offline.start_recording()
    recorded = {}
    for path in SAMPLES:
        recorded[path.name] = summary(run_pipeline(path.read_bytes()))
        print(f"  {path.name:24} {recorded[path.name]}")
    gaps = offline.report()["unsaved"]
    offline.save(samples=recorded)
    if gaps:
        print(f"\n{len(gaps)} lookup(s) failed while recording and were NOT saved (re-run to try again):")
        for g in gaps:
            print("   ", g)

    print("\nReplaying with the network switched off ...")
    offline.reset()
    offline.set_mode("replay")
    block_network()
    same = True
    for path in SAMPLES:
        replayed = summary(run_pipeline(path.read_bytes()))
        ok = replayed == recorded[path.name]
        same &= ok
        print(f"  {'OK  ' if ok else 'DIFF'} {path.name:24} {replayed}")
    missing = offline.report()["missing"]
    if missing:
        print(f"\nNot in the saved file during replay ({len(missing)}):")
        for m in missing:
            print("   ", m)
    print("\nOffline demo is ready." if same else "\nReplay differs from the recording: run this script again.")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
