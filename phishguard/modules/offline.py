"""Offline demo mode (NFR-4): record the internet's answers once, replay them with Wi-Fi off.

Every function that touches the network (DNS, WHOIS, the TLS handshake and the AI) is wrapped
with cached() below. The wrapper does one of three things:

  live    - just call the real function (normal use)
  record  - call the real function AND save its answer in data/cache/lookups.json
  replay  - never touch the network: answer from the saved file. Anything not saved
            behaves exactly like "no internet", so that check shows "could not run".

The check code itself always runs; only the answers from the internet come from the file.
config.yaml (offline.mode) or the PHISHGUARD_MODE environment variable may choose only
live or replay. Record mode is switched on only by scripts/record_offline_cache.py, which reads
the built-in sample emails, so an uploaded email's lookups are never written to disk (PRV-1).
"""
import base64
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from modules import load_config

CACHE_FILE = Path(__file__).resolve().parent.parent / "data" / "cache" / "lookups.json"
ENV_VAR = "PHISHGUARD_MODE"
ALLOWED = ("live", "replay")              # what config / environment may choose

_lock = threading.Lock()                  # lookups run on many threads at once
_state = {"override": None, "answers": None, "recorded_at": None, "missing": [], "unsaved": []}


def mode():
    """'live', 'record' or 'replay'. Raises ValueError for a typo, so the app refuses to start in the wrong mode."""
    if _state["override"]:
        return _state["override"]
    chosen = (os.environ.get(ENV_VAR) or load_config().get("offline", {}).get("mode", "live")).strip().lower()
    if chosen not in ALLOWED:
        raise ValueError(f"Offline mode must be one of {', '.join(ALLOWED)} (got '{chosen}'). "
                         f"Check {ENV_VAR} or offline.mode in config.yaml.")
    return chosen


def set_mode(value):
    """For the recording script and tests only. None goes back to config / environment."""
    with _lock:
        _state["override"] = value


def reset():
    """Forget everything loaded or noted (the next replay reads the file again)."""
    with _lock:
        _state.update(override=None, answers=None, recorded_at=None, missing=[], unsaved=[])


# ---------------------------------------------------------------- the saved file

def _encode(value):
    """JSON cannot hold bytes, tuples or dates, so they are tagged."""
    if isinstance(value, bytes):
        return {"__bytes__": base64.b64encode(value).decode()}
    if isinstance(value, datetime):
        return {"__datetime__": value.isoformat()}
    if isinstance(value, tuple):
        return {"__tuple__": [_encode(v) for v in value]}
    if isinstance(value, list):
        return [_encode(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _encode(v) for k, v in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)                     # e.g. a DNS name object inside an SPF answer


def _decode(value):
    if isinstance(value, list):
        return [_decode(v) for v in value]
    if isinstance(value, dict):
        if "__bytes__" in value:
            return base64.b64decode(value["__bytes__"])
        if "__datetime__" in value:
            return datetime.fromisoformat(value["__datetime__"])
        if "__tuple__" in value:
            return tuple(_decode(v) for v in value["__tuple__"])
        return {k: _decode(v) for k, v in value.items()}
    return value


def _answers():
    """The saved answers, read from disk once."""
    with _lock:
        if _state["answers"] is None:
            data = json.loads(CACHE_FILE.read_text()) if CACHE_FILE.is_file() else {}
            _state["answers"] = data.get("answers", {})
            stamp = data.get("recorded_at")
            _state["recorded_at"] = datetime.fromisoformat(stamp) if stamp else None
        return _state["answers"]


def start_recording():
    """Record mode: keep the answers already saved (so re-running fills gaps) and add new ones."""
    _answers()
    with _lock:
        _state.update(override="record", recorded_at=datetime.now(timezone.utc), missing=[], unsaved=[])


def save(samples=None):
    """Write all answers to the file in one go (temp file + rename, so a crash never leaves half a file).
    `samples` = the verdict each sample got while recording, so replay can be checked against it."""
    with _lock:
        data = {"recorded_at": _state["recorded_at"].isoformat(),
                "note": "Saved internet answers for the sample emails (offline demo mode). Re-create with "
                        "scripts/record_offline_cache.py. AI answers are keyed by a hash of the prompt.",
                "samples": samples or {},
                "answers": dict(sorted(_state["answers"].items()))}
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False))
    os.replace(tmp, CACHE_FILE)


def now():
    """The 'current time' the checks should use. In replay it is the time of recording, so a domain's
    age or a certificate's expiry is judged exactly as it was when the answers were saved."""
    if mode() == "replay":
        _answers()
        if _state["recorded_at"]:
            return _state["recorded_at"]
    return datetime.now(timezone.utc)


def describe():
    """One line for the page and the report, or '' in live mode."""
    if mode() != "replay":
        return ""
    _answers()
    when = _state["recorded_at"]
    return ("Offline demo mode: internet answers (DNS, WHOIS, certificates, AI) are replayed from saved results"
            + (f" recorded {when:%d %b %Y}" if when else " (none saved yet)") + ", not looked up live.")


def report():
    """For the recording script: lookups that were not saved (record) or not found (replay)."""
    with _lock:
        return {"unsaved": sorted(set(_state["unsaved"])), "missing": sorted(set(_state["missing"]))}


# ---------------------------------------------------------------- the wrapper

def prompt_key(system, user, *_, **__):
    """AI answers are filed under a fingerprint of the prompt, so no prompt text is stored."""
    return [hashlib.sha256((system + "\n" + user).encode()).hexdigest()[:32]]


def cached(kind, key, on_miss, keep=lambda answer: True):
    """Wrap one network function.

    key(*args)      -> list of JSON-friendly parts that identify the question
    on_miss()       -> what to do when replay has no answer: fail exactly like the live function
                       does without internet (raise its error, or return its 'error' value)
    keep(answer)    -> False for answers that are really failures (they are not saved)
    """
    def wrap(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            current = mode()
            if current == "live":
                return fn(*args, **kwargs)
            name = kind + "|" + json.dumps(key(*args, **kwargs))
            if current == "replay":
                answers = _answers()
                if name in answers:
                    return _decode(answers[name])
                with _lock:
                    _state["missing"].append(name)
                return on_miss()
            try:                                           # record
                answer = fn(*args, **kwargs)
            except Exception:
                with _lock:
                    _state["unsaved"].append(name)
                raise
            with _lock:
                if keep(answer):
                    _state["answers"][name] = _encode(answer)
                else:
                    _state["unsaved"].append(name)
            return answer
        return wrapper
    return wrap
