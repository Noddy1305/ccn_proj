"""Offline demo mode (NFR-4): record answers, replay them, and run the whole demo with the network off."""
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app import app
from modules import offline
from pipeline import run_pipeline

SAMPLES = Path(__file__).parent.parent / "data" / "samples"
REAL_CACHE = offline.CACHE_FILE


@pytest.fixture
def cache_file(tmp_path, monkeypatch):
    path = tmp_path / "lookups.json"
    monkeypatch.setattr(offline, "CACHE_FILE", path)
    offline.reset()
    return path


def toy(store):
    """A pretend network function that counts its calls."""
    def lookup(name, timeout=5):
        store.append(name)
        if name == "broken":
            raise OSError("timeout")
        return [(b"\x00bytes", 1), {"when": datetime(2026, 1, 2, tzinfo=timezone.utc)}]
    return offline.cached("toy", key=lambda name, *_: [name], on_miss=lambda: "MISS")(lookup)


# ---------- the three modes

def test_live_mode_calls_through_and_writes_nothing(cache_file):
    calls = []
    offline.set_mode("live")
    toy(calls)("a.com")
    assert calls == ["a.com"] and not cache_file.exists()


def test_record_then_replay_gives_back_exactly_the_same_answer(cache_file):
    calls = []
    lookup = toy(calls)
    offline.start_recording()
    answer = lookup("a.com")
    offline.save()
    offline.reset()
    offline.set_mode("replay")
    assert lookup("a.com") == answer                     # bytes, tuples and dates survive the file
    assert calls == ["a.com"]                            # replay never called the real function
    assert lookup("unknown.com") == "MISS" and offline.report()["missing"] == ['toy|["unknown.com"]']


def test_failures_are_not_saved_and_are_listed(cache_file):
    calls = []
    lookup = toy(calls)
    offline.start_recording()
    with pytest.raises(OSError):
        lookup("broken")
    offline.save()
    assert offline.report()["unsaved"] == ['toy|["broken"]']
    assert json.loads(cache_file.read_text())["answers"] == {}


def test_keep_rule_skips_answers_that_are_really_errors(cache_file):
    lookup = offline.cached("w", key=lambda d: [d], on_miss=lambda: ("error", None),
                            keep=lambda a: a[0] != "error")(lambda d: ("error", None))
    offline.start_recording()
    lookup("x.com")
    assert offline.report()["unsaved"] == ['w|["x.com"]']


def test_recording_again_keeps_older_answers(cache_file):
    calls = []
    lookup = toy(calls)
    offline.start_recording()
    lookup("a.com")
    offline.save()
    offline.reset()
    offline.start_recording()
    lookup("b.com")
    offline.save()
    assert set(json.loads(cache_file.read_text())["answers"]) == {'toy|["a.com"]', 'toy|["b.com"]'}


def test_replay_uses_the_time_of_recording(cache_file):
    offline.start_recording()
    recorded = offline._state["recorded_at"]
    offline.save()
    offline.reset()
    offline.set_mode("replay")
    assert offline.now() == recorded
    assert "Offline demo mode" in offline.describe()
    offline.set_mode("live")
    assert offline.describe() == ""


# ---------- choosing the mode safely

def test_mode_comes_from_the_environment_and_rejects_typos_and_record(monkeypatch):
    offline.set_mode(None)
    monkeypatch.setenv(offline.ENV_VAR, "replay")
    assert offline.mode() == "replay"
    for bad in ("replya", "record"):                     # record would save uploaded emails' lookups (PRV-1)
        monkeypatch.setenv(offline.ENV_VAR, bad)
        with pytest.raises(ValueError):
            offline.mode()


def test_ai_answers_are_filed_under_a_fingerprint_not_the_prompt():
    key = offline.prompt_key("system rules", "Subject: secret exam results")
    assert len(key) == 1 and "secret" not in key[0] and key == offline.prompt_key("system rules", "Subject: secret exam results")


# ---------- the done-when test: the demo runs with Wi-Fi off

@pytest.fixture
def network_off(monkeypatch, real_network_functions):
    """Real lookup functions, but every way out to the internet is blocked."""
    def refuse(*_, **__):
        raise OSError("network is off in this test")
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(offline, "CACHE_FILE", REAL_CACHE)
    offline.reset()
    offline.set_mode("replay")


def recorded_samples():
    return json.loads(REAL_CACHE.read_text())["samples"]


def test_saved_answers_cover_every_sample():
    assert REAL_CACHE.is_file(), "run scripts/record_offline_cache.py"
    assert set(recorded_samples()) == {p.name for p in SAMPLES.glob("*.eml")}


@pytest.mark.parametrize("name", sorted(p.name for p in SAMPLES.glob("*.eml")))
def test_demo_runs_with_the_network_off_and_matches_the_recording(network_off, name):
    expected = recorded_samples()[name]
    result = run_pipeline((SAMPLES / name).read_bytes())
    assert {"score": result["total"], "verdict": result["band"], "report": result["report"]["source"],
            "not_run": result["not_run"]} == expected
    assert expected["report"] == "ai"                    # the AI's saved explanation is used, not the template


def test_offline_page_says_so_and_still_downloads_a_pdf(network_off):
    client = app.test_client()
    page = client.post("/analyze", data={"sample": "forged_exam_cell.eml"}).data.decode()
    assert "Offline demo mode" in page and "saved answer (offline)" in page and "Phishing" in page
    token = page.split("/report.pdf?id=")[1].split('"')[0]
    pdf = client.get(f"/report.pdf?id={token}")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF-")


def test_an_unknown_email_offline_still_gets_a_verdict(network_off):
    raw = (b"From: Someone <x@never-recorded-example.com>\nTo: a@b.com\nSubject: Hello\n"
           b"Date: Mon, 26 Oct 2026 10:00:00 +0000\n\nVisit https://never-recorded-example.com/now\n")
    result = run_pipeline(raw)
    assert result["band"] in ("safe", "suspicious", "phishing") and result["report"]["source"] == "template"
    assert "tone" in result["not_run"] and "certificate" in result["not_run"]
