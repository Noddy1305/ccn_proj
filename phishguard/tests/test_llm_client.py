import copy
import json
import urllib.error

import pytest

from modules import llm_client, load_config
from modules.llm_client import LLMError, complete_json, mask_addresses, parse_json  # real functions (the fixture only patches the module attribute)

KEY = "nvapi-test-secret-123"


def cfg(provider="nemotron"):
    config = copy.deepcopy(load_config())
    config["llm"]["provider"] = provider
    return config


def reply(content):
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


@pytest.fixture
def wire(monkeypatch):
    """Replace the single network line. `wire.response` is what the 'server' returns; `wire.sent` records the request."""
    class Wire:
        response, sent = reply('{"ok": true}'), {}
    w = Wire()

    def fake_post(url, payload, headers, timeout):
        w.sent = {"url": url, "payload": payload, "headers": headers, "timeout": timeout}
        if isinstance(w.response, Exception):
            raise w.response
        return w.response
    monkeypatch.setattr(llm_client, "_post", fake_post)
    monkeypatch.setenv("LLM_API_KEY", KEY)
    return w


def test_nemotron_request_shape(wire):
    assert complete_json("sys", "usr", 300, cfg()) == {"ok": True}
    sent, payload = wire.sent, wire.sent["payload"]
    assert sent["url"] == "https://integrate.api.nvidia.com/v1/chat/completions"
    assert sent["headers"]["Authorization"] == "Bearer " + KEY
    assert payload["model"] == "nvidia/nemotron-3.5-lightning-30b-a3b"
    assert payload["temperature"] == 0 and payload["max_tokens"] == 300
    assert payload["chat_template_kwargs"] == {"enable_thinking": False}
    assert payload["messages"] == [{"role": "system", "content": "sys"}, {"role": "user", "content": "usr"}]
    assert sent["timeout"] == 8


def test_ollama_needs_no_key_and_no_thinking_switch(wire, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY")
    complete_json("s", "u", 100, cfg("ollama"))
    assert wire.sent["url"] == "http://localhost:11434/v1/chat/completions"
    assert "Authorization" not in wire.sent["headers"] and "chat_template_kwargs" not in wire.sent["payload"]


def test_missing_key_is_a_clear_error_without_calling_out(wire, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY")
    with pytest.raises(LLMError, match="LLM_API_KEY is not set") as err:
        complete_json("s", "u", 100, cfg())
    assert err.value.unreachable and wire.sent == {}


def test_provider_off_and_unknown(wire):
    for provider in ("off", "mystery"):
        with pytest.raises(LLMError) as err:
            complete_json("s", "u", 100, cfg(provider))
        assert err.value.unreachable
    assert wire.sent == {}


def test_json_inside_fences_or_chatter_is_accepted(wire):
    wire.response = reply('Sure! Here you go:\n```json\n{"score": 4}\n```')
    assert complete_json("s", "u", 100, cfg()) == {"score": 4}


@pytest.mark.parametrize("content", [None, "", "   ", "no json here", '{"broken": ', "[1, 2]"])
def test_empty_or_unusable_answers_raise(wire, content):
    wire.response = reply(content)
    with pytest.raises(LLMError):
        complete_json("s", "u", 100, cfg())


def test_a_broken_answer_is_retried_once_and_can_recover(wire, monkeypatch):
    answers = iter([reply('{"broken": '), reply('{"ok": true}')])
    calls = []
    monkeypatch.setattr(llm_client, "_post", lambda *a: (calls.append(a), next(answers))[1])
    assert complete_json("s", "u", 100, cfg()) == {"ok": True} and len(calls) == 2


def test_two_broken_answers_in_a_row_still_fail(wire, monkeypatch):
    calls = []
    monkeypatch.setattr(llm_client, "_post", lambda *a: (calls.append(a), reply("not json"))[1])
    with pytest.raises(LLMError):
        complete_json("s", "u", 100, cfg())
    assert len(calls) == 2


def test_unreachable_service_is_never_retried(wire, monkeypatch):
    calls = []

    def down(*args):
        calls.append(args)
        raise urllib.error.URLError("no network")
    monkeypatch.setattr(llm_client, "_post", down)
    with pytest.raises(LLMError):
        complete_json("s", "u", 100, cfg())
    assert len(calls) == 1


def test_unexpected_reply_shape_raises(wire):
    wire.response = {"error": "nope"}
    with pytest.raises(LLMError, match="unexpected shape"):
        complete_json("s", "u", 100, cfg())


def test_network_failures_are_unreachable_and_never_leak_the_key(wire):
    for failure in (urllib.error.HTTPError("u", 401, "Unauthorized", {}, None), urllib.error.URLError("dns failed"), TimeoutError("slow")):
        wire.response = failure
        with pytest.raises(LLMError) as err:
            complete_json("s", "u", 100, cfg())
        assert err.value.unreachable and KEY not in str(err.value)


def test_unreadable_service_reply_is_not_called_unreachable(wire):
    wire.response = json.JSONDecodeError("bad", "x", 0)
    with pytest.raises(LLMError) as err:
        complete_json("s", "u", 100, cfg())
    assert not err.value.unreachable


def test_parse_json_requires_an_object():
    assert parse_json(' {"a": 1} ') == {"a": 1}
    with pytest.raises(LLMError):
        parse_json("[1]")


def test_mask_addresses_keeps_the_domain():
    assert mask_addresses("mail bob.smith@college.edu or x+y@evil.co.in now") == "mail ***@college.edu or ***@evil.co.in now"
    assert mask_addresses("") == "" and mask_addresses(None) == ""
