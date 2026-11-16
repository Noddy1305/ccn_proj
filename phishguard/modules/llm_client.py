"""One door to any LLM (NFR-6).

Tone (M5) and the report text (M7) both talk to the AI only through complete_json().
Which AI answers (NVIDIA Nemotron in the cloud, Ollama on this laptop, or none) is
a setting in config.yaml, so no other file needs to change when the provider does.

The AI is never trusted: every failure becomes an LLMError, and the callers carry on
without it (FR-5.3, FR-7.4).
"""
import json
import os
import re
import urllib.error
import urllib.request

from modules import load_config

EMAIL_ADDRESS = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


class LLMError(RuntimeError):
    """The AI could not give a usable answer. `unreachable` is True when we never got a reply."""

    def __init__(self, message, unreachable=False):
        super().__init__(message)
        self.unreachable = unreachable


def mask_addresses(text):
    """PRV-2: hide the name part of every email address, keep the domain (it is the evidence)."""
    return EMAIL_ADDRESS.sub(r"***@\1", text or "")


def _post(url, payload, headers, timeout):
    """The only line of code that touches the network. Tests replace it."""
    request = urllib.request.Request(url, json.dumps(payload).encode(), headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def parse_json(text):
    """AI models often wrap JSON in ```json fences or add a sentence around it. Take the {...} part."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("The AI did not return JSON.")
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise LLMError("The AI returned broken JSON.") from exc
    if not isinstance(data, dict):
        raise LLMError("The AI returned JSON of the wrong shape.")
    return data


def complete_json(system, user, max_tokens, config=None):
    """Send one prompt, return the AI's answer as a dict. Raises LLMError on any problem."""
    config = config or load_config()
    llm = config["llm"]
    provider = llm["provider"]
    if provider == "off":
        raise LLMError("The AI is switched off in config.yaml.", unreachable=True)
    if provider not in ("nemotron", "ollama"):
        raise LLMError(f"Unknown LLM provider '{provider}' in config.yaml.", unreachable=True)
    settings = llm[provider]

    headers = {"Content-Type": "application/json"}
    key_name = settings.get("api_key_env")
    if key_name:
        key = os.environ.get(key_name, "")
        if not key:
            raise LLMError(f"Environment variable {key_name} is not set.", unreachable=True)
        headers["Authorization"] = "Bearer " + key

    payload = {"model": settings["model"], "temperature": llm["temperature"], "max_tokens": max_tokens,
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if settings.get("disable_thinking"):
        payload["chat_template_kwargs"] = {"enable_thinking": False}

    try:
        data = _post(settings["base_url"].rstrip("/") + "/chat/completions", payload, headers, llm["timeout_seconds"])
    except urllib.error.HTTPError as exc:      # never put headers (the key) in a message
        raise LLMError(f"The AI service answered with HTTP {exc.code}.", unreachable=True) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMError("The AI service could not be reached.", unreachable=True) from exc
    except json.JSONDecodeError as exc:
        raise LLMError("The AI service sent an unreadable reply.") from exc

    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError("The AI reply had an unexpected shape.") from exc
    if not isinstance(content, str) or not content.strip():
        raise LLMError("The AI returned an empty answer.")   # e.g. all tokens spent on thinking
    return parse_json(content)
