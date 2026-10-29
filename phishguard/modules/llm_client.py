"""Unified LLM client for PhishGuard-AI (M5 tone and M7 report).

Connects to NVIDIA Nemotron API (cloud) or Ollama (local fallback),
switchable in config.yaml (NFR-6). API keys are read from environment
variable LLM_API_KEY, never hardcoded (PRV-3).
"""
import json
import os
import re
import urllib.error
import urllib.request

from modules import load_config


def extract_json_block(text):
    """Extract JSON object from LLM response text, handling markdown fences."""
    text = text.strip()
    # Match ```json ... ``` or ``` ... ```
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Try finding outer braces
    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def call_llm(prompt, system_prompt=None, json_mode=True, config=None):
    """Send prompt to configured LLM provider and return parsed response or None.

    Never raises: network errors, timeouts, or invalid JSON return None.
    """
    config = config or load_config()
    llm_cfg = config.get("llm", {})
    provider = llm_cfg.get("provider", "nemotron")
    timeout = llm_cfg.get("timeout_seconds", 10)

    if provider == "nemotron":
        api_key = os.environ.get("LLM_API_KEY")
        if not api_key:
            return None  # No key available, caller should use fallback
        n_cfg = llm_cfg.get("nemotron", {})
        base_url = n_cfg.get("base_url", "https://integrate.api.nvidia.com/v1").rstrip("/")
        model = n_cfg.get("model", "nvidia/nemotron-4-340b-instruct")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
    elif provider == "ollama":
        o_cfg = llm_cfg.get("ollama", {})
        base_url = o_cfg.get("base_url", "http://localhost:11434/v1").rstrip("/")
        model = o_cfg.get("model", "llama3.2:1b")
        headers = {"Content-Type": "application/json"}
    else:
        return None

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
    }

    req_url = f"{base_url}/chat/completions"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(req_url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            res_data = json.loads(body)
            content = res_data["choices"][0]["message"]["content"]
            if json_mode:
                return extract_json_block(content)
            return content
    except Exception:
        return None
