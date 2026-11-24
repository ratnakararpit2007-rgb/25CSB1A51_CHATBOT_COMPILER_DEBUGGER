"""Single localhost Ollama client wrapper with multi-language agent prompt support."""

from __future__ import annotations

import json
import os
from typing import Any

import requests
from languages import get_adapter


def _load_env_file() -> None:
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip('"').strip("'")
                        if k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass


_load_env_file()

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "llama3")
TIMEOUT_SEC = 120


def get_agent_system_prompt(language: str = "cpp") -> str:
    adapter = get_adapter(language)
    lang_name = adapter.display_name

    return f"""You are an expert, security-conscious {lang_name} compiler and debugging agent for college developers.
Your mission is to systematically identify root causes, audit every function or code block for bugs and security vulnerabilities, map them to CWE identifiers, and synthesize verified solutions.

You may ONLY return one single valid JSON object (no markdown quotes, no conversational text outside the JSON) with keys:
  "thought": "concise explanation of your reasoning for this step",
  "tool": "one of: compile, run, lldb, validate_fix, finish",
  "args": {{}}

Tool arguments schema:
- compile: {{}}
- run: {{"stdin": "optional program input string"}}
- lldb: {{"command": "<allowlisted lldb command for C/C++>"}}
  Allowlisted LLDB commands: bt, backtrace, thread backtrace, frame variable, register read, source list, frame info, thread list
- validate_fix: {{"code": "<complete, self-contained corrected {lang_name} source code>"}}
- finish: {{
    "summary": "Brief overview of all issues identified",
    "bugs": [
      {{
        "location": "function name or line number (e.g. 'reverseArray()', 'line 14', 'computeTax()')",
        "type": "CWE-120 Buffer Overflow / CWE-119 Bounds Violation / CWE-78 Command Injection / CWE-369 Divide by Zero / Logic Error / etc.",
        "description": "Detailed explanation of what is wrong here",
        "fix_applied": "How this specific issue is resolved in the fixed code"
      }}
    ],
    "root_cause": "Comprehensive explanation covering ALL identified bugs and CWE vulnerabilities across all functions",
    "fixed_code": "complete working {lang_name} source code resolving ALL issues",
    "confidence": "high",
    "learning_note": "practical pedagogical advice on how to avoid these bugs in the future"
  }}

Crucial Security & Multi-Bug Rules:
- Audit EVERY function in the program. Student code frequently contains MULTIPLE simultaneous bugs and vulnerabilities (e.g. CWE-120 gets/strcpy overflows, CWE-119 off-by-one loops, CWE-369 divide by zero, unhandled null values, type mismatches).
- Do NOT stop after detecting just one bug! Return ALL bugs in the "bugs" array and repair ALL of them in "fixed_code".
- If compilation or syntax verification fails, there is NO runnable binary or script. Do NOT call "run" or "lldb". Call "validate_fix" with the complete corrected source code.
- Once "validate_fix" returns accepted=True, immediately call "finish" with the verified code.
- Output strictly a single JSON object.
"""


AGENT_SYSTEM = get_agent_system_prompt("cpp")
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


class LLMError(RuntimeError):
    pass


class OllamaError(LLMError):
    pass


class GeminiError(LLMError):
    pass


def _post_ollama(prompt: str, prefer_json: bool) -> str:
    payload: dict[str, Any] = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
    }
    if prefer_json:
        payload["format"] = "json"
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=TIMEOUT_SEC)
    except requests.RequestException as exc:
        raise OllamaError(
            "Ollama is not reachable on http://127.0.0.1:11434. "
            "Start Ollama with `ollama serve` or `docker compose up -d ollama`, "
            f"then run `ollama pull {MODEL_NAME}`. ({exc})"
        ) from exc
    if response.status_code != 200:
        raise OllamaError(f"Ollama returned HTTP {response.status_code}: {response.text[:300]}")
    try:
        return response.json().get("response", "")
    except ValueError as exc:
        raise OllamaError("Ollama returned non-JSON HTTP body") from exc


def _post_gemini(prompt: str, prefer_json: bool, api_key: str, model: str = "gemini-3.8-flash") -> str:
    if not api_key:
        raise GeminiError(
            "Gemini API key is not configured. Enter your Gemini API key in the sidebar or "
            "set the GEMINI_API_KEY environment variable. Get a free key at https://aistudio.google.com"
        )

    target_model = model or "gemini-3.8-flash"
    url = f"{GEMINI_BASE_URL}/{target_model}:generateContent?key={api_key}"
    payload: dict[str, Any] = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
        },
    }
    if prefer_json:
        payload["generationConfig"]["responseMimeType"] = "application/json"

    try:
        response = requests.post(url, json=payload, timeout=TIMEOUT_SEC)
    except requests.RequestException as exc:
        raise GeminiError(f"Failed to connect to Google Gemini API: {exc}") from exc

    if response.status_code != 200:
        err_msg = response.text
        try:
            err_json = response.json()
            err_msg = err_json.get("error", {}).get("message", response.text)
        except Exception:
            pass
        raise GeminiError(f"Gemini API returned HTTP {response.status_code}: {err_msg}")

    try:
        resp_data = response.json()
        candidates = resp_data.get("candidates", [])
        if not candidates:
            feedback = resp_data.get("promptFeedback", {})
            raise GeminiError(f"Gemini returned no candidates (feedback: {feedback})")
        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            raise GeminiError("Gemini returned empty content parts")
        return parts[0].get("text", "")
    except (ValueError, KeyError, IndexError) as exc:
        raise GeminiError(f"Failed to parse Gemini response: {exc}") from exc


def _post_llm(
    prompt: str,
    prefer_json: bool,
    provider: str = "auto",
    gemini_api_key: str | None = None,
    gemini_model: str = "gemini-3.8-flash",
) -> str:
    key = gemini_api_key or os.environ.get("GEMINI_API_KEY", os.environ.get("GOOGLE_API_KEY", ""))
    prov = (provider or "auto").lower()

    if prov == "gemini" or (prov == "auto" and key):
        return _post_gemini(prompt, prefer_json, api_key=key, model=gemini_model)
    return _post_ollama(prompt, prefer_json)


def _post(prompt: str, prefer_json: bool) -> str:
    """Backward compatibility wrapper."""
    return _post_llm(prompt, prefer_json)


def choose_tool(
    state_prompt: str,
    language: str = "cpp",
    provider: str = "auto",
    gemini_api_key: str | None = None,
    gemini_model: str = "gemini-3.8-flash",
) -> dict:
    """Ask LLM (Gemini or Ollama) for a single JSON tool call tailored to the active language."""
    system = get_agent_system_prompt(language)
    prompt = f"{system}\n\n--- CURRENT STATE ---\n{state_prompt}\n"
    raw = _post_llm(
        prompt,
        prefer_json=True,
        provider=provider,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
    )
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        import re
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass
        # Fallback: scan for outermost JSON object { ... }
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                data = json.loads(raw[start : end + 1])
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass
        return {
            "thought": "parse_error",
            "tool": None,
            "args": {},
            "_parse_error": raw[:500],
        }
    if not isinstance(data, dict):
        return {"thought": "parse_error", "tool": None, "args": {}, "_parse_error": str(data)[:500]}
    return data


def complete_text(
    prompt: str,
    language: str = "cpp",
    provider: str = "auto",
    gemini_api_key: str | None = None,
    gemini_model: str = "gemini-3.8-flash",
) -> str:
    """Pedagogical follow-up tutor chat for the student's code."""
    adapter = get_adapter(language)
    constrained = (
        f"You are a friendly, expert {adapter.display_name} programming tutor. "
        "Answer questions helpfully and pedagogically about the student's code, "
        "compiler errors, syntax, and debugging concepts. Refuse unrelated requests.\n\n"
        f"{prompt}"
    )
    return _post_llm(
        constrained,
        prefer_json=False,
        provider=provider,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
    )
