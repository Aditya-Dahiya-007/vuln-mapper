"""
remediation.py -- Stage 2: AI reasoning & remediation layer (local, via Ollama).

For a vulnerability that a deterministic scanner has ALREADY confirmed (Stage 1),
this module:

    1. pulls the real surrounding source code from the file (fixing the
       "requires login" snippet gap some scanners leave), then
    2. asks a locally-running LLM (Ollama, http://localhost:11434) to return a
       strict-JSON explanation with three parts:
           root_cause        -- why this code is dangerous (tied to its CWE)
           attack_mechanics  -- a concrete step-by-step exploit example
           secure_code       -- a corrected, paste-ready version

Because the LLM only ever operates on findings the scanner proved exist, it
can't invent vulnerabilities -- it only explains and fixes real ones.

Configuration (environment variables, both optional):
    OLLAMA_HOST   default "http://localhost:11434"
    OLLAMA_MODEL  default "llama3.1"   (set this to a model you've pulled)
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

import requests

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1"
REMEDIATE_TIMEOUT = 180  # seconds; local generation can be slow on a laptop

# Which backend generates the fixes:
#   "ollama" -> local model, fully private/offline (default)
#   "gemini" -> Google Gemini cloud API, better quality, needs GEMINI_API_KEY
DEFAULT_PROVIDER = "ollama"
GEMINI_DEFAULT_MODEL = "gemini-3.6-flash"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GEMINI_TIMEOUT = 90


def _provider() -> str:
    return os.environ.get("LLM_PROVIDER", DEFAULT_PROVIDER).strip().lower()


# --------------------------------------------------------------------------- #
# 1. Code context extraction
# --------------------------------------------------------------------------- #
def extract_context(abs_path: str, line: int, radius: int = 12) -> Dict[str, Any]:
    """
    Return a window of source lines around `line` (1-indexed), with line
    numbers and a '>>' marker on the flagged line. Language-agnostic, so it
    works for every language Semgrep supports, not just Python.
    """
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return {"code": "", "start_line": line, "end_line": line}

    total = len(lines)
    if total == 0 or line < 1:
        return {"code": "", "start_line": line, "end_line": line}

    start = max(1, line - radius)
    end = min(total, line + radius)

    numbered = []
    for i in range(start, end + 1):
        marker = ">>" if i == line else "  "
        numbered.append(f"{i:>4} {marker} {lines[i - 1].rstrip()}")

    return {"code": "\n".join(numbered), "start_line": start, "end_line": end}


def attach_context(
    findings: List[Dict[str, Any]], code_root: str, radius: int = 12
) -> List[Dict[str, Any]]:
    """
    Populate finding['context'] with real surrounding code for every finding.
    Must be called while the extracted source still exists on disk (i.e. before
    the temp upload dir is cleaned up).
    """
    for f in findings:
        abs_path = os.path.join(code_root, f.get("file", ""))
        ctx = extract_context(abs_path, f.get("line", 0), radius=radius)
        f["context"] = ctx["code"]
    return findings


# --------------------------------------------------------------------------- #
# 2. Prompt construction
# --------------------------------------------------------------------------- #
def build_prompt(finding: Dict[str, Any]) -> (str, str):
    system = (
        "You are a senior application security engineer performing a code review. "
        "A deterministic static-analysis tool has ALREADY CONFIRMED that the vulnerability "
        "below is present -- do not dispute whether it is real; your job is to explain and "
        "fix it.\n"
        "Follow these rules when writing the fix:\n"
        "1. The fix MUST eliminate the root cause. Sanitize, validate, or parameterize the "
        "actual tainted input -- do not just rearrange the code around it.\n"
        "2. PREFER built-in, battle-tested library functions over hand-written regex or string "
        "manipulation (e.g. use path.basename / os.path.basename for path traversal, "
        "parameterized queries for SQL, shlex/argument lists instead of shell strings).\n"
        "3. Handle ALL variants of the attack, not just the obvious one (e.g. for path "
        "traversal cover both '/' and '\\\\' separators and '..' segments).\n"
        "4. Do NOT add unrelated logic, role checks, or conditionals that don't address the "
        "vulnerability. Stay faithful to the original intent of the code.\n"
        "5. Keep the fix minimal and paste-ready.\n"
        "Respond with ONLY a single JSON object and nothing else: no markdown, no code "
        "fences, no commentary outside the JSON. The value of every key must be a plain "
        "string (secure_code must be a single string of code, not an object or array)."
    )

    cwe = finding.get("cwe") or "N/A"
    code = finding.get("context") or finding.get("snippet") or "(code unavailable)"

    user = f"""A static analysis scan flagged the following issue.

Tool: {finding.get('tool', '')}
Rule: {finding.get('rule_id', '')}
Category (CWE): {cwe}
Severity: {finding.get('severity', '')}
File: {finding.get('file', '')} (line {finding.get('line', '')})
Scanner message: {finding.get('message', '')}

Relevant code (the flagged line is marked with >>):
{code}

Return a JSON object with EXACTLY these three string keys:
- "root_cause": In 2-4 sentences, explain why this specific code is insecure, referencing the {cwe} weakness class.
- "attack_mechanics": Give a concrete, step-by-step example of how an attacker exploits this exact code, including a sample malicious input or payload where applicable.
- "secure_code": A corrected version of the affected lines or function that removes the root cause per the rules above. Use built-in safe functions rather than hand-rolled filtering, cover every variant of the attack, and add no unrelated logic. Must be a single plain string of code, ready to paste in.

Respond with only the JSON object."""
    return system, user


# --------------------------------------------------------------------------- #
# 3. Helpers
# --------------------------------------------------------------------------- #
def _repair_backslashes(text: str) -> str:
    r"""
    Small models often emit regex like \b or \d inside a JSON string without
    doubling the backslash (JSON requires \\b). That makes the JSON invalid at
    that point, so a strict parser stops early and the code gets truncated.

    This escapes any backslash that isn't already part of a valid JSON escape
    (\" \\ \/ \b \f \n \r \t \uXXXX), turning a lone \b into \\b so the whole
    object parses. Valid escapes are left untouched.
    """
    return re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)


def _safe_json(text: str) -> Optional[Dict[str, Any]]:
    """Parse model output as JSON, tolerating stray text and loose backslashes."""
    if not text:
        return None

    # 1. straight parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. isolate the outermost {...} block
    start, end = text.find("{"), text.rfind("}")
    block = text[start : end + 1] if (start != -1 and end != -1 and end > start) else text

    # 3. try that block as-is, then with backslashes repaired (fixes regex fixes)
    for candidate in (block, _repair_backslashes(block)):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


def check_ollama(host: Optional[str] = None) -> Dict[str, Any]:
    """
    Health check for whichever provider is configured. Keeps the same response
    shape the UI already expects (ok / configured_model / model_present), so the
    status chip works for both local and cloud without any frontend change.
    """
    if _provider() == "gemini":
        model = os.environ.get("GEMINI_MODEL", GEMINI_DEFAULT_MODEL)
        if not os.environ.get("GEMINI_API_KEY", "").strip():
            return {
                "ok": False,
                "provider": "gemini",
                "configured_model": model,
                "model_present": False,
                "error": "GEMINI_API_KEY is not set.",
            }
        return {
            "ok": True,
            "provider": "gemini",
            "configured_model": model,
            "model_present": True,
            "available_models": [model],
        }

    host = host or os.environ.get("OLLAMA_HOST", DEFAULT_HOST)
    model = os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL)
    try:
        resp = requests.get(f"{host}/api/tags", timeout=5)
    except requests.exceptions.RequestException as exc:
        return {
            "ok": False,
            "provider": "ollama",
            "host": host,
            "error": f"Could not reach Ollama ({exc}). Start it with 'ollama serve'.",
        }

    if resp.status_code != 200:
        return {"ok": False, "provider": "ollama", "host": host,
                "error": f"Ollama responded {resp.status_code}"}

    available = [m.get("name", "") for m in resp.json().get("models", [])]
    present = any(m == model or m.split(":")[0] == model.split(":")[0] for m in available)
    return {
        "ok": True,
        "host": host,
        "configured_model": model,
        "available_models": available,
        "model_present": present,
    }


# --------------------------------------------------------------------------- #
# 4. The remediation call
# --------------------------------------------------------------------------- #
def _remediate_ollama(
    finding: Dict[str, Any],
    model: Optional[str] = None,
    host: Optional[str] = None,
    timeout: int = REMEDIATE_TIMEOUT,
) -> Dict[str, Any]:
    """
    Ask the local model to explain and fix a single confirmed finding.
    Returns {"ok": True, root_cause, attack_mechanics, secure_code, model}
    or {"ok": False, "error": ...} -- never raises, so one bad finding can't
    take down the request.
    """
    model = model or os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL)
    host = host or os.environ.get("OLLAMA_HOST", DEFAULT_HOST)

    system, user = build_prompt(finding)
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "format": "json",  # force Ollama to emit valid JSON
        "options": {
            "temperature": 0.2,
            # Cap output generously so multi-line fixes aren't cut off mid-code.
            # Ollama's default is short; larger models write longer answers.
            "num_predict": 1536,
        },
    }

    try:
        resp = requests.post(f"{host}/api/chat", json=payload, timeout=timeout)
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "Could not reach Ollama. Is it running? Try 'ollama serve'."}
    except requests.exceptions.Timeout:
        return {
            "ok": False,
            "error": f"Ollama timed out after {timeout}s. The model may be large for this machine -- "
            f"try a smaller one (e.g. llama3.2:3b).",
        }
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "error": f"Ollama request failed: {exc}"}

    if resp.status_code != 200:
        # Ollama's body usually explains the problem (e.g. model not pulled).
        return {"ok": False, "error": f"Ollama error ({resp.status_code}): {resp.text.strip()[:400]}"}

    try:
        content = resp.json().get("message", {}).get("content", "")
    except ValueError:
        return {"ok": False, "error": "Ollama returned a non-JSON envelope."}

    parsed = _safe_json(content)
    if parsed is None:
        return {
            "ok": False,
            "error": "Model did not return valid JSON.",
            "raw": content[:800],
        }

    return {
        "ok": True,
        "model": model,
        "root_cause": _as_text(parsed.get("root_cause", "")),
        "attack_mechanics": _as_text(parsed.get("attack_mechanics", "")),
        "secure_code": _as_text(parsed.get("secure_code", "")),
    }


# --------------------------------------------------------------------------- #
# 5. Gemini (cloud) -- better quality, free tier, needs GEMINI_API_KEY
# --------------------------------------------------------------------------- #
def _remediate_gemini(
    finding: Dict[str, Any],
    model: Optional[str] = None,
    timeout: int = GEMINI_TIMEOUT,
) -> Dict[str, Any]:
    """
    Ask Google Gemini to explain and fix a confirmed finding. Same contract as
    the Ollama path: returns {"ok": True, root_cause, attack_mechanics,
    secure_code, model} or {"ok": False, "error": ...}. Never raises.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return {
            "ok": False,
            "error": "GEMINI_API_KEY is not set. Export your key, or switch "
            "LLM_PROVIDER back to 'ollama'.",
        }

    model = model or os.environ.get("GEMINI_MODEL", GEMINI_DEFAULT_MODEL)
    system, user = build_prompt(finding)

    payload = {
        # Gemini takes the system prompt separately from the user turn.
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {
            # Gemini 3.x reasoning is tuned for default temperature/top_p, and
            # Google explicitly recommends not overriding them -- so we don't.
            # Thinking tokens are billed against maxOutputTokens on 3.x models,
            # so this must be generous or the JSON gets truncated to nothing.
            "maxOutputTokens": 8192,
            # Ask for JSON directly so we don't have to strip markdown fences.
            "responseMimeType": "application/json",
        },
    }

    try:
        resp = requests.post(
            GEMINI_URL.format(model=model),
            json=payload,
            headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        return {"ok": False, "error": f"Gemini timed out after {timeout}s."}
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "error": f"Gemini request failed: {exc}"}

    if resp.status_code == 429:
        return {
            "ok": False,
            "error": "Gemini rate limit hit (free tier). Wait a minute and retry, "
            "or use a lighter model like gemini-2.5-flash-lite.",
        }
    if resp.status_code in (401, 403):
        return {"ok": False, "error": "Gemini rejected the API key (check GEMINI_API_KEY)."}
    if resp.status_code == 404:
        return {
            "ok": False,
            "error": f"Gemini model '{model}' not available to this key. Google retires "
            f"model names over time -- set GEMINI_MODEL to a current one "
            f"(e.g. gemini-3.6-flash or gemini-3.5-flash-lite).",
        }
    if resp.status_code != 200:
        return {"ok": False, "error": f"Gemini error ({resp.status_code}): {resp.text.strip()[:300]}"}

    # Unwrap: candidates[0].content.parts[*].text
    try:
        data = resp.json()
        candidates = data.get("candidates") or []
        if not candidates:
            blocked = (data.get("promptFeedback") or {}).get("blockReason")
            return {
                "ok": False,
                "error": f"Gemini returned no candidates{f' (blocked: {blocked})' if blocked else ''}.",
            }
        cand = candidates[0]
        finish = cand.get("finishReason", "")
        parts = (cand.get("content") or {}).get("parts") or []
        # On 3.x models some parts are internal reasoning summaries flagged with
        # thought=true. Those aren't the answer, and mixing them in breaks JSON.
        content = "".join(
            p.get("text", "") for p in parts if not p.get("thought")
        )
    except ValueError:
        return {"ok": False, "error": "Gemini returned a non-JSON envelope."}

    if not content.strip():
        hint = (
            " The response hit the output limit (thinking tokens count toward it) -- "
            "try GEMINI_MODEL=gemini-3.5-flash-lite."
            if finish == "MAX_TOKENS"
            else ""
        )
        return {
            "ok": False,
            "error": f"Gemini returned empty text (finishReason: {finish or 'unknown'}).{hint}",
        }

    parsed = _safe_json(content)
    if parsed is None:
        return {
            "ok": False,
            "error": f"Gemini did not return valid JSON (finishReason: {finish or 'unknown'}).",
            "raw": content[:800],
        }

    return {
        "ok": True,
        "model": model,
        "root_cause": _as_text(parsed.get("root_cause", "")),
        "attack_mechanics": _as_text(parsed.get("attack_mechanics", "")),
        "secure_code": _as_text(parsed.get("secure_code", "")),
    }


# --------------------------------------------------------------------------- #
# 6. Public entry point -- routes to whichever provider is configured
# --------------------------------------------------------------------------- #
def remediate(finding: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
    """
    Explain and fix one confirmed finding using the configured provider.

    Set LLM_PROVIDER=gemini (with GEMINI_API_KEY) for the cloud model, or leave
    it unset / set it to 'ollama' to keep everything local and offline.
    Callers don't need to know which one is active -- the return shape is
    identical either way.
    """
    if _provider() == "gemini":
        return _remediate_gemini(finding, model=kwargs.get("model"))
    return _remediate_ollama(finding, **kwargs)


def _as_text(value: Any) -> str:
    """
    Coerce whatever the model put in a field into a clean string. Small models
    sometimes wrap secure_code in an object like {"code": "..."} or a list of
    lines instead of a plain string -- without this, the UI shows the dreaded
    '[object Object]'.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        # a list of code lines (or fragments) -> join into one block
        return "\n".join(_as_text(v) for v in value)
    if isinstance(value, dict):
        # common shapes: {"code": "..."} / {"content": "..."} / {"fix": "..."}
        for key in ("code", "content", "fix", "secure_code", "text", "value"):
            if key in value:
                return _as_text(value[key])
        # fallback: stitch all string-ish values together
        return "\n".join(_as_text(v) for v in value.values())
    return str(value)