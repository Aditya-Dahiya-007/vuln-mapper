"""
sast.py -- Static Application Security Testing engine.

Runs deterministic, open-source static analyzers over a directory of source
code and normalizes their output into a single unified findings schema:

    Bandit  -> Python security issues (offline, no network needed)
    Semgrep -> multi-language rules (first run fetches rules; then cached)

Everything downstream (the Stage 2 AI remediation layer) consumes these
findings. The AI never invents a vulnerability -- it only explains and fixes
ones that a scanner here has already proven exist.

Unified finding schema:
    {
        "tool":       "bandit" | "semgrep",
        "file":       "path/relative/to/scan/root.py",
        "line":       42,
        "severity":   "HIGH" | "MEDIUM" | "LOW",
        "confidence": "HIGH" | "MEDIUM" | "LOW" | "",
        "cwe":        "CWE-89" | None,
        "rule_id":    "B608",
        "title":      "hardcoded_sql_expressions",
        "message":    "Possible SQL injection vector ...",
        "snippet":    "query = \"SELECT ...\" % username",
    }
"""

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

# Give each scanner a hard ceiling so a pathological repo can't hang the request.
SCAN_TIMEOUT = 180  # seconds

# Used to sort findings so the scariest things surface first.
_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _rel(path: str, root: str) -> str:
    """Show paths relative to the scan root, not the ugly /tmp/... prefix."""
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def _normalize_severity_semgrep(sev: str) -> str:
    # Semgrep speaks ERROR/WARNING/INFO; map onto our HIGH/MEDIUM/LOW scale.
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(
        (sev or "").upper(), "LOW"
    )


def _extract_cwe_from_semgrep(metadata: Dict[str, Any]) -> Optional[str]:
    cwe_field = metadata.get("cwe")
    if not cwe_field:
        return None
    # May be a list like ["CWE-89: SQL Injection ..."] or a plain string.
    if isinstance(cwe_field, list):
        cwe_field = cwe_field[0] if cwe_field else ""
    token = str(cwe_field).split(":", 1)[0].strip()  # keep just "CWE-89"
    return token or None


# --------------------------------------------------------------------------- #
# Bandit
# --------------------------------------------------------------------------- #
def _run_bandit(target_dir: str) -> Dict[str, Any]:
    """Run Bandit over target_dir. Returns {'findings': [...], 'error': str|None}."""
    if shutil.which("bandit") is None:
        return {"findings": [], "error": "bandit not installed (pip install bandit)"}

    try:
        proc = subprocess.run(
            ["bandit", "-r", target_dir, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "bandit timed out"}
    except Exception as exc:  # noqa: BLE001
        return {"findings": [], "error": f"bandit failed to run: {exc}"}

    # IMPORTANT: Bandit exits 1 when it *finds* issues. That is success, not
    # failure, so we key off stdout content rather than the return code.
    if not proc.stdout.strip():
        return {"findings": [], "error": None}

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"findings": [], "error": "could not parse bandit output"}

    findings: List[Dict[str, Any]] = []
    for r in data.get("results", []):
        cwe = None
        cwe_obj = r.get("issue_cwe")
        if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
            cwe = f"CWE-{cwe_obj['id']}"
        findings.append(
            {
                "tool": "bandit",
                "file": _rel(r.get("filename", ""), target_dir),
                "line": r.get("line_number", 0),
                "severity": (r.get("issue_severity") or "LOW").upper(),
                "confidence": (r.get("issue_confidence") or "").upper(),
                "cwe": cwe,
                "rule_id": r.get("test_id", ""),
                "title": r.get("test_name", ""),
                "message": r.get("issue_text", ""),
                "snippet": (r.get("code") or "").strip(),
            }
        )
    return {"findings": findings, "error": None}


# --------------------------------------------------------------------------- #
# Semgrep
# --------------------------------------------------------------------------- #
def _run_semgrep(target_dir: str, config: str = "auto") -> Dict[str, Any]:
    """Run Semgrep over target_dir. Returns {'findings': [...], 'error': str|None}."""
    if shutil.which("semgrep") is None:
        return {"findings": [], "error": "semgrep not installed (pip install semgrep)"}

    try:
        proc = subprocess.run(
            ["semgrep", "--config", config, "--json", "--quiet", target_dir],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "semgrep timed out"}
    except Exception as exc:  # noqa: BLE001
        return {"findings": [], "error": f"semgrep failed to run: {exc}"}

    if not proc.stdout.strip():
        # Semgrep reports rule/config problems on stderr; surface the last line.
        hint = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "no output"
        return {"findings": [], "error": f"semgrep returned nothing ({hint})"}

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"findings": [], "error": "could not parse semgrep output"}

    findings: List[Dict[str, Any]] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        check_id = r.get("check_id", "")
        findings.append(
            {
                "tool": "semgrep",
                "file": _rel(r.get("path", ""), target_dir),
                "line": r.get("start", {}).get("line", 0),
                "severity": _normalize_severity_semgrep(extra.get("severity", "INFO")),
                "confidence": str(metadata.get("confidence", "")).upper(),
                "cwe": _extract_cwe_from_semgrep(metadata),
                "rule_id": check_id,
                "title": check_id.split(".")[-1] or "finding",
                "message": (extra.get("message") or "").strip(),
                "snippet": (extra.get("lines") or "").strip(),
            }
        )
    return {"findings": findings, "error": None}


# --------------------------------------------------------------------------- #
# orchestrator
# --------------------------------------------------------------------------- #
def analyze_directory(target_dir: str, semgrep_config: str = "auto") -> Dict[str, Any]:
    """
    Run every available analyzer over target_dir and return a unified report:

        {
            "findings": [ ...normalized findings, most severe first... ],
            "summary":  {"total": n, "high": h, "medium": m, "low": l},
            "tools":    {"bandit": {"ran": bool, "error": str|None},
                         "semgrep": {"ran": bool, "error": str|None}},
        }

    If one scanner is missing or errors, the other still runs -- so you get
    Bandit results offline even if Semgrep can't fetch its rules.
    """
    if not os.path.isdir(target_dir):
        return {
            "findings": [],
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0},
            "tools": {},
            "error": f"not a directory: {target_dir}",
        }

    bandit = _run_bandit(target_dir)
    semgrep = _run_semgrep(target_dir, config=semgrep_config)

    findings = bandit["findings"] + semgrep["findings"]
    findings.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 9), f["file"], f["line"]))

    summary = {
        "total": len(findings),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] in ("LOW", "INFO")),
    }

    return {
        "findings": findings,
        "summary": summary,
        "tools": {
            "bandit": {"ran": bandit["error"] is None, "error": bandit["error"]},
            "semgrep": {"ran": semgrep["error"] is None, "error": semgrep["error"]},
        },
    }