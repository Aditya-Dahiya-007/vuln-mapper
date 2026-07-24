import os
import shutil
import tempfile
import threading
import zipfile
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner.recon import scan_ports
from scanner.vuln_api import check_cve
from scanner.fuzzer import run_fuzzer
from analyzer.sast import analyze_directory
from analyzer.remediation import attach_context, remediate, check_ollama
import db
from report import build_report

app = FastAPI()
db.init_db()


# ============================================================================ #
# CORE SCAN LOGIC  (shared by the sync endpoints and the background jobs)
# ============================================================================ #
def _do_recon(target: str):
    """Run a full recon pass. Returns (result_dict, summary_dict)."""
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].strip()
    ports = scan_ports(clean_target)

    recon_results = []
    is_web_server = False
    for p in ports:
        raw_banner = p.get("version", "")
        vulns = check_cve(raw_banner)
        if p.get("port") in [80, 443, 8000]:
            is_web_server = True
        recon_results.append(
            {"port": p.get("port"), "service_banner": raw_banner, "vulnerabilities": vulns}
        )

    hidden_directories = run_fuzzer(clean_target) if is_web_server else []

    result = {"target": clean_target, "recon": recon_results, "directories": hidden_directories}
    summary = {"ports": len(recon_results), "directories": len(hidden_directories)}
    return result, summary


def _safe_extract_zip(zip_path: str, dest_dir: str) -> None:
    """Extract a zip while preventing path traversal ('zip-slip')."""
    dest_root = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = os.path.realpath(os.path.join(dest_dir, member))
            if target != dest_root and not target.startswith(dest_root + os.sep):
                raise ValueError(f"unsafe path in archive: {member}")
        zf.extractall(dest_dir)


def _do_audit(zip_bytes: bytes, filename: str):
    """Run SAST over an uploaded zip's bytes. Returns (result_dict, summary_dict)."""
    work_dir = tempfile.mkdtemp(prefix="vulnmapper_sast_")
    zip_path = os.path.join(work_dir, "upload.zip")
    code_dir = os.path.join(work_dir, "code")
    os.makedirs(code_dir, exist_ok=True)
    try:
        with open(zip_path, "wb") as out:
            out.write(zip_bytes)
        _safe_extract_zip(zip_path, code_dir)
        result = analyze_directory(code_dir)
        attach_context(result["findings"], code_dir)
        result["filename"] = filename
        return result, result.get("summary", {})
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


# ============================================================================ #
# BACKGROUND JOB RUNNERS (each runs in its own thread, writing status to SQLite)
# ============================================================================ #
def _run_recon_job(sid: str, target: str):
    try:
        result, summary = _do_recon(target)
        db.finish_scan(sid, result, summary)
    except Exception as exc:  # noqa: BLE001
        db.fail_scan(sid, exc)


def _run_audit_job(sid: str, zip_bytes: bytes, filename: str):
    try:
        result, summary = _do_audit(zip_bytes, filename)
        db.finish_scan(sid, result, summary)
    except Exception as exc:  # noqa: BLE001
        db.fail_scan(sid, exc)


# ============================================================================ #
# API ROUTES  (before the StaticFiles mount, or the mount swallows them)
# ============================================================================ #

# ---- Async job endpoints (used by the UI: start -> poll) ------------------- #
@app.post("/api/scan/start")
def scan_start(target: str):
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].strip()
    if not clean_target:
        raise HTTPException(status_code=400, detail="enter a target host")
    sid = db.create_scan("recon", clean_target)
    threading.Thread(target=_run_recon_job, args=(sid, target), daemon=True).start()
    return {"job_id": sid}


@app.post("/api/analyze/start")
async def analyze_start(file: UploadFile = File(...)):
    filename = file.filename or "archive.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="please upload a .zip archive")
    data = await file.read()
    sid = db.create_scan("audit", filename)
    threading.Thread(target=_run_audit_job, args=(sid, data, filename), daemon=True).start()
    return {"job_id": sid}


@app.get("/api/job/{job_id}")
def job_status(job_id: str):
    scan = db.get_scan(job_id)
    if not scan:
        raise HTTPException(status_code=404, detail="job not found")
    return scan


# ---- History ---------------------------------------------------------------- #
@app.get("/api/history")
def history(limit: int = 25):
    return {"scans": db.list_scans(limit)}


@app.delete("/api/history/{job_id}")
def history_delete(job_id: str):
    db.delete_scan(job_id)
    return {"deleted": job_id}


# ---- PDF report ------------------------------------------------------------- #
@app.get("/api/report/{job_id}")
def report_pdf(job_id: str):
    scan = db.get_scan(job_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    if scan.get("status") != "done":
        raise HTTPException(status_code=409, detail="scan has not finished yet")
    pdf_bytes = build_report(scan)
    safe = (scan.get("label") or job_id).replace("/", "_").replace(" ", "_")
    headers = {"Content-Disposition": f'attachment; filename="vulnmapper_{safe}.pdf"'}
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


# ---- AI-remediated PDF report (loops the model over every finding) ---------- #
def _run_ai_report_job(ai_id: str, scan: dict):
    try:
        result = dict(scan.get("result") or {})
        findings = list(result.get("findings", []))

        # Dedup exact duplicates (same cwe/file/line) so an identical flaw flagged
        # by both Bandit and Semgrep isn't sent to the slow model twice.
        rem_cache = {}
        order = []
        for f in findings:
            key = (f.get("cwe"), f.get("file"), f.get("line"))
            if key not in rem_cache:
                rem_cache[key] = None
                order.append((key, f))

        total = len(order)
        db.set_summary(ai_id, {"done": 0, "total": total})

        for i, (key, f) in enumerate(order, 1):
            res = remediate(f)
            if not res.get("ok"):
                # Fail the whole report, but say exactly which finding broke.
                db.fail_scan(
                    ai_id,
                    f"Failed on finding {i}/{total} "
                    f"({f.get('title') or f.get('rule_id') or 'finding'}): {res.get('error')}",
                )
                return
            rem_cache[key] = {
                "root_cause": res.get("root_cause", ""),
                "attack_mechanics": res.get("attack_mechanics", ""),
                "secure_code": res.get("secure_code", ""),
                "model": res.get("model", ""),
            }
            db.set_summary(ai_id, {"done": i, "total": total})

        # Attach each fix back onto every finding (duplicates share the cached fix).
        for f in findings:
            f["remediation"] = rem_cache.get((f.get("cwe"), f.get("file"), f.get("line")))
        result["findings"] = findings
        db.finish_scan(ai_id, result, {"total": total, "remediated": total})
    except Exception as exc:  # noqa: BLE001
        db.fail_scan(ai_id, exc)


@app.post("/api/report/ai/{scan_id}/start")
def ai_report_start(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    if scan.get("kind") != "audit":
        raise HTTPException(status_code=400, detail="AI reports are only for code audits")
    if scan.get("status") != "done":
        raise HTTPException(status_code=409, detail="scan has not finished yet")
    findings = (scan.get("result") or {}).get("findings", [])
    if not findings:
        raise HTTPException(status_code=400, detail="no findings to remediate")

    ai_id = db.create_scan("ai_report", scan.get("label", ""))
    threading.Thread(target=_run_ai_report_job, args=(ai_id, scan), daemon=True).start()
    # The finished report is downloaded via the existing GET /api/report/{ai_id}.
    return {"job_id": ai_id, "total": len(findings)}


# ---- Synchronous endpoints (kept for /docs testing & backward compat) ------- #
@app.get("/api/scan")
def run_scan(target: str):
    result, _ = _do_recon(target)
    return result


@app.post("/api/analyze")
async def analyze_code(file: UploadFile = File(...)):
    filename = (file.filename or "").lower()
    if not filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="please upload a .zip archive of your source code")
    data = await file.read()
    result, _ = _do_audit(data, file.filename or "archive.zip")
    return result


# ---- AI remediation (Stage 2) ---------------------------------------------- #
class Finding(BaseModel):
    tool: str = ""
    file: str = ""
    line: int = 0
    severity: str = ""
    cwe: Optional[str] = None
    rule_id: str = ""
    title: str = ""
    message: str = ""
    snippet: str = ""
    context: str = ""


@app.post("/api/remediate")
def remediate_finding(finding: Finding):
    return remediate(finding.dict())


@app.get("/api/llm-status")
def llm_status():
    return check_ollama()


# ============================================================================ #
# Mount the frontend LAST
# ============================================================================ #
app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")