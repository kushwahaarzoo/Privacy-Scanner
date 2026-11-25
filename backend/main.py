import logging
import threading
import time
import uuid
import json
import re
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from fastapi.responses import FileResponse

from backend.scanner.browser import scan_website
from backend.scanner.consent import scan_consent_behavior
from backend.scanner.privacy_signals import scan_privacy_signals
from backend.scanner.privacy_policy import scan_privacy_policy
from backend.scanner.security import assert_public_url

# NOTE: full_audit is imported lazily inside _run_audit_job, so a problem in
# the audit modules cannot stop the API from starting.

logger = logging.getLogger("privacy_scanner")

app = FastAPI(
    title="Privacy Scanner",
    description="Automated website privacy scanner",
    version="0.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# One worker: audits run one at a time, so browsers don't pile up.
_executor = ThreadPoolExecutor(max_workers=1)
_jobs: dict = {}
_jobs_lock = threading.Lock()

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)
FRONTEND_DIR = BASE_DIR.parent / "frontend"
_JOB_ID_RE = re.compile(r"^[a-f0-9]{32}$")


def _save_job(job_id: str, job: dict) -> None:
    try:
        with open(REPORT_DIR / f"{job_id}.json", "w", encoding="utf-8") as f:
            json.dump(job, f, default=str)
    except Exception:
        logger.exception("Could not save report %s", job_id)


def _load_job(job_id: str):
    if not _JOB_ID_RE.match(job_id):      # blocks path traversal
        return None
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job:
        return job
    path = REPORT_DIR / f"{job_id}.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None

class ScanRequest(BaseModel):
    url: HttpUrl


def _check_url(url: str) -> None:
    """Shared validation + SSRF guard. Raises HTTP 400 on bad input."""
    try:
        assert_public_url(url)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get("/")
def root():
    return {"name": "Privacy Scanner", "version": "0.3.0", "status": "running"}


@app.post("/scan")
def scan(request: ScanRequest):
    url = str(request.url)
    _check_url(url)

    try:
        return {"success": True, "result": scan_website(url)}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception:
        logger.exception("Level 2 scan failed")
        raise HTTPException(
            status_code=500,
            detail="Scan failed. Check the server logs.",
        )


@app.post("/scan/consent")
def scan_consent(request: ScanRequest):
    url = str(request.url)
    _check_url(url)

    try:
        return {"success": True, "result": scan_consent_behavior(url)}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception:
        logger.exception("Consent scan failed")
        raise HTTPException(
            status_code=500,
            detail="Consent scan failed. Check the server logs.",
        )


@app.post("/scan/fingerprints")
def scan_fingerprints(request: ScanRequest):
    url = str(request.url)
    _check_url(url)

    try:
        return {"success": True, "result": scan_privacy_signals(url)}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception:
        logger.exception("Level 4 scan failed")
        raise HTTPException(
            status_code=500,
            detail="Level 4 scan failed. Check the server logs.",
        )


@app.post("/scan/reports")
def scan_reports(request: ScanRequest):
    url = str(request.url)
    _check_url(url)

    try:
        return {"success": True, "level": 5, "result": scan_privacy_policy(url)}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception:
        logger.exception("Level 5 privacy policy scan failed")
        raise HTTPException(
            status_code=500,
            detail="Level 5 scan failed. Check the server logs.",
        )


# ---------------------------------------------------------------------------
# Full audit (background job + polling)
# ---------------------------------------------------------------------------

def _run_audit_job(job_id: str, url: str) -> None:
    with _jobs_lock:
        _jobs[job_id]["status"] = "running"
        _jobs[job_id]["started_at"] = time.time()

    try:
        from backend.scanner.audit import full_audit

        def progress(stage: str) -> None:
            with _jobs_lock:
                _jobs[job_id]["stage"] = stage

        result = full_audit(url, on_progress=progress)
        src = result.pop("_screenshot_src", None)
        if src and Path(src).exists():
            shutil.copyfile(src, REPORT_DIR / f"{job_id}.png")
            result["has_screenshot"] = True

        with _jobs_lock:
            _jobs[job_id].update(status="done", result=result, stage="finished")
            snapshot = dict(_jobs[job_id])
        _save_job(job_id, snapshot)
    
    except Exception as exc:
        logger.exception("Audit job %s failed", job_id)
        with _jobs_lock:
            _jobs[job_id].update(
                status="failed",
                error=f"{type(exc).__name__}: {exc}",
            )
    finally:
        with _jobs_lock:
            _jobs[job_id]["finished_at"] = time.time()


@app.post("/audit")
def start_audit(request: ScanRequest):
    url = str(request.url)
    _check_url(url)

    job_id = uuid.uuid4().hex

    with _jobs_lock:
        _jobs[job_id] = {
            "status": "queued",
            "url": url,
            "created_at": time.time(),
        }

    _executor.submit(_run_audit_job, job_id, url)

    return {"success": True, "job_id": job_id, "status": "queued"}


@app.get("/audit/{job_id}")
def get_audit(job_id: str):
    job = _load_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job id.")
    return job


@app.get("/audit/{job_id}/pdf")
def get_audit_pdf(job_id: str):
    job = _load_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job id.")
    if job.get("status") != "done":
        raise HTTPException(status_code=409, detail="Audit not finished yet.")

    from backend.scanner.report_pdf import build_pdf

    pdf = build_pdf(job["result"])
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename="privacy-audit-{job_id[:8]}.pdf"'
        },
    )


@app.get("/reports")
def list_reports():
    items = []
    files = sorted(REPORT_DIR.glob("*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)[:50]
    for p in files:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            r = d.get("result") or {}
            items.append({
                "job_id": p.stem,
                "url": d.get("url"),
                "status": d.get("status"),
                "score": (r.get("score") or {}).get("score"),
                "grade": (r.get("score") or {}).get("grade"),
            })
        except Exception:
            continue
    return items

@app.get("/audit/{job_id}/screenshot")
def get_screenshot(job_id: str):
    if not _JOB_ID_RE.match(job_id):
        raise HTTPException(status_code=404, detail="Not found.")
    path = REPORT_DIR / f"{job_id}.png"
    if not path.exists():
        raise HTTPException(status_code=404, detail="No screenshot.")
    return FileResponse(path, media_type="image/png")


if FRONTEND_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="ui")