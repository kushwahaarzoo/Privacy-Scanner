from fastapi import (
    FastAPI,
    HTTPException,
)

from pydantic import (
    BaseModel,
    HttpUrl,
)

from backend.scanner.browser import (
    scan_website,
)

from backend.scanner.consent import scan_consent_behavior


from urllib.parse import urlparse

from backend.scanner.privacy_signals import scan_privacy_signals
from backend.scanner.privacy_policy import scan_privacy_policy

app = FastAPI(
    title="Privacy Scanner",
    description=(
        "Automated website "
        "privacy scanner"
    ),
    version="0.2.0",
)


class ScanRequest(BaseModel):

    url: HttpUrl


@app.get("/")
def root():

    return {
        "name":
            "Privacy Scanner",

        "version":
            "0.2.0",

        "status":
            "running",
    }


@app.post("/scan")
def scan(
    request: ScanRequest,
):

    try:

        result = scan_website(
            str(request.url)
        )

        return {
            "success": True,

            "result": result,
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,

            detail=str(error),
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,

            detail=(
                f"Scan failed: "
                f"{str(error)}"
            ),
        )

    
@app.post("/scan/consent")
def scan_consent(request: ScanRequest):
    try:
        result = scan_consent_behavior(str(request.url))

        return {
            "success": True,
            "result": result,
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception:
        # Avoid returning internal exception details to API clients.
        raise HTTPException(
            status_code=500,
            detail="Consent scan failed. Check the server logs.",
        )



@app.post("/scan/fingerprints")
def scan_fingerprints(request: ScanRequest):
    url = str(request.url)
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="A valid HTTP or HTTPS URL is required.",
        )

    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=400,
            detail="URLs containing credentials are not allowed.",
        )

    try:
        result = scan_privacy_signals(url)

        return {
            "success": True,
            "result": result,
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception:
        # Do not expose internal errors or sensitive details.
        raise HTTPException(
            status_code=500,
            detail="Level 4 scan failed. Check the server logs.",
        )



@app.post("/scan/reports")
def scan_reports(request: ScanRequest):
    url = str(request.url)
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="A valid HTTP or HTTPS URL is required.",
        )

    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=400,
            detail="URLs containing credentials are not allowed.",
        )

    try:
        result = scan_privacy_policy(url)
        return {
            "success": True,
            "level": 5,
            "result": result,
        }
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception:
        # Keep internal exception details in server logs, not API responses.
        import logging
        logging.exception("Level 5 privacy policy scan failed")
        raise HTTPException(
            status_code=500,
            detail="Level 5 scan failed. Check the server logs.",
        )
