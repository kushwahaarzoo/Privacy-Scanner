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