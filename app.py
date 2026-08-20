from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from policy import evaluate_release


app = FastAPI()


@app.get("/")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/release-gate")
async def release_gate(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = None
    return JSONResponse(status_code=200, content=evaluate_release(body))
