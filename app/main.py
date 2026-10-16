import sys
from pathlib import Path

from fastapi import FastAPI
import httpx

from fastapi.middleware.cors import CORSMiddleware

from discovery.models import Discovery
from module.modules import Modules 

import logging
import time

from fastapi import Request
from app.logging_config import logger

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        duration_ms = (time.perf_counter() - start_time) * 1000

        logger.exception(
            "Unhandled exception | method=%s | path=%s | duration_ms=%.2f",
            request.method,
            request.url.path,
            duration_ms,
        )
        raise

    duration_ms = (time.perf_counter() - start_time) * 1000

    logger.info(
        "HTTP request | method=%s | path=%s | status=%s | duration_ms=%.2f",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )

    return response


@app.get("/")
def home():
    return {"message": "app is running"}



@app.get("/scan")
def scan(target: str, num: int = 1000):
    logger.info(
        "Scan started | target=%s | dictionary_size=%d",
        target,
        num,
    )

    discovery = Discovery()
    results = discovery.discover(target, num)

    logger.info(
        "Scan completed | target=%s | endpoints_found=%d",
        target,
        len(results),
    )

    return {"target": target, "results": results}



if __name__ == "__main__":
    
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

