from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import time

from app.logging_config import logger
from discovery.models import Discovery
from module.modules import Modules
from module.signin import LoginConfigurationError, Signin

app = FastAPI(title="MicroScan API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def validate_target(target: str):
    try:
        return Signin.normalize_target(target)
    except LoginConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
    normalized_target = validate_target(target)
    logger.info("Scan started | target=%s | dictionary_size=%d", normalized_target, num)

    try:
        discovery = Discovery()
        endpoints = discovery.discover(normalized_target, num)
        analyzed = Modules().analyze_endpoints(normalized_target, endpoints)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (FileNotFoundError, RuntimeError, TimeoutError) as exc:
        logger.exception("Scan failed | target=%s | error=%s", normalized_target, str(exc))
        raise HTTPException(status_code=424, detail=str(exc)) from exc

    findings = []
    for endpoint in analyzed:
        for result in endpoint.get("test_results", []) or []:
            if result.get("status") in {
                "confirmed",
                "potential",
                "not_vulnerable_in_test",
                "inconclusive",
                "skipped",
                "error",
            }:
                findings.append({
                    "endpoint": endpoint.get("path") or endpoint.get("target") or "/",
                    "method": endpoint.get("method"),
                    "module": result.get("test_module"),
                    "status": result.get("status"),
                    "reason": result.get("reason"),
                    "tested_endpoint": result.get("tested_endpoint"),
                    "endpoint_selection_reason": result.get("endpoint_selection_reason"),
                    "discovery": result.get("discovery"),
                    "unauthenticated_checks": result.get("unauthenticated_checks", []),
                    "authenticated_check": result.get("authenticated_check"),
                    "authentication_mechanism": result.get("authentication_mechanism", "unknown"),
                    "evidence": result.get("evidence", []),
                })

    summary = {
        "total_endpoints": len(analyzed),
        "auth_endpoints": sum(1 for endpoint in analyzed if endpoint.get("classification") == "authentication"),
        "potential_findings": sum(1 for item in findings if item["status"] == "potential"),
        "not_vulnerable": sum(1 for item in findings if item["status"] == "not_vulnerable_in_test"),
        "skipped_tests": sum(1 for item in findings if item["status"] == "skipped"),
        "inconclusive_tests": sum(1 for item in findings if item["status"] == "inconclusive"),
        "error_tests": sum(1 for item in findings if item["status"] == "error"),
    }

    logger.info("Scan completed | target=%s | endpoints_found=%d", normalized_target, len(analyzed))
    return {
        "target": normalized_target,
        "results": analyzed,
        "summary": summary,
        "findings": findings,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
