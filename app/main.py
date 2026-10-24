from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time

from app.logging_config import logger
from discovery.models import Discovery
from module.modules import Modules
from module.pentest_report import build_pentest_report
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
def scan(target: str, num: int = 1000, auto_jwt_local_lab: bool = False):
    normalized_target = validate_target(target)
    logger.info("Scan started | target=%s | dictionary_size=%d", normalized_target, num)

    try:
        discovery = Discovery()
        endpoints = discovery.discover(normalized_target, num)
        analyzed = Modules().analyze_endpoints(
            normalized_target,
            endpoints,
            auto_jwt_local_lab=auto_jwt_local_lab,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (FileNotFoundError, RuntimeError, TimeoutError) as exc:
        logger.exception("Scan failed | target=%s | error=%s", normalized_target, str(exc))
        report = build_pentest_report(
            scan_failed=True,
            failure_reason="Discovery or scan execution failed before evidence collection.",
        )
        return JSONResponse(
            status_code=424,
            content={
                "detail": str(exc),
                "target": normalized_target,
                "summary": report["summary"],
                "findings": report["findings"],
                "test_results": report["test_results"],
                "endpoint_assessments": report["endpoint_assessments"],
            },
        )

    report = build_pentest_report(analyzed)
    summary = report["summary"]
    discovered_count = summary["discovered_endpoints"]
    allowlist_targets = sorted(
        {
            (endpoint.get("method"), endpoint.get("path"))
            for endpoint in analyzed
            if endpoint.get("jwt_allowlisted")
        }
    )
    summary.update(
        {
            "total_endpoints": discovered_count,
            "selected_endpoints": sum(
                1 for endpoint in analyzed if endpoint.get("jwt_selected")
            ),
            "skipped_endpoints": sum(
                1
                for endpoint in analyzed
                if endpoint.get("discovery_source") == "discovery"
                and not endpoint.get("jwt_selected")
            ),
            "skipped_endpoint_reasons": [
                {
                    "method": endpoint.get("method"),
                    "path": endpoint.get("path"),
                    "reason": endpoint.get("jwt_selection_reason"),
                }
                for endpoint in analyzed
                if endpoint.get("discovery_source") == "discovery"
                and not endpoint.get("jwt_selected")
            ],
            "total_test_targets": len(analyzed),
            "jwt_allowlist_configured": bool(allowlist_targets),
            "jwt_selection_mode": next(
                (
                    endpoint.get("jwt_selection_mode")
                    for endpoint in analyzed
                    if endpoint.get("jwt_selection_mode")
                ),
                "not_confirmed",
            ),
            "jwt_allowlist_entries": len(allowlist_targets),
            "jwt_allowlist_targets": [
                {"method": method, "path": path}
                for method, path in allowlist_targets
            ],
            "not_vulnerable": summary["not_detected_test_cases"],
            "auth_endpoints": sum(
                1
                for endpoint in analyzed
                if endpoint.get("discovery_source") == "discovery"
                and endpoint.get("classification") == "authentication"
            ),
        }
    )

    logger.info("Scan completed | target=%s | endpoints_found=%d", normalized_target, discovered_count)
    return {
        "target": normalized_target,
        "results": analyzed,
        "summary": summary,
        "findings": report["findings"],
        "test_results": report["test_results"],
        "endpoint_assessments": report["endpoint_assessments"],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
