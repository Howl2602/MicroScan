import asyncio
import ast
import json
import os
import re
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from app.logging_config import logger
from discovery.file_discovery import DEFAULT_WORDLIST, FileDiscovery, normalize_origin
from discovery.models import Discovery
from module.modules import Modules
from module.pentest_report import build_pentest_report
from module.signin import LoginConfigurationError, Signin

app = FastAPI(title="MicroScan API", version="1.0.0")

TRUSTED_LOCAL_LAB_PROFILES = {
    ("localhost", 3000): ("http://localhost:8085",),
    ("localhost", 8085): (),
    ("127.0.0.1", 3000): ("http://127.0.0.1:8085",),
    ("127.0.0.1", 8085): (),
    ("::1", 3000): ("http://[::1]:8085",),
    ("::1", 8085): (),
}


@dataclass(frozen=True)
class RecursiveDiscoveryLimits:
    max_depth: int = 3
    max_origins: int = 3
    max_seeds_per_round: int = 50
    max_rounds: int = 4
    command_timeout_seconds: int = 45


DISCOVERY_LIMITS = RecursiveDiscoveryLimits()


class FileDiscoveryRequest(BaseModel):
    target: str = Field(max_length=2048)
    wordlist: str | None = Field(default=None, max_length=20000)
    requests_per_second: float = Field(default=2, ge=0.5, le=5)
    timeout: float = Field(default=5, ge=1, le=15)
    concurrency: int = Field(default=2, ge=1, le=5)
    analyze_javascript: bool = True
    verify_endpoints: bool = False
    gateway_target: str | None = Field(default=None, max_length=2048)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def validate_target(target: str):
    try:
        return Signin.normalize_target(target)
    except LoginConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _configured_gateway_target():
    Signin.load_environment()
    configured = os.environ.get("MICROSCAN_GATEWAY_TARGET", "").strip()
    if not configured:
        return None
    try:
        return normalize_origin(validate_target(configured)).rstrip("/")
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"MICROSCAN_GATEWAY_TARGET is outside the authorized local lab scope: {exc}",
        ) from exc


def _normalized_scope_origin(value):
    normalized = validate_target(value)
    parts = urlsplit(normalized)
    hostname = (parts.hostname or "").lower()
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return normalize_origin(normalized).rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), "", "", ""))


def _authorized_scan_scope(target, scope_origins, legacy_gateway=None):
    origins = [_normalized_scope_origin(target)]
    parsed_target = urlsplit(origins[0])
    profile_origins = TRUSTED_LOCAL_LAB_PROFILES.get(
        ((parsed_target.hostname or "").lower(), parsed_target.port or 80),
        (),
    )
    for origin in profile_origins:
        normalized = _normalized_scope_origin(origin)
        if normalized not in origins:
            origins.append(normalized)
    for origin in [*(scope_origins or []), legacy_gateway]:
        if not origin:
            continue
        normalized = _normalized_scope_origin(origin)
        if normalized not in origins:
            origins.append(normalized)
    return origins


def _static_api_seed_path(value):
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        return None
    if (
        not re.match(r"^/api(?:/|$)", value, re.IGNORECASE)
        or value == "/"
        or any(character.isspace() for character in value)
        or "\\" in value
        or "?" in value
        or "#" in value
        or "${" in value
        or re.search(r"\{[^/}]+\}|(?<![\w]):[A-Za-z_$][\w$]*(?=/|$)", value)
    ):
        return None
    return value


def _static_route_path(value):
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        return None
    if (
        any(character.isspace() for character in value)
        or "\\" in value
        or "?" in value
        or "#" in value
        or "${" in value
        or re.search(r"\{[^/}]+\}|(?<![\w]):[A-Za-z_$][\w$]*(?=/|$)", value)
    ):
        return None
    return value


def _javascript_root_origin(item):
    sources = item.get("sources")
    url = item.get("url")
    if (
        not isinstance(sources, list)
        or "javascript" not in sources
        or item.get("is_api_endpoint") is True
        or not isinstance(url, str)
    ):
        return None
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.netloc
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        ):
            return _normalized_scope_origin(
                urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
            )
    except (ValueError, HTTPException):
        return None
    return None


def _javascript_api_base(item):
    sources = item.get("sources")
    url = item.get("url")
    evidence = item.get("evidence")
    if (
        not isinstance(sources, list)
        or "javascript" not in sources
        or not isinstance(url, str)
        or not any(
            isinstance(entry, dict)
            and isinstance(entry.get("snippet"), str)
            and re.search(
                r"(?i)\b(?:api[_-]?(?:base|url)|base[_-]?url)\b",
                entry["snippet"],
            )
            for entry in (evidence if isinstance(evidence, list) else [])
        )
    ):
        return None
    try:
        parsed = urlsplit(url)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path or "/", "", "")
            )
    except ValueError:
        return None
    return None


def _safe_seed_evidence(evidence):
    safe = []
    for entry in evidence if isinstance(evidence, list) else []:
        if not isinstance(entry, dict):
            continue
        source_url = entry.get("source_url")
        if isinstance(source_url, str):
            try:
                parts = urlsplit(source_url)
                if parts.scheme and parts.netloc:
                    source_url = urlunsplit(
                        (parts.scheme, parts.netloc, parts.path, "", "")
                    )
            except ValueError:
                source_url = "[invalid source URL]"
        snippet = entry.get("snippet")
        if isinstance(snippet, str):
            snippet = re.sub(
                r"""(?i)(authorization|cookie|password|passwd|token|api[_-]?key|secret)(\s*[:=]\s*)(["']?)[^"'\s,;}]+""",
                r"\1\2\3[REDACTED]",
                snippet,
            )
            snippet = snippet[:240]
        safe.append(
            {
                "source_url": source_url,
                "snippet": snippet,
            }
        )
    return safe


def _safe_command_arguments(command):
    safe = []
    for argument in command if isinstance(command, (list, tuple)) else []:
        value = str(argument)
        value = re.sub(
            r"""(?i)(token|password|passwd|api[_-]?key|secret)(=|:)([^&\s]+)""",
            r"\1\2[REDACTED]",
            value,
        )
        safe.append(value)
    return safe


def _command_from_error(error):
    match = re.search(r"command=(\[[^\]]*\])", str(error))
    if not match:
        return []
    try:
        command = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError):
        return []
    return _safe_command_arguments(command)


def _safe_inventory_url(value):
    if not isinstance(value, str):
        return None
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.hostname:
            return parts.path[:300] if parts.path.startswith("/") else "[invalid URL]"
        hostname = parts.hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        port = f":{parts.port}" if parts.port else ""
        return urlunsplit(
            (parts.scheme.lower(), f"{hostname}{port}", parts.path[:300], "", "")
        )
    except ValueError:
        return "[invalid URL]"


def _recursive_seed_batches(file_result, frontend_target, authorized_origins):
    records = file_result.get("results", []) if isinstance(file_result, dict) else []
    allowed = set(authorized_origins)
    frontend_origin = _normalized_scope_origin(frontend_target)
    frontend_parts = urlsplit(frontend_origin)
    trusted_local_origins = TRUSTED_LOCAL_LAB_PROFILES.get(
        ((frontend_parts.hostname or "").lower(), frontend_parts.port or 80),
        (),
    )
    configured_gateway = None
    if raw_gateway := os.environ.get("MICROSCAN_GATEWAY_TARGET", "").strip():
        try:
            configured_gateway = _normalized_scope_origin(raw_gateway)
        except (ValueError, HTTPException):
            configured_gateway = None
    paths_by_origin = {}
    relative_paths = []
    base_urls_by_origin = {}
    diagnostics = []
    for item in records:
        if not isinstance(item, dict):
            continue
        sources = item.get("sources")
        source_list = sources if isinstance(sources, list) else []
        if not any(source in {"javascript", "html"} for source in source_list):
            continue
        evidence = item.get("evidence")
        base_constant = "javascript" in source_list and any(
            isinstance(entry, dict)
            and isinstance(entry.get("snippet"), str)
            and re.search(
                r"(?i)\b(?:api[_-]?(?:base|url)|base[_-]?url)\b",
                entry["snippet"],
            )
            for entry in (evidence if isinstance(evidence, list) else [])
        )
        root_origin = _javascript_root_origin(item)
        explicit_api_base = _javascript_api_base(item)
        method = str(item.get("method") or "GET").upper()
        raw_url = item.get("url")
        discovered_url = item.get("discovered_url") or item.get("discovered_path")
        diagnostic = {
            "original_path": discovered_url or raw_url or item.get("template"),
            "original_url": raw_url,
            "observed_method": method,
            "source": source_list,
            "source_evidence": _safe_seed_evidence(evidence),
            "resolved_origin": None,
            "resolved_url": None,
            "scope_authorized": False,
            "classification": "dynamic" if item.get("is_template") or item.get("template") else "static",
            "seed_path": None,
            "runner_method": "GET",
            "seed_eligible": False,
            "exclusion_reason": None,
        }
        if item.get("is_template") or item.get("template"):
            diagnostic["exclusion_reason"] = "Dynamic URL template; literal requests are prohibited."
            diagnostics.append(diagnostic)
            continue
        path = None
        if isinstance(discovered_url, str):
            try:
                parsed_discovered = urlsplit(discovered_url)
                path_value = (
                    parsed_discovered.path
                    if parsed_discovered.scheme and parsed_discovered.netloc
                    else discovered_url
                )
                path = _static_api_seed_path(path_value)
            except ValueError:
                path = None
        if not path and isinstance(raw_url, str):
            try:
                path = _static_api_seed_path(urlsplit(raw_url).path)
            except ValueError:
                path = None
        endpoint_classification = str(item.get("classification") or "").lower()
        direct_route_evidence = (
            bool({"javascript", "html"} & set(source_list))
            and isinstance(evidence, list)
            and any(
                isinstance(entry, dict)
                and (
                    isinstance(entry.get("snippet"), str)
                    or isinstance(entry.get("source_url"), str)
                )
                for entry in evidence
            )
        )
        classified_api_route = (
            item.get("is_api_endpoint") is True
            or endpoint_classification in {"api_endpoint", "api endpoint"}
        )
        if endpoint_classification == "frontend_route":
            diagnostic["exclusion_reason"] = (
                "Discovery classified this record as a frontend route, not an API route."
            )
            diagnostics.append(diagnostic)
            continue
        content_type = str(
            item.get("content_type") or item.get("response_content_type") or ""
        ).split(";", 1)[0].strip().lower()
        raw_status_code = item.get("status_code") or item.get("status")
        try:
            status_code = int(raw_status_code) if raw_status_code is not None else None
        except (TypeError, ValueError):
            status_code = None
        if (
            item.get("verification_status") == "not_found"
            or content_type in {"text/html", "application/xhtml+xml"}
            and isinstance(status_code, int)
            and 200 <= status_code < 300
        ):
            diagnostic["exclusion_reason"] = (
                "Discovery response indicates a missing route or frontend HTML fallback."
            )
            diagnostics.append(diagnostic)
            continue
        if not (classified_api_route or (path and direct_route_evidence)):
            base_url = explicit_api_base or (
                f"{root_origin}/" if root_origin else None
            )
            if base_url:
                base_parts = urlsplit(base_url)
                base_origin = _normalized_scope_origin(
                    urlunsplit(
                        (
                            base_parts.scheme,
                            base_parts.netloc,
                            "",
                            "",
                            "",
                        )
                    )
                )
                diagnostic["resolved_origin"] = base_origin
                diagnostic["resolved_url"] = base_url
                diagnostic["scope_authorized"] = base_origin in allowed
                if base_origin in allowed:
                    base_urls_by_origin.setdefault(base_origin, set()).add(base_url)
                    diagnostic["exclusion_reason"] = (
                        "Origin evidence only; root URL is not an API route."
                        if root_origin
                        else "API base evidence only; base URL is not an API route."
                    )
                else:
                    diagnostic["exclusion_reason"] = (
                        "API base origin is outside the authorized scan scope."
                    )
            else:
                diagnostic["exclusion_reason"] = (
                    "Discovery record is not classified as an API endpoint or API base."
                )
            diagnostics.append(diagnostic)
            continue
        if not path:
            diagnostic["exclusion_reason"] = (
                "No static /api/* path could be extracted from the original discovery URL."
            )
            diagnostics.append(diagnostic)
            continue
        diagnostic["original_path"] = discovered_url or path
        diagnostic["seed_path"] = path
        candidate_url = (
            item.get("resolved_url")
            or item.get("verification_url")
            or raw_url
        )
        has_resolved_origin = bool(
            item.get("resolved_url") or item.get("verification_url")
        )
        try:
            discovered_parts = (
                urlsplit(discovered_url)
                if isinstance(discovered_url, str)
                else None
            )
            raw_url_parts = urlsplit(raw_url) if isinstance(raw_url, str) else None
        except ValueError:
            diagnostic["exclusion_reason"] = "Candidate URL is malformed."
            diagnostics.append(diagnostic)
            continue
        absolute_discovered_reference = bool(
            discovered_parts and discovered_parts.scheme and discovered_parts.netloc
        )
        absolute_raw_reference = bool(
            raw_url_parts and raw_url_parts.scheme and raw_url_parts.netloc
        )
        raw_url_origin = None
        if absolute_raw_reference:
            try:
                raw_url_origin = _normalized_scope_origin(
                    urlunsplit(
                        (
                            raw_url_parts.scheme,
                            raw_url_parts.netloc,
                            "",
                            "",
                            "",
                        )
                    )
                )
            except (ValueError, HTTPException):
                diagnostic["exclusion_reason"] = "Candidate URL is malformed."
                diagnostics.append(diagnostic)
                continue
        absolute_reference = absolute_discovered_reference or bool(
            absolute_raw_reference
            and (
                not item.get("relative_to_frontend")
                or raw_url_origin != frontend_origin
            )
        )
        relative_path = not absolute_reference and bool(
            item.get("relative_to_frontend")
            or isinstance(discovered_url, str) and discovered_url.startswith("/")
            or isinstance(raw_url, str)
            and raw_url.startswith("/")
            and not raw_url.startswith("//")
        )
        candidate_origin = None
        if isinstance(candidate_url, str) and (
            base_constant or root_origin or not relative_path or has_resolved_origin
        ):
            try:
                parsed_url = urlsplit(candidate_url)
                if (
                    parsed_url.scheme
                    and parsed_url.netloc
                    and (
                        not relative_path
                        or has_resolved_origin
                    )
                ):
                    origin = _normalized_scope_origin(
                        urlunsplit((parsed_url.scheme, parsed_url.netloc, "", "", ""))
                    )
                    diagnostic["resolved_origin"] = origin
                    diagnostic["scope_authorized"] = origin in allowed
                    if origin in allowed:
                        candidate_origin = origin
                        if base_constant or root_origin and origin != frontend_origin:
                            base_urls_by_origin.setdefault(origin, set()).add(
                                f"{origin}/"
                            )
            except (ValueError, HTTPException):
                diagnostic["exclusion_reason"] = "Candidate URL is malformed."
                diagnostics.append(diagnostic)
                continue
        frontend_only_resolution = bool(
            relative_path
            and candidate_origin == frontend_origin
            and item.get("resolution_rule") == "urljoin"
            and not item.get("verification_url")
        )
        if relative_path and (
            not has_resolved_origin or frontend_only_resolution
        ):
            relative_paths.append(            (path, diagnostic, item, discovered_url or path))
            diagnostics.append(diagnostic)
            continue
        if candidate_origin not in allowed:
            diagnostic["exclusion_reason"] = (
                "Resolved origin is missing or outside the authorized scan scope."
            )
            diagnostics.append(diagnostic)
            continue
        diagnostic["resolved_url"] = f"{candidate_origin}{path}"
        diagnostic["seed_eligible"] = True
        paths_by_origin.setdefault(candidate_origin, []).append(path)
        diagnostics.append(diagnostic)

    if relative_paths:
        if base_urls_by_origin:
            relative_targets = set(base_urls_by_origin)
        elif configured_gateway in allowed:
            relative_targets = {configured_gateway}
        elif trusted_local_origins:
            relative_targets = set(trusted_local_origins)
        else:
            relative_targets = {frontend_origin}
        authorized_relative_targets = relative_targets & allowed
        for path, diagnostic, item, observed_reference in relative_paths:
            if not authorized_relative_targets:
                diagnostic["exclusion_reason"] = (
                    "No candidate origin for this relative path is authorized."
                )
                continue
            for origin in authorized_relative_targets:
                bases = base_urls_by_origin.get(origin) or {f"{origin}/"}
                resolved_routes = set()
                for base_url in bases:
                    resolved = urljoin(base_url, observed_reference)
                    resolved_parts = urlsplit(resolved)
                    resolved_origin = _normalized_scope_origin(
                        urlunsplit(
                            (
                                resolved_parts.scheme,
                                resolved_parts.netloc,
                                "",
                                "",
                                "",
                            )
                        )
                    )
                    if resolved_origin == origin:
                        route = _static_route_path(resolved_parts.path)
                        if route:
                            resolved_routes.add(route)
                if not resolved_routes:
                    diagnostic["exclusion_reason"] = (
                        "Relative path could not be safely resolved against an authorized API base."
                    )
                    continue
                diagnostic["resolved_origin"] = origin
                diagnostic["scope_authorized"] = True
                diagnostic["seed_eligible"] = True
                diagnostic["resolved_url"] = f"{origin}{sorted(resolved_routes)[0]}"
                item["resolved_url"] = diagnostic["resolved_url"]
                item["resolved_origin"] = origin
                item["resolution_status"] = "resolved"
                item["resolution_rule"] = (
                    "explicit_api_base"
                    if origin in base_urls_by_origin
                    else "trusted_local_lab_profile"
                    if origin in trusted_local_origins
                    else "authorized_origin"
                )
                paths_by_origin.setdefault(origin, []).extend(
                    sorted(resolved_routes)
                )

    batches = []
    for origin in authorized_origins:
        paths = list(dict.fromkeys(paths_by_origin.get(origin, [])))
        if paths:
            batches.append((origin, paths))
    for diagnostic in diagnostics:
        if diagnostic["seed_eligible"]:
            continue
        if diagnostic["exclusion_reason"] is None:
            diagnostic["exclusion_reason"] = (
                "Candidate was not assigned to an authorized seed target."
            )
    for diagnostic in diagnostics:
        evidence_json = json.dumps(diagnostic, ensure_ascii=True, sort_keys=True)
        logger.info("Seed candidate evaluated | candidate=%s", evidence_json)
    file_result["seed_candidate_diagnostics"] = diagnostics
    return batches


def _authorized_discovered_origins(file_result, authorized_origins):
    allowed = set(authorized_origins)
    origins = set()
    records = file_result.get("results", []) if isinstance(file_result, dict) else []
    for record in records:
        if not isinstance(record, dict):
            continue
        candidate = (
            record.get("resolved_url")
            or record.get("verification_url")
            or record.get("url")
        )
        if not isinstance(candidate, str):
            continue
        try:
            parts = urlsplit(candidate)
            if not parts.scheme or not parts.netloc:
                continue
            origin = _normalized_scope_origin(
                urlunsplit((parts.scheme, parts.netloc, "", "", ""))
            )
        except (ValueError, HTTPException):
            continue
        if origin in allowed and (
            record.get("is_api_endpoint") is True
            or _javascript_root_origin(record)
            or _javascript_api_base(record)
        ):
            origins.add(origin)
    return origins


def _merge_file_discovery_results(destination, incoming):
    if not isinstance(incoming, dict):
        return
    existing_records = destination.setdefault("results", [])
    identities = {
        (
            item.get("method"),
            item.get("discovered_url") or item.get("discovered_path") or item.get("url"),
            item.get("template"),
        )
        for item in existing_records
        if isinstance(item, dict)
    }
    for item in incoming.get("results", []):
        if not isinstance(item, dict):
            continue
        identity = (
            item.get("method"),
            item.get("discovered_url") or item.get("discovered_path") or item.get("url"),
            item.get("template"),
        )
        if identity in identities:
            continue
        identities.add(identity)
        existing_records.append(item)
    destination.setdefault("page_sources", []).extend(
        page
        for page in incoming.get("page_sources", [])
        if page not in destination.get("page_sources", [])
    )
    destination.setdefault("scripts", []).extend(
        script
        for script in incoming.get("scripts", [])
        if script not in destination.get("scripts", [])
    )


def _deduplicate_seed_results(results, origin):
    unique = []
    seen = set()
    for item in results if isinstance(results, list) else []:
        if not isinstance(item, dict):
            continue
        method = str(item.get("method") or "GET").upper()
        path = _route_path(item.get("path") or item.get("target"), origin)
        if not path:
            continue
        identity = (origin, path, method)
        if identity in seen:
            continue
        seen.add(identity)
        record = dict(item)
        record["method"] = method
        record["path"] = path
        record["resolved_url"] = f"{origin}{path}"
        unique.append(record)
    return unique


def _api_candidate_security_target(
    primary_target,
    gateway_target,
    authorized_origins,
    discovery_results,
):
    if not gateway_target:
        return primary_target
    try:
        expected = _normalized_scope_origin(gateway_target)
    except (ValueError, HTTPException):
        return primary_target
    if expected not in set(authorized_origins):
        return primary_target
    for record in discovery_results:
        if not isinstance(record, dict):
            continue
        if str(record.get("method") or "").upper() != "GET":
            continue
        candidate = (
            record.get("resolved_url")
            or record.get("verification_url")
            or record.get("url")
        )
        if not isinstance(candidate, str):
            continue
        try:
            parts = urlsplit(candidate)
            if not parts.scheme or not parts.netloc:
                continue
            origin = _normalized_scope_origin(
                urlunsplit((parts.scheme, parts.netloc, "", "", ""))
            )
            path = _static_route_path(parts.path or "/")
        except (ValueError, HTTPException):
            continue
        if (
            origin == expected
            and origin in set(authorized_origins)
            and path
            and path != "/"
            and (
                record.get("is_api_endpoint") is True
                or re.match(r"^/api(?:/|$)", path, re.IGNORECASE)
            )
        ):
            return gateway_target
    return primary_target


def _jwt_inventory_candidates(
    discovery_inventory,
    security_target,
    authorized_origins,
    endpoint_allowlist=(),
):
    candidates = []
    exclusions = []
    target_origin = _normalized_scope_origin(security_target)
    authorized = set(authorized_origins)
    allowlisted = set(endpoint_allowlist)
    seen = set()

    for record in discovery_inventory:
        if not isinstance(record, dict):
            continue
        original_url = record.get("original_url") or record.get("url")
        candidate_url = (
            record.get("resolved_url")
            or record.get("verification_url")
            or record.get("url")
        )
        method_value = record.get("method")
        method = str(method_value).strip().upper() if method_value else ""
        reason = None
        if record.get("template") or record.get("is_template"):
            reason = "Unresolved dynamic template cannot be sent as a literal request."
        elif method not in {"GET"}:
            reason = (
                f"Unsupported or unknown discovery method {method or 'UNKNOWN'}; "
                "JWT probes currently support GET only."
            )
        elif not isinstance(candidate_url, str) or not candidate_url:
            reason = "No resolved endpoint URL is available."
        elif (
            record.get("resolution_status") == "unresolved"
            or isinstance(original_url, str)
            and original_url.startswith("/")
            and not record.get("resolved_url")
            and not record.get("verification_url")
        ):
            reason = "Relative discovery has no resolved in-scope origin."

        parsed = None
        if reason is None:
            try:
                parsed = urlsplit(candidate_url)
                if (
                    parsed.scheme not in {"http", "https"}
                    or not parsed.netloc
                    or parsed.username
                    or parsed.password
                    or parsed.query
                    or parsed.fragment
                ):
                    reason = "Resolved endpoint URL is malformed or contains query data."
                else:
                    origin = _normalized_scope_origin(
                        urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
                    )
                    if origin not in authorized:
                        reason = "Resolved endpoint origin is outside the authorized scan scope."
                    elif origin != target_origin:
                        reason = (
                            "Resolved endpoint is authorized but is not on the selected "
                            "JWT testing origin."
                        )
            except (ValueError, HTTPException):
                reason = "Resolved endpoint URL is malformed or outside supported scope."

        path = _static_route_path(parsed.path or "/") if parsed else None
        is_allowlisted = (method, path) in allowlisted
        if reason is None and (not path or path == "/"):
            reason = "Origin root is not an API route."
        if reason is None and (
            "${" in path
            or re.search(r"\{[^/}]+\}|(?<![\w]):[A-Za-z_$][\w$]*(?=/|$)", path)
        ):
            reason = "Unresolved dynamic template cannot be sent as a literal request."
        if reason is None and not (
            record.get("is_api_endpoint") is True
            or re.match(r"^/api(?:/|$)", path, re.IGNORECASE)
        ):
            reason = "Discovery record is not classified as an API route."
        status_code = _endpoint_status(record)
        if reason is None and status_code == 405:
            reason = (
                "Discovery returned HTTP 405 for the observed method; no alternate "
                "method is inferred."
            )
        if reason is None and status_code == 404:
            reason = "Discovery returned HTTP 404 for this route."
        content_type = record.get("content_type")
        if reason is None and isinstance(content_type, str) and (
            content_type.split(";", 1)[0].strip().lower() == "text/html"
        ):
            reason = (
                "Discovery returned HTML rather than an API response; SPA fallback "
                "content is not a JWT endpoint candidate."
            )
        if (
            reason is None
            and not is_allowlisted
            and record.get("verification_status") != "verified"
        ):
            if status_code not in {401, 403} and not (
                isinstance(status_code, int) and 200 <= status_code < 300
            ):
                reason = (
                    "No endpoint response evidence establishes a safe JWT candidate; "
                    "transport or policy blocks remain inconclusive."
                )

        if reason:
            exclusions.append(
                {
                    "method": method or "UNKNOWN",
                    "url": _safe_inventory_url(candidate_url),
                    "reason": reason,
                }
            )
            continue

        identity = (origin, path, method)
        if identity in seen:
            exclusions.append(
                {
                    "method": method,
                    "url": _safe_inventory_url(candidate_url),
                    "reason": "Duplicate resolved URL and method.",
                }
            )
            continue
        seen.add(identity)
        candidates.append(
            {
                **record,
                "method": method,
                "path": path,
                "resolved_url": candidate_url,
                "discovery_source": "discovery",
                "discovered": True,
                "discovery_sources": [
                    source
                    for source in (
                        record.get("sources")
                        if isinstance(record.get("sources"), list)
                        else []
                    )
                    if source
                    in {"javascript", "html", "kiterunner", "kiterunner_seeded"}
                ],
                "discovery_evidence": (
                    list(record["evidence"])
                    if isinstance(record.get("evidence"), list)
                    else []
                ),
                "responses": (
                    [{"sc": status_code}]
                    if isinstance(status_code, int)
                    else record.get("responses", [])
                ),
            }
        )
    return candidates, exclusions


def _jwt_discovery_inventory(discovery_inventory, security_target, authorized_origins):
    records = []
    authorized = set(authorized_origins)
    target_origin = _normalized_scope_origin(security_target)
    for record in discovery_inventory:
        if not isinstance(record, dict):
            continue
        method = str(record.get("method") or "").strip().upper()
        candidate_url = (
            record.get("resolved_url")
            or record.get("verification_url")
            or record.get("url")
        )
        if (
            not method
            or not re.fullmatch(r"[A-Z]+", method)
            or record.get("template")
            or record.get("is_template")
            or not isinstance(candidate_url, str)
        ):
            continue
        try:
            parsed = urlsplit(candidate_url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                continue
            origin = _normalized_scope_origin(
                urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
            )
        except (ValueError, HTTPException):
            continue
        path = _static_route_path(parsed.path or "/")
        if (
            origin not in authorized
            or origin != target_origin
            or not path
            or path == "/"
            or not (
                record.get("is_api_endpoint") is True
                or re.match(r"^/api(?:/|$)", path, re.IGNORECASE)
            )
        ):
            continue
        records.append(
            {
                **record,
                "method": method,
                "path": path,
                "responses": (
                    [{"sc": record["status_code"]}]
                    if isinstance(record.get("status_code"), int)
                    else record.get("responses", [])
                ),
            }
        )
    return records


def _endpoint_status(endpoint):
    responses = endpoint.get("responses")
    for response in responses if isinstance(responses, list) else []:
        if isinstance(response, dict):
            status = response.get("sc") or response.get("status_code") or response.get("status")
            try:
                if status is not None:
                    return int(status)
            except (TypeError, ValueError):
                pass
    for field in ("status_code", "status"):
        try:
            if endpoint.get(field) is not None:
                return int(endpoint[field])
        except (TypeError, ValueError):
            pass
    return None


def _endpoint_content_type(endpoint):
    for candidate in (
        endpoint.get("content_type"),
        endpoint.get("content-type"),
        endpoint.get("headers", {}).get("content-type")
        if isinstance(endpoint.get("headers"), dict)
        else None,
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.split(";", 1)[0].strip().lower()
    responses = endpoint.get("responses")
    for response in responses if isinstance(responses, list) else []:
        if not isinstance(response, dict):
            continue
        candidate = response.get("content_type") or response.get("content-type")
        headers = response.get("headers")
        if not candidate and isinstance(headers, dict):
            candidate = headers.get("content-type") or headers.get("Content-Type")
        if isinstance(candidate, str) and candidate.strip():
            return candidate.split(";", 1)[0].strip().lower()
    return None


def _discovery_observation(endpoint, source, url, method):
    status = _endpoint_status(endpoint)
    content_type = _endpoint_content_type(endpoint)
    allow = _endpoint_allow_methods(endpoint)
    return {
        "source": source,
        "method": method,
        "url": _safe_inventory_url(url),
        "status_code": status,
        "content_type": content_type,
        "verification_status": endpoint.get("verification_status"),
        "allow": allow if status == 405 else None,
    }


def _normalize_discovery_results(records):
    records_by_route = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        route_url = record.get("resolved_url") or record.get("verification_url") or record.get("url")
        try:
            parsed = urlsplit(route_url or "")
            route_identity = (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/") or "/",
            )
        except ValueError:
            continue
        records_by_route.setdefault(route_identity, []).append(record)

    for record in records:
        if not isinstance(record, dict):
            continue
        status = _endpoint_status(record)
        content_type = _endpoint_content_type(record)
        current_state = record.get("verification_status")
        if status in {401, 403}:
            record["verification_status"] = "blocked"
        elif status == 405:
            record["verification_status"] = "inconclusive"
        elif status == 404 or current_state == "not_found":
            html_fallback = (
                current_state == "not_found"
                and status is not None
                and 200 <= status < 300
                and content_type in {"text/html", "application/xhtml+xml"}
            )
            if html_fallback:
                record["verification_status"] = "not_found"
                record["verification_reason"] = (
                    "Response fingerprint matched the frontend HTML fallback."
                )
                continue

            sources = record.get("sources")
            evidence = record.get("evidence")
            direct_route_evidence = (
                isinstance(sources, list)
                and bool({"javascript", "html"} & set(sources))
                and isinstance(evidence, list)
                and bool(evidence)
            )
            route_url = (
                record.get("resolved_url")
                or record.get("verification_url")
                or record.get("url")
            )
            try:
                parsed = urlsplit(route_url or "")
                route_identity = (
                    parsed.scheme.lower(),
                    parsed.netloc.lower(),
                    parsed.path.rstrip("/") or "/",
                )
                related_endpoint_evidence = any(
                    other is not record
                    and _endpoint_status(other) in {200, 201, 202, 204, 401, 403, 405}
                    for other in records_by_route.get(route_identity, [])
                )
            except ValueError:
                related_endpoint_evidence = False
            if direct_route_evidence or related_endpoint_evidence:
                record["verification_status"] = "inconclusive"
                record["verification_reason"] = (
                    "HTTP 404 conflicts with independent route evidence; review is required."
                )
            else:
                record["verification_status"] = "not_found"
                record["verification_reason"] = "Discovery returned HTTP 404."
        elif status is not None and current_state not in {
            "verified",
            "blocked",
            "inconclusive",
            "not_found",
        }:
            record["verification_status"] = "discovered"
    return records


def _discovery_category(record):
    verification = record.get("verification_status")
    status = _endpoint_status(record)
    if verification == "not_found":
        return "not_found"
    if verification == "blocked":
        return "blocked"
    if verification == "inconclusive":
        return "inconclusive"
    if status == 404:
        return "not_found"
    if status in {401, 403}:
        return "blocked"
    if status == 405 or record.get("resolution_status") == "unresolved":
        return "inconclusive"
    return "actionable"


def _endpoint_allow_methods(endpoint):
    if not isinstance(endpoint, dict):
        return None
    response_records = endpoint.get("responses")
    response_records = response_records if isinstance(response_records, list) else []
    sources = [endpoint, *[item for item in response_records if isinstance(item, dict)]]
    for source in sources:
        headers = source.get("headers") or source.get("response_headers")
        value = (
            source.get("allow")
            or source.get("allow_header")
            or (
                headers.get("allow") or headers.get("Allow")
                if isinstance(headers, dict)
                else None
            )
        )
        if isinstance(value, str) and value.strip():
            methods = [
                method.strip().upper()
                for method in value.split(",")
                if re.fullmatch(r"\s*[A-Za-z]+\s*", method)
            ]
            if methods:
                return ", ".join(dict.fromkeys(methods))
    return None


def _has_usable_kiterunner_evidence(endpoint):
    content_type = _endpoint_content_type(endpoint)
    if not content_type or "html" in content_type:
        return False
    return content_type in {
        "application/json",
        "application/problem+json",
        "application/xml",
        "text/xml",
        "application/protobuf",
        "application/octet-stream",
    } or content_type.endswith("+json") or content_type.endswith("+xml")


def _verification_state(status):
    if status in {401, 403}:
        return "blocked"
    if status == 404:
        return "not_found"
    return "discovered" if status is None else "inconclusive"


def _route_path(value, origin):
    if not isinstance(value, str) or not value.strip():
        return None
    parsed = urlsplit(value.strip())
    if parsed.scheme or parsed.netloc:
        if parsed.query or parsed.fragment:
            return None
        value_origin = urlsplit(value)
        target_origin = urlsplit(origin)
        if (value_origin.scheme.lower(), value_origin.netloc.lower()) != (
            target_origin.scheme.lower(),
            target_origin.netloc.lower(),
        ):
            return None
        return parsed.path or "/"
    if parsed.query or parsed.fragment:
        return None
    return value.strip() if value.startswith("/") else f"/{value.strip()}"


def _correlate_discoveries(
    kiterunner_results,
    file_results,
    scan_origin,
    gateway_target,
    frontend_page_scanned=False,
    security_target=None,
):
    security_target = security_target or scan_origin
    unified = {}
    analyzed_endpoints = {}

    for endpoint in kiterunner_results:
        if not isinstance(endpoint, dict):
            continue
        raw_method = endpoint.get("method")
        method = str(raw_method).upper() if raw_method else None
        resolved_url = endpoint.get("resolved_url")
        result_origin = scan_origin
        if isinstance(resolved_url, str):
            try:
                resolved_parts = urlsplit(resolved_url)
                if resolved_parts.scheme and resolved_parts.netloc:
                    result_origin = urlunsplit(
                        (resolved_parts.scheme, resolved_parts.netloc, "", "", "")
                    )
            except ValueError:
                pass
        path = _route_path(endpoint.get("path") or endpoint.get("target"), result_origin)
        if not path:
            continue
        url = urlunsplit(
            (
                urlsplit(result_origin).scheme.lower(),
                urlsplit(result_origin).netloc.lower(),
                path,
                "",
                "",
            )
        )
        status = _endpoint_status(endpoint)
        source = (
            "kiterunner_seeded"
            if endpoint.get("discovery_phase") == "seeded"
            else "kiterunner"
        )
        record = unified.setdefault(
            (method, url),
            {
                "url": url,
                "method": method,
                "status_code": status,
                "content_type": None,
                "sources": [],
                "verification_status": _verification_state(status),
                "evidence": [],
            },
        )
        if source not in record["sources"]:
            record["sources"].append(source)
        if status is not None:
            record["status_code"] = status
            record["verification_status"] = _verification_state(status)
        allow_methods = _endpoint_allow_methods(endpoint)
        if status == 405 and allow_methods:
            record["allow"] = allow_methods
        record.setdefault("discovery_observations", []).append(
            _discovery_observation(endpoint, source, url, method)
        )
        endpoint_content_type = _endpoint_content_type(endpoint)
        if endpoint_content_type:
            record["content_type"] = endpoint_content_type

        if (
            (urlsplit(result_origin).scheme.lower(), urlsplit(result_origin).netloc.lower())
            == (
                urlsplit(security_target).scheme.lower(),
                urlsplit(security_target).netloc.lower(),
            )
        ):
            identity = (method, path)
            correlated = analyzed_endpoints.get(identity)
            if correlated is None:
                correlated = dict(endpoint)
                correlated.update(
                    {
                        "path": path,
                        "method": method,
                        "discovery_sources": [],
                        "verification_status": _verification_state(status),
                        "discovery_evidence": [],
                    }
                )
                analyzed_endpoints[identity] = correlated
            if source not in correlated["discovery_sources"]:
                correlated["discovery_sources"].append(source)
            if status is not None:
                correlated["verification_status"] = _verification_state(status)

    for file_result in file_results:
        if not isinstance(file_result, dict):
            continue
        raw_method = file_result.get("method")
        method = str(raw_method).upper() if isinstance(raw_method, str) and raw_method else None
        discovered_url = file_result.get("url")
        observed_url = discovered_url
        endpoint_url = discovered_url
        is_javascript = (
            isinstance(file_result.get("sources"), list)
            and "javascript" in file_result["sources"]
        )
        is_relative_discovery = bool(
            file_result.get("relative_to_frontend")
            or isinstance(observed_url, str)
            and observed_url.startswith("/")
            and not observed_url.startswith("//")
        )
        if (
            isinstance(endpoint_url, str)
            and endpoint_url.startswith("/")
            and not endpoint_url.startswith("//")
            and (
                is_javascript
                or isinstance(file_result.get("sources"), list)
                and "html" in file_result["sources"]
            )
        ):
            endpoint_url = f"{scan_origin.rstrip('/')}{endpoint_url}"
        if not isinstance(endpoint_url, str) or not endpoint_url:
            template = file_result.get("template")
            if template:
                identity = (method, f"template:{template}")
                record = unified.setdefault(
                    identity,
                    {
                        "url": None,
                        "template": template,
                        "method": method,
                        "status_code": None,
                        "content_type": None,
                        "sources": [],
                        "verification_status": "discovered",
                        "resolution_status": "unresolved",
                        "classification": file_result.get(
                            "classification", "api_endpoint"
                        ),
                        "is_api_endpoint": bool(file_result.get("is_api_endpoint")),
                        "evidence": [],
                    },
                )
                file_sources = file_result.get("sources")
                for source in file_sources if isinstance(file_sources, list) else []:
                    if source not in record["sources"]:
                        record["sources"].append(source)
                file_evidence = file_result.get("evidence")
                if isinstance(file_evidence, list):
                    record["evidence"].extend(file_evidence)
            continue
        try:
            parsed_url = urlsplit(endpoint_url)
        except ValueError:
            continue
        if not parsed_url.scheme or not parsed_url.netloc:
            continue
        discovered_url = urlunsplit(
            (
                parsed_url.scheme.lower(),
                parsed_url.netloc.lower(),
                parsed_url.path or "/",
                "",
                "",
            )
        )
        verification_url = file_result.get("verification_url")
        if not isinstance(verification_url, str) or not verification_url:
            verification_url = None
        resolved_url = file_result.get("resolved_url")
        if not isinstance(resolved_url, str) or not resolved_url:
            resolved_url = verification_url
        identity_url = (
            resolved_url
            if is_javascript and file_result.get("is_api_endpoint") and resolved_url
            else discovered_url
        )
        discovery_identity = (method, identity_url)
        resolution_status = file_result.get("resolution_status")
        if not resolution_status:
            resolution_status = (
                "unresolved"
                if is_javascript
                and file_result.get("is_api_endpoint")
                and is_relative_discovery
                and not resolved_url
                and not verification_url
                else "resolved"
            )
        record = unified.setdefault(
            discovery_identity,
            {
                "url": discovered_url,
                "original_url": (
                    observed_url
                    if isinstance(observed_url, str) and observed_url.startswith("/")
                    else discovered_url
                ),
                "method": method,
                "status_code": None,
                "content_type": None,
                "sources": [],
                "verification_status": file_result.get("verification_status", "discovered"),
                "resolution_status": resolution_status,
                "resolved_url": resolved_url,
                "classification": file_result.get("classification"),
                "evidence": [],
                "request_body_fields": [],
                "request_content_type": None,
                "request_content_type_evidence": None,
            },
        )
        if discovered_url != record.get("url"):
            record.setdefault("discovered_urls", [])
            if discovered_url not in record["discovered_urls"]:
                record["discovered_urls"].append(discovered_url)
        if is_javascript and is_relative_discovery:
            record["original_url"] = (
                observed_url
                if isinstance(observed_url, str) and observed_url.startswith("/")
                else discovered_url
            )
        else:
            record.setdefault("original_url", discovered_url)
        discovered_path = file_result.get("discovered_url") or file_result.get(
            "discovered_path"
        )
        if not discovered_path and isinstance(observed_url, str) and observed_url.startswith("/"):
            discovered_path = observed_url
        if discovered_path:
            record.setdefault("discovered_path", discovered_path)
        if verification_url:
            record["verification_url"] = verification_url
            record["resolution_status"] = file_result.get(
                "resolution_status", "resolved"
            )
        if resolved_url:
            record["resolved_url"] = resolved_url
        if file_result.get("classification") and not record.get("classification"):
            record["classification"] = file_result["classification"]
        if "is_api_endpoint" in file_result:
            record["is_api_endpoint"] = file_result["is_api_endpoint"]
        for source in file_result.get("sources", []):
            if source not in record["sources"]:
                record["sources"].append(source)
        if verification_url and "gateway_verification" not in record["sources"]:
            record["sources"].append("gateway_verification")
        if file_result.get("status_code") is not None:
            record["status_code"] = file_result["status_code"]
        if file_result.get("content_type") is not None:
            record["content_type"] = file_result["content_type"]
        if isinstance(file_result.get("request_body_fields"), list):
            record["request_body_fields"] = file_result["request_body_fields"]
        if file_result.get("request_content_type"):
            record["request_content_type"] = file_result["request_content_type"]
            record["request_content_type_evidence"] = file_result.get(
                "request_content_type_evidence"
            )
        allow_methods = _endpoint_allow_methods(file_result)
        if file_result.get("status_code") == 405 and allow_methods:
            record["allow"] = allow_methods
        if file_result.get("verification_status") in {
            "verified",
            "blocked",
            "not_found",
            "inconclusive",
        }:
            record["verification_status"] = file_result["verification_status"]
        record["evidence"].extend(file_result.get("evidence", []))
        record.setdefault("discovery_observations", []).append(
            _discovery_observation(
                file_result,
                ",".join(
                    source
                    for source in file_result.get("sources", [])
                    if isinstance(source, str)
                )
                or "file_discovery",
                resolved_url or verification_url or discovered_url,
                method,
            )
        )

        if not is_javascript or not file_result.get("is_api_endpoint"):
            continue
        if file_result.get("verification_status") != "verified":
            continue
        security_url = verification_url or discovered_url
        try:
            security_parts = urlsplit(security_url)
        except ValueError:
            continue
        allowed_security_origins = {
            (
                urlsplit(scan_origin).scheme.lower(),
                urlsplit(scan_origin).netloc.lower(),
            )
        }
        if gateway_target:
            allowed_security_origins.add(
                (
                    urlsplit(gateway_target).scheme.lower(),
                    urlsplit(gateway_target).netloc.lower(),
                )
            )
        if (
            security_parts.scheme.lower(),
            security_parts.netloc.lower(),
        ) not in allowed_security_origins:
            continue
        if (security_parts.scheme.lower(), security_parts.netloc.lower()) != (
            urlsplit(security_target).scheme.lower(),
            urlsplit(security_target).netloc.lower(),
        ):
            continue
        if file_result.get("relative_to_frontend") and not verification_url:
            continue
        path = security_parts.path or "/"
        if not path:
            continue
        identity = (method, path)
        existing = analyzed_endpoints.get(identity)
        if existing:
            if "javascript" not in existing["discovery_sources"]:
                existing["discovery_sources"].append("javascript")
            existing["discovery_evidence"].extend(file_result.get("evidence", []))
            if file_result.get("verification_status") == "verified":
                existing["verification_status"] = "verified"
            if file_result.get("status_code") is not None:
                existing["responses"] = [
                    {"sc": file_result["status_code"]}
                ]
        else:
            analyzed_endpoints[identity] = {
                "method": method,
                "path": path,
                "responses": (
                    [{"sc": file_result["status_code"]}]
                    if file_result.get("status_code") is not None
                    else []
                ),
                "discovery_sources": ["javascript"],
                "verification_status": file_result.get(
                    "verification_status", "discovered"
                ),
                "discovery_evidence": file_result.get("evidence", []),
            }

    return (
        _normalize_discovery_results(list(unified.values())),
        list(analyzed_endpoints.values()),
    )


def _set_security_dispositions(discovery_results, endpoint_assessments, target, fallback_reason):
    assessments_by_identity = {
        (item.get("method"), item.get("path")): item
        for item in endpoint_assessments
    }
    target_parts = urlsplit(target)
    target_origin = (target_parts.scheme.lower(), target_parts.netloc.lower())
    for item in discovery_results:
        if not item.get("url"):
            item["security_status"] = "skipped"
            item["security_reason"] = (
                "Dynamic template has no concrete URL to send to security testing."
            )
            continue
        security_url = (
            item.get("resolved_url")
            or item.get("verification_url")
            or item.get("url")
        )
        try:
            item_url = urlsplit(security_url) if security_url else None
        except ValueError:
            item_url = None
        same_security_origin = bool(
            item_url
            and (item_url.scheme.lower(), item_url.netloc.lower()) == target_origin
        )
        assessment = (
            assessments_by_identity.get(
                (item.get("method"), item_url.path or "/")
            )
            if same_security_origin and item_url
            else None
        )
        if assessment and assessment.get("actually_tested"):
            item["security_status"] = "tested"
            item["security_reason"] = None
        else:
            item["security_status"] = "skipped"
            item["security_reason"] = (
                assessment.get("reason")
                if assessment
                else fallback_reason
            )


async def _run_scan_pipeline(
    target,
    num,
    auto_jwt_local_lab,
    progress_callback=None,
    scope_origins=None,
):
    normalized_target = validate_target(target)
    stages = {}

    async def emit(stage, status=None, detail=None):
        if isinstance(stage, dict):
            event = stage
            stage = event["stage"]
        else:
            event = {"stage": stage, "status": status, "detail": detail}
        stages[stage] = event
        if progress_callback:
            await progress_callback(event)

    gateway_target = None
    gateway_config_error = None
    try:
        gateway_target = _configured_gateway_target()
    except HTTPException as exc:
        gateway_config_error = str(exc.detail)
        logger.warning(
            "Ignoring invalid legacy Gateway configuration | reason=%s",
            gateway_config_error,
        )

    legacy_gateway_target = gateway_target
    authorized_origins = _authorized_scan_scope(
        normalized_target, scope_origins, legacy_gateway_target
    )
    if gateway_target is None:
        frontend_origin = _normalized_scope_origin(normalized_target)
        additional_origins = [
            origin for origin in authorized_origins if origin != frontend_origin
        ]
        gateway_target = next(
            (
                origin
                for origin in additional_origins
                if (urlsplit(origin).hostname or "").lower()
                in {"localhost", "127.0.0.1", "::1"}
                and urlsplit(origin).port == 8085
            ),
            additional_origins[0] if additional_origins else None,
        )
    file_gateway_target = None
    if gateway_target:
        try:
            file_gateway_target = normalize_origin(gateway_target).rstrip("/")
        except ValueError:
            logger.info(
                "File Discovery endpoint verification is unsupported for scoped origin %s",
                gateway_target,
            )
    discovery_target = normalized_target
    limits = DISCOVERY_LIMITS
    logger.info(
        "Scan started | target=%s | dictionary_size=%d | authorized_scope=%s",
        normalized_target,
        num,
        authorized_origins,
    )
    await emit(
        {
            "stage": "Authorized Scope",
            "status": "completed",
            "detail": ", ".join(authorized_origins),
            "origins": authorized_origins,
        }
    )

    await emit("API Discovery", "running")
    kiterunner_results = []
    kiterunner_error = None
    try:
        kiterunner_results = await asyncio.to_thread(
            Discovery().discover, discovery_target, num
        )
        await emit(
            "API Discovery",
            "completed",
            f"Kiterunner discovered {len(kiterunner_results)} endpoint(s).",
        )
    except (ValueError, FileNotFoundError, RuntimeError, TimeoutError) as exc:
        kiterunner_error = str(exc)
        logger.warning("API Discovery failed | error=%s", type(exc).__name__)
        await emit("API Discovery", "error", kiterunner_error)
    except Exception as exc:
        kiterunner_error = f"Kiterunner failed with {type(exc).__name__}."
        logger.exception("API Discovery failed | error=%s", type(exc).__name__)
        await emit("API Discovery", "error", kiterunner_error)
    for endpoint in kiterunner_results:
        if not isinstance(endpoint, dict) or endpoint.get("resolved_url"):
            continue
        path = _route_path(endpoint.get("path") or endpoint.get("target"), normalized_target)
        if path:
            endpoint["resolved_url"] = f"{normalized_target.rstrip('/')}{path}"

    await emit("File Discovery", "running")
    file_result = {"results": [], "summary": {}}
    file_error = None
    try:
        file_result = await FileDiscovery().scan(
            normalized_target,
            verify_endpoints=bool(file_gateway_target),
            gateway_target=file_gateway_target,
            progress_callback=emit,
        )
        request_count = file_result.get("summary", {}).get("requests_made", 0)
        failed_count = file_result.get("summary", {}).get("requests_failed", 0)
        if request_count and failed_count >= request_count:
            file_error = "All File Discovery requests failed."
            await emit("File Discovery", "error", file_error)
        else:
            file_error = None
    except (ValueError, httpx.HTTPError, TimeoutError, RuntimeError) as exc:
        file_error = str(exc)
        logger.warning("File Discovery failed | error=%s", type(exc).__name__)
        await emit("File Discovery", "error", file_error)
        if "JavaScript Analysis" not in stages:
            await emit(
                "JavaScript Analysis",
                "skipped",
                "File Discovery could not retrieve an in-scope HTML document.",
            )
    except Exception as exc:
        file_error = f"File Discovery failed with {type(exc).__name__}."
        logger.exception("File Discovery failed | error=%s", type(exc).__name__)
        await emit("File Discovery", "error", file_error)
        if "JavaScript Analysis" not in stages:
            await emit(
                "JavaScript Analysis",
                "skipped",
                "File Discovery could not retrieve an in-scope HTML document.",
            )

    limits = DISCOVERY_LIMITS
    origin_discovery_rounds = []
    visited_discovery_origins = {_normalized_scope_origin(discovery_target)}
    pending_origins = sorted(
        _authorized_discovered_origins(file_result, authorized_origins)
        - visited_discovery_origins
    )
    while pending_origins:
        origin = pending_origins.pop(0)
        if origin in visited_discovery_origins:
            continue
        if len(visited_discovery_origins) >= limits.max_origins:
            await emit(
                {
                    "stage": "API Origin Discovery",
                    "status": "skipped",
                    "detail": (
                        f"Origin {origin} was not scanned because the configured "
                        f"maximum of {limits.max_origins} unique origins was reached."
                    ),
                    "target": origin,
                    "stop_reason": "target_limit",
                }
            )
            continue
        visited_discovery_origins.add(origin)
        round_number = len(origin_discovery_rounds) + 1
        stage_name = f"API Origin Discovery Round {round_number}"
        await emit(stage_name, "running", f"Scanning authorized origin {origin}.")
        origin_results = []
        try:
            origin_outcome = await asyncio.to_thread(
                Discovery().discover,
                origin,
                num,
                True,
                limits.command_timeout_seconds,
            )
            if isinstance(origin_outcome, dict):
                origin_results = origin_outcome.get("results", [])
                origin_target = origin_outcome.get("target", origin)
                origin_command = _safe_command_arguments(
                    origin_outcome.get("command", [])
                )
                origin_exit_code = origin_outcome.get("exit_code")
                origin_result_count = origin_outcome.get(
                    "result_count", len(origin_results)
                )
            else:
                origin_results = origin_outcome
                origin_target = origin
                origin_command = []
                origin_exit_code = None
                origin_result_count = len(origin_results)
            if not isinstance(origin_results, list):
                raise RuntimeError(
                    "Kiterunner returned an invalid API origin result payload."
                )
            origin_results = [
                dict(result) if isinstance(result, dict) else result
                for result in origin_results
            ]
            for result in origin_results:
                if not isinstance(result, dict) or result.get("resolved_url"):
                    continue
                result_path = _route_path(
                    result.get("path") or result.get("target"), origin
                )
                if result_path:
                    result["resolved_url"] = f"{origin}{result_path}"
            kiterunner_results.extend(origin_results)
            origin_record = {
                "round": round_number,
                "target": origin_target,
                "status": "completed",
                "command": origin_command,
                "exit_code": origin_exit_code,
                "result_count": origin_result_count,
                "timeout_seconds": limits.command_timeout_seconds,
            }
            origin_discovery_rounds.append(origin_record)
            await emit(
                {
                    "stage": stage_name,
                    "status": "completed",
                    "detail": (
                        f"Kiterunner scanned {origin_target}; "
                        f"{origin_result_count} parsed result(s), "
                        f"exit code {origin_exit_code if origin_exit_code is not None else 'not reported'}; "
                        f"command={origin_command!r}."
                    ),
                    **origin_record,
                }
            )
        except (ValueError, FileNotFoundError, RuntimeError, TimeoutError) as exc:
            failure = {
                "round": round_number,
                "target": origin,
                "status": "failed",
                "command": _command_from_error(exc),
                "exit_code": (
                    int(match.group(1))
                    if (match := re.search(r"\bexit_code=(\d+)", str(exc)))
                    else None
                ),
                "result_count": 0,
                "timeout_seconds": limits.command_timeout_seconds,
                "error": str(exc),
            }
            origin_discovery_rounds.append(failure)
            logger.warning(
                "Authorized API origin scan failed | target=%s | error=%s",
                origin,
                type(exc).__name__,
            )
            await emit(
                {
                    "stage": stage_name,
                    "status": "failed",
                    "detail": (
                        f"{exc}; command={failure['command']!r}; "
                        f"timeout={limits.command_timeout_seconds}s."
                    ),
                    **failure,
                }
            )
        has_html_discovery = any(
            isinstance(result, dict)
            and (urlsplit(result.get("path") or result.get("target") or "/").path in {"", "/"})
            and "html" in (_endpoint_content_type(result) or "")
            for result in origin_results
        )
        if (
            has_html_discovery
            and urlsplit(origin).hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            try:
                await emit(
                    {
                        "stage": f"File Analysis {origin}",
                        "status": "running",
                        "detail": "Analyzing in-scope HTML and JavaScript at the discovered origin.",
                    }
                )
                origin_files = await FileDiscovery().scan(
                    origin,
                    wordlist="",
                    analyze_javascript=True,
                    verify_endpoints=False,
                    progress_callback=emit,
                )
                _merge_file_discovery_results(file_result, origin_files)
                await emit(
                    {
                        "stage": f"File Analysis {origin}",
                        "status": "completed",
                        "detail": (
                            f"Added {len(origin_files.get('results', []))} file discovery "
                            "record(s) from the authorized origin."
                        ),
                    }
                )
            except (ValueError, httpx.HTTPError, TimeoutError, RuntimeError) as exc:
                logger.info(
                    "Authorized origin file analysis unavailable | target=%s | reason=%s",
                    origin,
                    type(exc).__name__,
                )
                await emit(
                    {
                        "stage": f"File Analysis {origin}",
                        "status": "skipped",
                        "detail": f"In-scope file analysis could not run: {type(exc).__name__}.",
                    }
                )
        newly_discovered = (
            _authorized_discovered_origins(file_result, authorized_origins)
            - visited_discovery_origins
            - set(pending_origins)
        )
        pending_origins.extend(sorted(newly_discovered))

    seeded_results = []
    seeded_error = None
    recursive_rounds = []
    seeded_outcome = None
    seed_batches = _recursive_seed_batches(
        file_result, normalized_target, authorized_origins
    )
    seed_diagnostics = file_result.get("seed_candidate_diagnostics", [])
    eligible_candidate_count = sum(
        1 for item in seed_diagnostics if item.get("seed_eligible")
    )
    excluded_candidate_count = len(seed_diagnostics) - eligible_candidate_count
    accepted_seed_details = [
        {
            "target_origin": item.get("resolved_origin"),
            "path": item.get("seed_path"),
            "observed_method": item.get("observed_method"),
            "runner_method": item.get("runner_method", "GET"),
            "source": item.get("source", []),
            "source_evidence": item.get("source_evidence", []),
        }
        for item in seed_diagnostics
        if item.get("seed_eligible")
    ]
    eligible_origins = list(dict.fromkeys(
        item.get("target_origin") for item in accepted_seed_details
    ))
    exclusion_detail = "; ".join(
        f"{item.get('original_path') or '(unknown path)'}: "
        f"{item.get('exclusion_reason')}"
        for item in seed_diagnostics
        if not item.get("seed_eligible") and item.get("exclusion_reason")
    )
    if len(exclusion_detail) > 1200:
        exclusion_detail = exclusion_detail[:1197] + "..."
    await emit(
        {
            "stage": "Seeded API Discovery Eligibility",
            "status": "completed",
            "detail": (
                f"Evaluated {len(seed_diagnostics)} JavaScript/HTML candidate(s): "
                f"{eligible_candidate_count} eligible, {excluded_candidate_count} excluded."
                + (
                    f" Accepted static seeds: {accepted_seed_details!r}; "
                    f"target origin(s): {eligible_origins!r}."
                    if accepted_seed_details
                    else ""
                )
                + (f" Exclusions: {exclusion_detail}" if exclusion_detail else "")
            ),
            "candidates": seed_diagnostics,
            "eligible_count": eligible_candidate_count,
            "excluded_count": excluded_candidate_count,
            "accepted_seeds": accepted_seed_details,
            "target_origins": eligible_origins,
        }
    )
    discovered_origins = set()
    for record in file_result.get("results", []):
        if not isinstance(record, dict):
            continue
        evidence = record.get("evidence")
        has_api_base_evidence = any(
            isinstance(entry, dict)
            and isinstance(entry.get("snippet"), str)
            and re.search(
                r"(?i)\b(?:api[_-]?(?:base|url)|base[_-]?url)\b",
                entry["snippet"],
            )
            for entry in (evidence if isinstance(evidence, list) else [])
        )
        if (
            record.get("is_api_endpoint") is not True
            and not has_api_base_evidence
            and not _javascript_root_origin(record)
        ):
            continue
        candidate_url = record.get("url")
        if record.get("resolved_url") or record.get("verification_url"):
            candidate_url = record.get("resolved_url") or record.get("verification_url")
        if not isinstance(candidate_url, str):
            continue
        try:
            parts = urlsplit(candidate_url)
            if parts.scheme and parts.netloc:
                candidate_origin = _normalized_scope_origin(
                    urlunsplit((parts.scheme, parts.netloc, "", "", ""))
                )
                discovered_origins.add(candidate_origin)
        except (ValueError, HTTPException):
            continue
    authorized_candidates = sorted(
        {origin for origin, _ in seed_batches}
        | (discovered_origins & set(authorized_origins))
    )
    out_of_scope_candidates = sorted(discovered_origins - set(authorized_origins))
    await emit(
        {
            "stage": "API Origin Candidates",
            "status": "completed",
            "detail": (
                f"Authorized candidates: {', '.join(authorized_candidates) or 'none'}. "
                f"Out-of-scope candidates ignored: "
                f"{', '.join(out_of_scope_candidates) or 'none'}."
            ),
            "authorized_candidates": authorized_candidates,
            "ignored_candidates": out_of_scope_candidates,
        }
    )
    if gateway_config_error:
        await emit(
            {
                "stage": "Legacy Gateway Configuration",
                "status": "warning",
                "detail": (
                    f"Ignored invalid MICROSCAN_GATEWAY_TARGET: {gateway_config_error} "
                    "The per-scan authorized scope remains in effect."
                ),
            }
        )
    queue = []
    remaining_initial_budget = limits.max_seeds_per_round * limits.max_rounds
    initial_seed_count = sum(len(paths) for _, paths in seed_batches)
    for origin, paths in seed_batches:
        if remaining_initial_budget <= 0:
            break
        eligible_paths = paths[:remaining_initial_budget]
        for start in range(0, len(eligible_paths), limits.max_seeds_per_round):
            queue.append(
                (
                    origin,
                    eligible_paths[
                        start : start + limits.max_seeds_per_round
                    ],
                    1,
                )
            )
        remaining_initial_budget -= len(eligible_paths)
    initial_budget_exceeded = initial_seed_count > (
        limits.max_seeds_per_round * limits.max_rounds
    )
    visited_seed_keys = {
        (origin, path, "GET")
        for origin, paths, _ in queue
        for path in paths
    }
    visited_origins = set(visited_discovery_origins)
    initial_discovery_keys = {
        (
            _normalized_scope_origin(
                urlunsplit(
                    (
                        resolved_parts.scheme,
                        resolved_parts.netloc,
                        "",
                        "",
                        "",
                    )
                )
                if isinstance(item.get("resolved_url"), str)
                and (resolved_parts := urlsplit(item["resolved_url"])).scheme
                and resolved_parts.netloc
                else discovery_target
            ),
            _route_path(
                item.get("path") or item.get("target"),
                item.get("resolved_url", discovery_target)
                if isinstance(item.get("resolved_url"), str)
                else discovery_target,
            ),
            str(item.get("method") or "GET").upper(),
        )
        for item in kiterunner_results
        if isinstance(item, dict)
    }
    known_result_keys = {key for key in initial_discovery_keys if key[1]}
    executed_seed_count = 0
    round_number = 0
    stop_reason = "request_budget" if initial_budget_exceeded else "queue_empty"

    if not queue:
        stop_reason = "no_eligible_seeds"
        exclusion_reasons = list(
            dict.fromkeys(
                item["exclusion_reason"]
                for item in seed_diagnostics
                if item.get("exclusion_reason")
            )
        )
        reason = (
            "No seeded Kiterunner command ran. Candidate exclusions: "
            + ("; ".join(exclusion_reasons) if exclusion_reasons else "no JavaScript/HTML API candidates were returned.")
        )
        await emit(
            {
                "stage": "Seeded API Discovery",
                "status": "skipped",
                "detail": reason,
                "target": None,
                "seed_count": 0,
                "result_count": 0,
                "exit_code": None,
                "candidate_diagnostics": seed_diagnostics,
            }
        )
    else:
        while queue:
            origin, paths, depth = queue.pop(0)
            if depth > limits.max_depth:
                stop_reason = "recursion_limit"
                continue
            if origin not in authorized_origins:
                continue
            if origin not in visited_origins and len(visited_origins) >= limits.max_origins:
                stop_reason = "target_limit"
                continue
            if origin not in visited_origins:
                visited_origins.add(origin)
            remaining_budget = (
                limits.max_seeds_per_round * limits.max_rounds
                - executed_seed_count
            )
            if remaining_budget <= 0:
                stop_reason = "request_budget"
                queue.insert(0, (origin, paths, depth))
                break
            if len(paths) > limits.max_seeds_per_round:
                queue[0:0] = [
                    (origin, paths[start : start + limits.max_seeds_per_round], depth)
                    for start in range(
                        limits.max_seeds_per_round,
                        min(len(paths), remaining_budget),
                        limits.max_seeds_per_round,
                    )
                ]
                paths = paths[: limits.max_seeds_per_round]
            paths = paths[: min(limits.max_seeds_per_round, remaining_budget)]
            executed_seed_count += len(paths)
            if round_number >= limits.max_rounds:
                stop_reason = "round_limit"
                queue.clear()
                break
            round_number += 1
            stage_name = (
                "Seeded API Discovery"
                if round_number == 1
                else f"Recursive Discovery Round {round_number}"
            )
            await emit(stage_name, "running")
            try:
                if limits.command_timeout_seconds == 45:
                    outcome = await asyncio.to_thread(
                        Discovery().discover_seeded,
                        origin,
                        paths,
                        min(max(int(num or 100), 1), 100),
                    )
                else:
                    outcome = await asyncio.to_thread(
                        Discovery().discover_seeded,
                        origin,
                        paths,
                        min(max(int(num or 100), 1), 100),
                        limits.command_timeout_seconds,
                    )
                if isinstance(outcome, dict):
                    round_results = outcome.get("results", [])
                    if not isinstance(round_results, list):
                        raise RuntimeError("Kiterunner returned an invalid seeded result payload.")
                    exit_code = outcome.get("exit_code")
                    result_count = outcome.get("result_count", len(round_results))
                    actual_seed_count = outcome.get("seed_count", len(paths))
                    execution_target = outcome.get("target", origin)
                    command = _safe_command_arguments(outcome.get("command", []))
                elif isinstance(outcome, list):
                    round_results = outcome
                    exit_code = None
                    result_count = len(round_results)
                    actual_seed_count = len(paths)
                    execution_target = origin
                    command = []
                else:
                    raise RuntimeError("Kiterunner returned an invalid seeded result payload.")

                new_results = []
                duplicate_count = 0
                for result in _deduplicate_seed_results(round_results, origin):
                    parsed_result = urlsplit(result["resolved_url"])
                    result_key = (origin, parsed_result.path or "/", result["method"])
                    if result_key in known_result_keys:
                        duplicate_count += 1
                    else:
                        known_result_keys.add(result_key)
                        new_results.append(result)
                seeded_results.extend(new_results)
                round_seed_details = [
                    {
                        "path": item.get("seed_path"),
                        "observed_method": item.get("observed_method"),
                        "runner_method": item.get("runner_method", "GET"),
                        "source": item.get("source", []),
                    }
                    for item in seed_diagnostics
                    if item.get("seed_eligible")
                    and item.get("resolved_origin") == origin
                    and item.get("seed_path") in paths
                ]
                round_record = {
                    "round": round_number,
                    "target": execution_target,
                    "seed_count": actual_seed_count,
                    "seeds": round_seed_details,
                    "status": "completed",
                    "exit_code": exit_code,
                    "result_count": result_count,
                    "new_results": len(new_results),
                    "duplicate_results": duplicate_count,
                    "queued_targets_remaining": len({item[0] for item in queue}),
                    "command": command,
                    "timeout_seconds": limits.command_timeout_seconds,
                }
                recursive_rounds.append(round_record)

                discovered_paths = []
                for item in new_results:
                    if item["method"] != "GET":
                        continue
                    if not _has_usable_kiterunner_evidence(item):
                        continue
                    path = _static_route_path(item["path"])
                    key = (origin, path, "GET") if path else None
                    if key and key not in visited_seed_keys:
                        visited_seed_keys.add(key)
                        discovered_paths.append(path)
                if discovered_paths:
                    if depth >= limits.max_depth:
                        stop_reason = "recursion_limit"
                    else:
                        queue.append((origin, discovered_paths, depth + 1))
                round_record["queued_targets_remaining"] = len(
                    {item[0] for item in queue}
                )
                stage_detail = (
                    f"Round {round_number}: Kiterunner executed against {execution_target}; "
                    f"{actual_seed_count} seed(s), exit code "
                    f"{exit_code if exit_code is not None else 'not reported'}, "
                    f"{result_count} parsed result(s), {len(new_results)} new and "
                    f"{duplicate_count} duplicate result(s); command={command!r}; "
                    f"seeds={round_seed_details!r}; "
                    f"timeout={limits.command_timeout_seconds}s; "
                    f"{round_record['queued_targets_remaining']} target(s) queued."
                )
                await emit({
                    "stage": stage_name,
                    "status": "completed",
                    "detail": stage_detail,
                    **round_record,
                })
                seeded_outcome = {
                    "target": execution_target,
                    "seed_count": actual_seed_count,
                    "exit_code": exit_code,
                    "result_count": result_count,
                }
            except (ValueError, FileNotFoundError, RuntimeError, TimeoutError) as exc:
                seeded_error = str(exc)
                exit_match = re.search(r"\bexit_code=(\d+)", seeded_error)
                failed_exit_code = int(exit_match.group(1)) if exit_match else None
                failed_command = _command_from_error(seeded_error)
                round_record = {
                    "round": round_number,
                    "target": origin,
                    "seed_count": len(paths),
                    "status": "failed",
                    "exit_code": failed_exit_code,
                    "result_count": 0,
                    "new_results": 0,
                    "duplicate_results": 0,
                    "queued_targets_remaining": len({item[0] for item in queue}),
                    "command": failed_command,
                    "timeout_seconds": limits.command_timeout_seconds,
                    "error": seeded_error,
                }
                recursive_rounds.append(round_record)
                await emit({
                    "stage": stage_name,
                    "status": "failed",
                    "detail": (
                        f"{seeded_error}; command={failed_command!r}; "
                        f"configured_timeout={limits.command_timeout_seconds}s"
                    ),
                    **round_record,
                })
                stop_reason = "timeout" if isinstance(exc, TimeoutError) else "error"
                break
            except Exception as exc:
                seeded_error = f"Kiterunner seeded discovery failed with {type(exc).__name__}: {exc}"
                logger.exception("Recursive API discovery failed | target=%s", origin)
                round_record = {
                    "round": round_number,
                    "target": origin,
                    "seed_count": len(paths),
                    "status": "failed",
                    "exit_code": None,
                    "result_count": 0,
                    "new_results": 0,
                    "duplicate_results": 0,
                    "queued_targets_remaining": len({item[0] for item in queue}),
                    "command": _command_from_error(seeded_error),
                    "timeout_seconds": limits.command_timeout_seconds,
                    "error": seeded_error,
                }
                recursive_rounds.append(round_record)
                await emit({
                    "stage": stage_name,
                    "status": "failed",
                    "detail": (
                        f"{seeded_error}; command={round_record['command']!r}; "
                        f"configured_timeout={limits.command_timeout_seconds}s"
                    ),
                    **round_record,
                })
                stop_reason = "error"
                break
        if stop_reason == "queue_empty" and queue:
            stop_reason = "recursion_limit"
        if stop_reason == "queue_empty" and not queue:
            stop_reason = "queue_empty"
        if seed_batches and not recursive_rounds:
            await emit(
                {
                    "stage": "Seeded API Discovery",
                    "status": "skipped",
                    "detail": (
                        f"No Kiterunner command ran because the {stop_reason} "
                        "prevented execution."
                    ),
                    "target": seed_batches[0][0],
                    "seed_count": 0,
                    "result_count": 0,
                    "exit_code": None,
                    "stop_reason": stop_reason,
                }
            )
        if recursive_rounds:
            recursive_rounds[-1]["stop_reason"] = stop_reason
        if seed_batches:
            await emit(
                {
                    "stage": "Recursive Discovery Summary",
                    "status": "completed" if stop_reason == "queue_empty" else "inconclusive",
                    "detail": (
                        f"Recursive discovery stopped: {stop_reason}; "
                        f"Kiterunner executed {len(recursive_rounds)} round(s)."
                    ),
                    "stop_reason": stop_reason,
                    "rounds": len(recursive_rounds),
                }
            )

    security_target = _api_candidate_security_target(
        normalized_target,
        gateway_target,
        authorized_origins,
        kiterunner_results
        + seeded_results
        + (
            file_result.get("results", [])
            if isinstance(file_result, dict)
            else []
        ),
    )
    await emit("Endpoint Correlation", "running")
    discovery_results, _ = _correlate_discoveries(
        kiterunner_results + seeded_results,
        file_result.get("results", []),
        normalized_target,
        gateway_target,
        frontend_page_scanned=bool(file_result.get("page_sources")),
        security_target=security_target,
    )
    endpoints_for_testing, jwt_inventory_exclusions = _jwt_inventory_candidates(
        discovery_results,
        security_target,
        authorized_origins,
        Modules._endpoint_allowlist(),
    )
    authentication_discovery_inventory = _jwt_discovery_inventory(
        discovery_results,
        security_target,
        authorized_origins,
    )
    await emit(
        "Endpoint Correlation",
        "completed",
        f"Correlated {len(discovery_results)} unique URL/method record(s).",
    )
    logger.info(
        "Security Testing input prepared | target=%s | eligible_endpoints=%d",
        security_target,
        len(endpoints_for_testing),
    )

    if kiterunner_error and file_error:
        report = build_pentest_report(
            scan_failed=True,
            failure_reason="All discovery stages failed before evidence collection.",
        )
        _set_security_dispositions(
            discovery_results,
            report.get("endpoint_assessments", []),
            security_target,
            "Discovery failed before security testing could run.",
        )
        return 424, {
            "detail": "API Discovery and File Discovery failed.",
            "target": normalized_target,
            "discovery_target": discovery_target,
            "security_target": security_target,
            "summary": report["summary"],
            "findings": report["findings"],
            "test_results": report["test_results"],
            "endpoint_assessments": report["endpoint_assessments"],
            "bola_assessments": report["bola_assessments"],
            "bola_baselines": report["bola_baselines"],
            "bola_active_tests": report["bola_active_tests"],
            "discovery_results": discovery_results,
            "discovery_stages": list(stages.values()),
            "discovery_errors": {
                key: value
                for key, value in {
                    "api_discovery": kiterunner_error,
                    "kiterunner_seed_discovery": seeded_error,
                    "file_discovery": file_error,
                }.items()
                if value
            },
        }

    await emit("Security Testing", "running")
    try:
        analyzed = await asyncio.to_thread(
            Modules().analyze_endpoints,
            security_target,
            endpoints_for_testing,
            auto_jwt_local_lab=auto_jwt_local_lab,
            discovered_inventory=authentication_discovery_inventory,
            discovered_route_templates=[
                item
                for item in discovery_results
                if isinstance(item, dict)
                and (item.get("template") or item.get("is_template"))
            ],
        )
    except ValueError:
        raise
    except Exception as exc:
        logger.exception("Security Testing failed | error=%s", type(exc).__name__)
        await emit("Security Testing", "error", "Security test execution failed.")
        report = build_pentest_report(
            scan_failed=True,
            failure_reason="Security testing failed after discovery.",
        )
        _set_security_dispositions(
            discovery_results,
            report.get("endpoint_assessments", []),
            security_target,
            "Security testing failed before this endpoint was assessed.",
        )
        return 424, {
            "detail": "Security testing failed after discovery.",
            "target": normalized_target,
            "discovery_target": discovery_target,
            "security_target": security_target,
            "summary": report["summary"],
            "findings": report["findings"],
            "test_results": report["test_results"],
            "endpoint_assessments": report["endpoint_assessments"],
            "bola_assessments": report["bola_assessments"],
            "bola_baselines": report["bola_baselines"],
            "bola_active_tests": report["bola_active_tests"],
            "discovery_results": discovery_results,
            "discovery_stages": list(stages.values()),
            "discovery_errors": {
                key: value
                for key, value in {
                    "api_discovery": kiterunner_error,
                    "kiterunner_seed_discovery": seeded_error,
                    "file_discovery": file_error,
                }.items()
                if value
            },
        }

    for endpoint in analyzed:
        correlated = next(
            (
                item
                for item in endpoints_for_testing
                if item.get("method") == endpoint.get("method")
                and item.get("path") == endpoint.get("path")
            ),
            None,
        )
        if correlated:
            endpoint["discovery_sources"] = correlated.get("discovery_sources", ["kiterunner"])
            endpoint["verification_status"] = correlated.get(
                "verification_status", "discovered"
            )
            endpoint["discovery_evidence"] = correlated.get("discovery_evidence", [])
    report = build_pentest_report(analyzed)
    selected_count = sum(1 for endpoint in analyzed if endpoint.get("jwt_selected"))
    tested_count = report["summary"]["tested_endpoints"]
    request_count = report["summary"]["request_count"]
    logger.info(
        "Security Testing completed | target=%s | input_endpoints=%d | "
        "selected_endpoints=%d | tested_endpoints=%d | request_attempts=%d",
        security_target,
        len(endpoints_for_testing),
        selected_count,
        tested_count,
        request_count,
    )
    await emit(
        "Security Testing",
        "completed",
        f"Input {len(endpoints_for_testing)} endpoint(s); selected {selected_count}; "
        f"actually tested {tested_count}; {request_count} request attempt(s).",
    )
    _set_security_dispositions(
        discovery_results,
        report.get("endpoint_assessments", []),
        security_target,
        "This discovery record was not eligible for security testing.",
    )
    summary = report["summary"]
    discovered_count = summary["discovered_endpoints"]
    allowlist_targets = sorted(
        {
            (endpoint.get("method"), endpoint.get("path"))
            for endpoint in analyzed
            if endpoint.get("jwt_allowlisted")
        }
    )
    zero_request_reason = None
    if not request_count:
        if not endpoints_for_testing:
            zero_request_reason = (
                "No eligible resolved API endpoints were present in the authorized "
                "discovery inventory."
            )
        else:
            skipped_reasons = list(
                dict.fromkeys(
                    endpoint.get("jwt_selection_reason")
                    for endpoint in analyzed
                    if endpoint.get("jwt_selection_reason")
                )
            )
            if not skipped_reasons:
                skipped_reasons = list(
                    dict.fromkeys(
                        result.get("reason")
                        for endpoint in analyzed
                        for result in endpoint.get("test_results", [])
                        if result.get("reason")
                    )
                )
            zero_request_reason = (
                "No JWT endpoint requests were sent. "
                + (
                    " ".join(skipped_reasons)
                    if skipped_reasons
                    else "No request attempt was recorded by the JWT module."
                )
            )
    login_workflows = [
        result.get("discovery")
        for endpoint in analyzed
        for result in endpoint.get("test_results", [])
        if result.get("test_module") == "jwt_authentication"
        and isinstance(result.get("discovery"), dict)
    ]
    if login_workflows:
        selected_workflow = next(
            (
                workflow
                for workflow in login_workflows
                if workflow.get("selected_login_route")
            ),
            login_workflows[0],
        )
        attempt_statuses = {
            workflow.get("login_attempt_status") for workflow in login_workflows
        }
        auth_statuses = {
            workflow.get("authentication_result") for workflow in login_workflows
        }
        login_summary = {
            "login_discovery_status": (
                "found"
                if any(
                    workflow.get("login_discovery_status") == "found"
                    for workflow in login_workflows
                )
                else "not_found"
            ),
            "selected_login_route": selected_workflow.get("selected_login_route"),
            "selected_login_method": selected_workflow.get("selected_login_method"),
            "selected_login_evidence_source": selected_workflow.get(
                "selected_login_evidence_source", []
            ),
            "login_attempt_status": (
                "succeeded"
                if "succeeded" in attempt_statuses
                else "failed"
                if "failed" in attempt_statuses
                else "unavailable"
            ),
            "authentication_result": (
                "success"
                if "success" in auth_statuses
                else "failed"
                if "failed" in auth_statuses
                else "inconclusive"
                if "inconclusive" in auth_statuses
                else "unavailable"
            ),
            "token_or_session_detected": any(
                workflow.get("token_or_session_detected") is True
                for workflow in login_workflows
            ),
            "login_attempts": selected_workflow.get("login_attempts", []),
            "eligible_endpoints": len(endpoints_for_testing),
            "selected_endpoints": sum(
                1 for endpoint in analyzed if endpoint.get("jwt_selected")
            ),
            "actually_tested_endpoints": summary.get("tested_endpoints", 0),
            "request_count": summary.get("request_count", 0),
        }
    else:
        login_summary = {
            "login_discovery_status": "not_found",
            "login_attempt_status": "unavailable",
            "authentication_result": "unavailable",
            "token_or_session_detected": False,
            "login_attempts": [],
            "eligible_endpoints": len(endpoints_for_testing),
            "selected_endpoints": 0,
            "actually_tested_endpoints": 0,
            "request_count": 0,
        }

    discovery_category_counts = {
        category: sum(
            1
            for endpoint in discovery_results
            if isinstance(endpoint, dict) and _discovery_category(endpoint) == category
        )
        for category in ("actionable", "not_found", "blocked", "inconclusive")
    }
    unique_discovery_identities = set()
    for endpoint in discovery_results:
        if not isinstance(endpoint, dict) or endpoint.get("template") or endpoint.get("is_template"):
            continue
        endpoint_url = (
            endpoint.get("resolved_url")
            or endpoint.get("verification_url")
            or endpoint.get("url")
        )
        method = str(endpoint.get("method") or "").strip().upper()
        try:
            parsed_endpoint_url = urlsplit(endpoint_url or "")
        except ValueError:
            continue
        if (
            method
            and parsed_endpoint_url.scheme in {"http", "https"}
            and parsed_endpoint_url.netloc
            and parsed_endpoint_url.path not in {"", "/"}
        ):
            unique_discovery_identities.add(
                (
                    parsed_endpoint_url.scheme.lower(),
                    parsed_endpoint_url.netloc.lower(),
                    parsed_endpoint_url.path,
                    method,
                )
            )
    summary.update(
        {
            "jwt_authentication_workflow": login_summary,
            "total_endpoints": discovered_count,
            "discovered_endpoints": discovered_count,
            "discovery_inventory_records": len(discovery_results),
            "unique_discovery_endpoints": len(unique_discovery_identities),
            "actionable_discovery_endpoints": (
                len(discovery_results) - discovery_category_counts["not_found"]
            ),
            "excluded_not_found_discovery_endpoints": discovery_category_counts["not_found"],
            "blocked_discovery_endpoints": discovery_category_counts["blocked"],
            "discovery_inconclusive_endpoints": discovery_category_counts["inconclusive"],
            "discovery_inventory_endpoints": len(discovery_results),
            "security_input_endpoints": len(endpoints_for_testing),
            "jwt_inventory_excluded_endpoints": len(jwt_inventory_exclusions),
            "jwt_inventory_exclusion_reasons": jwt_inventory_exclusions,
            "jwt_unsupported_method_endpoints": sum(
                "Unsupported or unknown discovery method" in item["reason"]
                for item in jwt_inventory_exclusions
            ),
            "jwt_unresolved_or_dynamic_endpoints": sum(
                "unresolved" in item["reason"].lower()
                or "dynamic template" in item["reason"].lower()
                for item in jwt_inventory_exclusions
            ),
            "jwt_out_of_scope_endpoints": sum(
                "outside the authorized scan scope" in item["reason"]
                for item in jwt_inventory_exclusions
            ),
            "jwt_zero_request_reason": zero_request_reason,
            "selected_endpoints": sum(1 for endpoint in analyzed if endpoint.get("jwt_selected")),
            "selected_for_testing_endpoints": sum(
                1 for endpoint in analyzed if endpoint.get("jwt_selected")
            ),
            "actually_tested_endpoints": tested_count,
            "attempted_endpoints": sum(
                1
                for endpoint in report.get("endpoint_assessments", [])
                if endpoint.get("actually_tested")
            ),
            "discovery_skipped_endpoints": sum(
                1 for endpoint in discovery_results
                if endpoint.get("security_status") == "skipped"
            ),
            "discovery_inconclusive_endpoints": sum(
                1 for endpoint in discovery_results
                if endpoint.get("verification_status") == "inconclusive"
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
            "discovery_result_count": len(discovery_results),
            "seeded_discovery": seeded_outcome,
            "discovery_rounds": recursive_rounds,
            "recursive_discovery_stop_reason": stop_reason,
            "authorized_scope": authorized_origins,
            "discovery_errors": {
                key: value
                for key, value in {
                    "api_discovery": kiterunner_error,
                    "kiterunner_seed_discovery": seeded_error,
                    "file_discovery": file_error,
                }.items()
                if value
            },
        }
    )
    logger.info(
        "Scan completed | target=%s | endpoints_found=%d",
        normalized_target,
        discovered_count,
    )
    return 200, {
        "target": normalized_target,
        "discovery_target": discovery_target,
        "security_target": security_target,
        "results": analyzed,
        "summary": summary,
        "findings": report["findings"],
        "test_results": report["test_results"],
        "endpoint_assessments": report["endpoint_assessments"],
        "bola_assessments": report["bola_assessments"],
        "bola_baselines": report["bola_baselines"],
        "bola_active_tests": report["bola_active_tests"],
        "discovery_results": discovery_results,
        "discovery_summary": file_result.get("summary", {}),
        "discovery_stages": list(stages.values()),
        "discovery_errors": {
            key: value
            for key, value in {
                "api_discovery": kiterunner_error,
                "kiterunner_seed_discovery": seeded_error,
                "file_discovery": file_error,
            }.items()
            if value
        },
    }


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


@app.get("/file-discovery/wordlists/default")
def default_file_discovery_wordlist():
    return {"name": "MicroScan default", "wordlist": DEFAULT_WORDLIST}


@app.post("/file-discovery")
async def file_discovery(request: FileDiscoveryRequest):
    try:
        return await FileDiscovery().scan(
            target=request.target,
            wordlist=request.wordlist,
            requests_per_second=request.requests_per_second,
            timeout=request.timeout,
            concurrency=request.concurrency,
            analyze_javascript=request.analyze_javascript,
            verify_endpoints=request.verify_endpoints,
            gateway_target=request.gateway_target,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/scan")
async def scan(
    target: str,
    num: int = 1000,
    auto_jwt_local_lab: bool = False,
    stream: bool = False,
    scope_origins: list[str] = Query(default=[]),
):
    if not stream:
        try:
            status, payload = await _run_scan_pipeline(
                target,
                num,
                auto_jwt_local_lab,
                scope_origins=scope_origins,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse(status_code=status, content=payload) if status != 200 else payload

    async def event_stream():
        queue = asyncio.Queue()

        async def progress(event):
            await queue.put({"type": "progress", **event})

        async def execute():
            try:
                status, payload = await _run_scan_pipeline(
                    target,
                    num,
                    auto_jwt_local_lab,
                    progress,
                    scope_origins,
                )
                await queue.put(
                    {"type": "complete", "status_code": status, "payload": payload}
                )
            except HTTPException as exc:
                await queue.put(
                    {
                        "type": "error",
                        "status_code": exc.status_code,
                        "detail": exc.detail,
                    }
                )
            except ValueError as exc:
                await queue.put(
                    {"type": "error", "status_code": 400, "detail": str(exc)}
                )
            finally:
                await queue.put(None)

        task = asyncio.create_task(execute())
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
