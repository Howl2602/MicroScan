import asyncio
import hashlib
import html
import ipaddress
import inspect
import re
import time
import uuid
from dataclasses import dataclass
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

import httpx


DEFAULT_WORDLIST = (
    "robots.txt\n"
    "sitemap.xml\n"
    "swagger\n"
    "swagger.json\n"
    "openapi.json\n"
    "api-docs\n"
    "docs\n"
    "static/\n"
    "assets/\n"
    "backup.zip\n"
    "backup.tar.gz\n"
    "config.bak\n"
    ".env.bak"
)
MAX_WORDLIST_ENTRIES = 100
MAX_BODY_BYTES = 1024 * 1024
MAX_SCRIPTS = 10
MAX_JS_ENDPOINTS = 100
MAX_HTML_ENDPOINTS = 100
MAX_EXECUTION_SECONDS = 60
MAX_EVIDENCE_CHARS = 180
MAX_KITERUNNER_SEEDS = 20

SECRET_PATTERN = re.compile(
    r"(?i)(authorization|cookie|password|passwd|token|api[_-]?key|access[_-]?key|private[_-]?key|secret)"
    r"(\s*[:=]\s*|\s+)([\"']?)[^\"'\s,;}]+"
)
QUOTED_SECRET_PATTERN = re.compile(
    r"""(?i)(authorization|cookie|password|passwd|token|api[_-]?key|access[_-]?key|private[_-]?key|secret)"""
    r"""(\s*[:=]\s*)(["'])(.*?)\3"""
)
SCRIPT_PATTERN = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""",
    re.IGNORECASE,
)
HTML_ENDPOINT_PATTERN = re.compile(
    r"""<\s*(a|form)\b[^>]*?\b(href|action)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))[^>]*>""",
    re.IGNORECASE,
)
JS_PATTERNS = (
    re.compile(r"""(?i)\bfetch\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?i)\baxios(?:\.\w+)?\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?i)\b(?:API_BASE|API_URL|BASE_URL|baseURL|baseUrl)\s*[:=]\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?i)\.open\s*\(\s*["'`](?:GET|POST|PUT|PATCH|DELETE)["'`]\s*,\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""["'`]((?:https?://[^"'`\s]+|/?(?:api|v\d+)(?:/[^"'`\s]*)?))["'`]"""),
)
JS_BASE_CONSTANT_PATTERN = re.compile(
    r"""(?i)\b(?:const|let|var)\s+([A-Z_$][\w$]*(?:API|BASE|URL)[A-Z_$\w]*)\s*=\s*(["'])([^"']+)\2"""
)
JS_BASE_ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)\b(API_BASE|API_URL|BASE_URL|baseURL|baseUrl)\s*[:=]\s*(["'])([^"']+)\2"""
)
STATIC_TEMPLATE_CONSTANT_PATTERN = re.compile(r"\$\{([A-Z_$][\w$]*)\}")
DYNAMIC_TEMPLATE_PATTERN = re.compile(
    r"""\$\{[^}]*\}|\{[A-Za-z_$][\w$]*\}|(?<![\w]):[A-Za-z_$][\w$]*(?=/|$)"""
)


@dataclass(frozen=True)
class FetchResult:
    status_code: int | None
    content_type: str | None
    size: int
    elapsed_ms: float
    body: bytes
    error: str | None = None
    redirected: bool = False
    truncated: bool = False
    allow: str | None = None

    def signature_for(self, url: str):
        body = self.body.decode("utf-8", errors="replace")
        path = urlsplit(url).path or "/"
        for variant in {path, quote(path, safe="/"), quote(path, safe=""), unquote(path)}:
            if variant:
                body = body.replace(variant, "<PATH>")
        return (
            self.status_code,
            self.content_type,
            len(body),
            hashlib.sha256(body.encode("utf-8")).hexdigest(),
        )


def normalize_origin(target: str) -> str:
    candidate = target.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"http://{candidate}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be a valid HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not allowed.")

    hostname = parsed.hostname.rstrip(".").lower()
    try:
        is_loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise ValueError("File Discovery is limited to loopback targets.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Target must use a valid port.") from exc
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _redact_evidence(value: str) -> str:
    value = html.unescape(value)
    value = QUOTED_SECRET_PATTERN.sub(r"\1\2\3[REDACTED]\3", value)
    value = SECRET_PATTERN.sub(r"\1\2[REDACTED]", value)
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
    return value[:MAX_EVIDENCE_CHARS]


def _same_origin(first: str, second: str) -> bool:
    left, right = urlsplit(first), urlsplit(second)
    return (left.scheme, left.hostname, left.port) == (
        right.scheme,
        right.hostname,
        right.port,
    )


def _canonical_endpoint(raw_url: str, page_url: str) -> str | None:
    candidate = raw_url.strip().rstrip(".,);")
    if not candidate or candidate.startswith(("data:", "javascript:", "#")):
        return None
    resolved = urljoin(page_url, candidate)
    parsed = urlsplit(resolved)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def extract_script_urls(page_url: str, document: str) -> list[str]:
    found = []
    for match in SCRIPT_PATTERN.finditer(document):
        raw = next((group for group in match.groups() if group), "").strip()
        url = _canonical_endpoint(raw, page_url)
        if url and _same_origin(page_url, url) and url not in found:
            found.append(url)
        if len(found) >= MAX_SCRIPTS:
            break
    return found


def extract_javascript_endpoints(
    source_url: str, script: str, base_url: str | None = None
) -> list[dict]:
    found = {}
    covered_spans = []
    resolution_base = base_url or source_url
    constants = {
        match.group(1): match.group(3).strip()
        for match in JS_BASE_CONSTANT_PATTERN.finditer(script)
    }
    constants.update(
        {
            match.group(1): match.group(3).strip()
            for match in JS_BASE_ASSIGNMENT_PATTERN.finditer(script)
        }
    )
    constants.update(
        {
            key.lower(): value
            for key, value in list(constants.items())
        }
    )
    for constant, value in constants.copy().items():
        constants.setdefault(constant.upper(), value)
    explicit_api_bases = {
        name: _canonical_endpoint(value, resolution_base)
        for name, value in constants.items()
    }
    explicit_api_bases = {
        name: value for name, value in explicit_api_bases.items() if value
    }
    unique_explicit_base = (
        next(iter(explicit_api_bases.values()))
        if len(set(explicit_api_bases.values())) == 1
        else None
    )
    for pattern_index, pattern in enumerate(JS_PATTERNS):
        for match in pattern.finditer(script):
            if pattern_index == len(JS_PATTERNS) - 1 and any(
                start <= match.start() < end for start, end in covered_spans
            ):
                continue
            raw = match.group(1).strip()
            resolved_raw = raw
            used_constant = None
            for _ in range(4):
                constant_match = next(
                    (
                        token.group(1)
                        for token in STATIC_TEMPLATE_CONSTANT_PATTERN.finditer(
                            resolved_raw
                        )
                        if token.group(1) in constants
                    ),
                    None,
                )
                if constant_match:
                    used_constant = constant_match
                replacement = STATIC_TEMPLATE_CONSTANT_PATTERN.sub(
                    lambda token: constants.get(token.group(1), token.group(0)),
                    resolved_raw,
                )
                if replacement == resolved_raw:
                    break
                resolved_raw = replacement
            unresolved_constant = any(
                token.group(1) not in constants
                for token in STATIC_TEMPLATE_CONSTANT_PATTERN.finditer(resolved_raw)
            )
            prefix = script[max(0, match.start() - 50):match.start()]
            suffix = script[match.end():match.end() + 120]
            has_dynamic_concat = bool(
                re.search(r"\+\s*$", prefix) or re.match(r"\s*\+", suffix)
            )
            is_template = (
                bool(DYNAMIC_TEMPLATE_PATTERN.search(resolved_raw))
                or unresolved_constant
                or has_dynamic_concat
            )
            normalized_raw = raw.lower()
            used_base = constants.get(used_constant) if used_constant else None
            if not used_constant and not is_template and unique_explicit_base:
                is_relative_reference = not normalized_raw.startswith(
                    ("http://", "https://", "//")
                )
                if is_relative_reference and pattern_index != 2:
                    used_base = unique_explicit_base
            endpoint_base = (
                used_base
                if used_base and used_constant
                else unique_explicit_base
                if used_base
                else resolution_base
            )
            endpoint = (
                None
                if is_template
                else _canonical_endpoint(
                    resolved_raw if used_constant else raw,
                    endpoint_base,
                )
            )
            if not endpoint and not is_template:
                continue

            context = script[
                max(0, match.start() - 50):min(len(script), match.end() + 120)
            ]
            invocation_start = script.rfind("api(", max(0, match.start() - 100), match.start())
            if (
                invocation_start >= 0
                and ")" in script[invocation_start:match.start()]
            ):
                invocation_start = -1
            invocation_context = (
                script[invocation_start:match.end() + 1000]
                if invocation_start >= 0
                else ""
            )
            method_match = re.search(
                r"""(?i)\baxios\.(get|post|put|patch|delete)\s*\(""",
                match.group(0),
            )
            xhr_method_match = re.search(
                r"""(?i)\.open\s*\(\s*["'](GET|POST|PUT|PATCH|DELETE)["']\s*,""",
                match.group(0),
            )
            option_match = re.search(
                r"""(?i)^\s*,\s*\{[^}]{0,500}\bmethod\s*:\s*["'](GET|POST|PUT|PATCH|DELETE)["']""",
                suffix,
            )
            method = (
                method_match.group(1).upper()
                if method_match
                else xhr_method_match.group(1).upper()
                if xhr_method_match
                else option_match.group(1).upper()
                if option_match
                else "GET"
            )
            json_body_match = re.search(
                r"""(?is)\bbody\s*:\s*JSON\.stringify\s*\(\s*\{([^{}]{0,700})\}""",
                invocation_context,
            )
            request_body_fields = (
                list(
                    dict.fromkeys(
                        re.findall(
                            r"""(?:^|,)\s*([A-Za-z_$][\w$]*)\s*(?::|(?=,|$))""",
                            json_body_match.group(1),
                        )
                    )
                )
                if json_body_match
                else []
            )
            request_content_type = None
            request_content_type_evidence = None
            if json_body_match:
                if re.search(
                    r"""(?i)["']Content-Type["']\s*:\s*["']application/json["']""",
                    invocation_context,
                ):
                    request_content_type = "application/json"
                    request_content_type_evidence = "javascript_request"
                elif re.search(
                    r"""(?is)\bfunction\s+api\s*\([^)]*\)\s*\{.{0,1600}?["']Content-Type["']\s*:\s*["']application/json["']""",
                    script,
                ):
                    request_content_type = "application/json"
                    request_content_type_evidence = "shared_api_helper"
            candidate_path = (
                urlsplit(endpoint).path
                if endpoint
                else resolved_raw.split("?", 1)[0].split("#", 1)[0]
            )
            observed_path = (
                urlsplit(resolved_raw).path
                if re.match(r"(?i)^https?://", resolved_raw)
                else resolved_raw.split("?", 1)[0].split("#", 1)[0]
            )
            has_api_path = bool(
                re.match(r"^/?api(?:/|$)", observed_path, re.IGNORECASE)
                or re.match(r"^/?api(?:/|$)", candidate_path, re.IGNORECASE)
            )
            is_api_endpoint = pattern_index in {0, 1, 3} and (
                has_api_path or bool(used_constant)
            )
            identity = ("template", raw, method) if is_template else (endpoint, method)
            record = {
                "url": endpoint,
                "discovered_url": raw,
                "original_observed_url": raw,
                "method": method,
                "relative_to_frontend": not is_template
                and not normalized_raw.startswith(("http://", "https://", "//")),
                "is_api_endpoint": is_api_endpoint,
                "classification": "api_endpoint" if is_api_endpoint else "unresolved",
                "is_template": is_template,
                "evidence": _redact_evidence(context),
                "request_body_fields": request_body_fields,
                "request_content_type": request_content_type,
                "request_content_type_evidence": request_content_type_evidence,
                "source_url": source_url,
                "resolution_base": endpoint_base,
                "resolution_rule": (
                    "static_constant_template"
                    if resolved_raw != raw
                    else "explicit_api_base"
                    if endpoint_base != resolution_base
                    else "urljoin"
                ),
            }
            if endpoint:
                endpoint_parts = urlsplit(endpoint)
                record["resolved_url"] = endpoint
                record["resolved_origin"] = urlunsplit(
                    (
                        endpoint_parts.scheme,
                        endpoint_parts.netloc,
                        "",
                        "",
                        "",
                    )
                )
            if is_template:
                if resolved_raw != raw:
                    record["resolved_template_url"] = resolved_raw
                template = (
                    resolved_raw
                    if DYNAMIC_TEMPLATE_PATTERN.search(resolved_raw)
                    else f"[dynamic] + {raw}"
                    if re.search(r"\+\s*$", prefix)
                    else f"{raw} + [dynamic]"
                )
                record["template"] = _redact_evidence(template)
            found.setdefault(identity, record)
            if pattern_index < len(JS_PATTERNS) - 1:
                covered_spans.append((match.start(), match.end()))
    return list(found.values())


def extract_html_endpoints(page_url: str, document: str) -> list[dict]:
    endpoints = {}
    for match in HTML_ENDPOINT_PATTERN.finditer(document):
        if len(endpoints) >= MAX_HTML_ENDPOINTS:
            break
        tag = match.group(1).lower()
        raw = next((group for group in match.groups()[2:] if group), "").strip()
        endpoint = _canonical_endpoint(raw, page_url)
        if not endpoint:
            continue
        method_match = re.search(
            r"""\bmethod\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""",
            match.group(0),
            re.IGNORECASE,
        )
        method = (
            next((value for value in method_match.groups() if value), "GET").upper()
            if tag == "form" and method_match
            else "GET"
        )
        is_api_endpoint = bool(
            tag == "form"
            and re.match(
                r"^/api(?:/|$)",
                urlsplit(endpoint).path,
                re.IGNORECASE,
            )
        )
        endpoints.setdefault(
            (method, endpoint),
            {
                "url": endpoint,
                "method": method,
                "relative_to_frontend": not raw.lower().startswith(
                    ("http://", "https://", "//")
                ),
                "is_api_endpoint": is_api_endpoint,
                "classification": "api_endpoint" if is_api_endpoint else "frontend_route",
                "evidence": _redact_evidence(match.group(0)),
                "source_url": page_url,
            },
        )
    return list(endpoints.values())


def _wordlist_entries(wordlist: str | None) -> list[str]:
    values = wordlist if wordlist is not None else DEFAULT_WORDLIST
    entries = []
    for line in values.splitlines():
        path = line.strip().lstrip("/")
        if not path or path.startswith("#") or "://" in path:
            continue
        if "?" in path or "#" in path or "\\" in path:
            raise ValueError("Wordlist entries must be plain paths without queries or fragments.")
        entries.append(path)
        if len(entries) > MAX_WORDLIST_ENTRIES:
            raise ValueError(f"Wordlists are limited to {MAX_WORDLIST_ENTRIES} paths.")
    return list(dict.fromkeys(entries))


class FileDiscovery:
    def __init__(self, transport=None):
        self.transport = transport

    @staticmethod
    async def _notify(progress_callback, stage, status, detail=None):
        if progress_callback is None:
            return
        result = progress_callback(
            {"stage": stage, "status": status, "detail": detail}
        )
        if inspect.isawaitable(result):
            await result

    async def _fetch(self, client, url: str, semaphore) -> FetchResult:
        start = time.perf_counter()
        try:
            async with semaphore:
                async with client.stream("GET", url, follow_redirects=False) as response:
                    body = bytearray()
                    truncated = False
                    content_length = response.headers.get("content-length", "")
                    declared_size = (
                        int(content_length)
                        if content_length.isdigit() and len(content_length) <= 15
                        else None
                    )
                    async for chunk in response.aiter_bytes():
                        remaining = MAX_BODY_BYTES - len(body)
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining or len(body) >= MAX_BODY_BYTES:
                            truncated = len(chunk) > remaining or declared_size is None or declared_size > MAX_BODY_BYTES
                            break
                    location = response.headers.get("location")
                    redirected = response.status_code is not None and 300 <= response.status_code < 400
                    if location:
                        destination = urljoin(url, location)
                        redirected = redirected or not _same_origin(url, destination)
                    return FetchResult(
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type", "").split(";", 1)[0].lower() or None,
                        size=declared_size if declared_size is not None else len(body),
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                        body=bytes(body),
                        redirected=redirected,
                        truncated=truncated,
                        allow=response.headers.get("allow"),
                    )
        except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError) as exc:
            return FetchResult(
                status_code=None,
                content_type=None,
                size=0,
                elapsed_ms=(time.perf_counter() - start) * 1000,
                body=b"",
                error=type(exc).__name__,
            )

    async def scan(
        self,
        target: str,
        wordlist: str | None = None,
        requests_per_second: float = 2,
        timeout: float = 5,
        concurrency: int = 2,
        analyze_javascript: bool = True,
        verify_endpoints: bool = False,
        gateway_target: str | None = None,
        progress_callback=None,
    ) -> dict:
        page_url = normalize_origin(target)
        entries = _wordlist_entries(wordlist)
        rate = min(max(float(requests_per_second), 0.5), 5)
        timeout = min(max(float(timeout), 1), 15)
        concurrency = min(max(int(concurrency), 1), 5)
        if verify_endpoints and not gateway_target:
            raise ValueError("A Gateway target is required when endpoint verification is enabled.")
        gateway_origin = normalize_origin(gateway_target) if verify_endpoints and gateway_target else None
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=httpx.Timeout(timeout),
            limits=limits,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": "MicroScan-FileDiscovery/1.0"},
        ) as client:
            semaphore = asyncio.Semaphore(concurrency)
            request_lock = asyncio.Lock()
            next_request = [0.0]
            deadline = time.monotonic() + MAX_EXECUTION_SECONDS
            requests_made = [0]
            requests_failed = [0]
            execution_limited = [False]

            async def limited_fetch(url):
                async with request_lock:
                    delay = max(0.0, next_request[0] - time.monotonic())
                    if time.monotonic() + delay >= deadline:
                        execution_limited[0] = True
                        requests_failed[0] += 1
                        return FetchResult(None, None, 0, 0, b"", error="ExecutionLimitExceeded")
                    if delay:
                        await asyncio.sleep(delay)
                    if time.monotonic() >= deadline:
                        execution_limited[0] = True
                        requests_failed[0] += 1
                        return FetchResult(None, None, 0, 0, b"", error="ExecutionLimitExceeded")
                    next_request[0] = time.monotonic() + 1 / rate
                    requests_made[0] += 1
                try:
                    async with asyncio.timeout(max(0, deadline - time.monotonic())):
                        result = await self._fetch(client, url, semaphore)
                        if result.error:
                            requests_failed[0] += 1
                        return result
                except asyncio.TimeoutError:
                    execution_limited[0] = True
                    requests_failed[0] += 1
                    return FetchResult(None, None, 0, 0, b"", error="ExecutionLimitExceeded")

            baseline_task = asyncio.create_task(limited_fetch(page_url))
            calibration_url = urljoin(page_url, f".microscan-missing-{uuid.uuid4().hex}")
            calibration_task = asyncio.create_task(limited_fetch(calibration_url))
            baseline, calibration = await asyncio.gather(baseline_task, calibration_task)
            generic_signature = (
                calibration.signature_for(calibration_url)
                if calibration.status_code is not None
                else None
            )
            scripts = []
            endpoints = {}
            page_sources = []

            if analyze_javascript and baseline.content_type and (
                "html" in baseline.content_type or baseline.body.lstrip().startswith(b"<")
            ):
                await self._notify(progress_callback, "JavaScript Analysis", "running")
                page_sources.append(page_url)
                document = baseline.body.decode("utf-8", errors="replace")
                for endpoint in extract_html_endpoints(page_url, document):
                    endpoints[(endpoint["method"], endpoint["url"])] = {
                        "url": endpoint["url"],
                        "discovered_url": endpoint["url"],
                        "method": endpoint["method"],
                        "relative_to_frontend": endpoint["relative_to_frontend"],
                        "is_api_endpoint": endpoint["is_api_endpoint"],
                        "classification": endpoint["classification"],
                        "sources": ["html"],
                        "verification_status": "discovered",
                        "status_code": None,
                        "content_type": None,
                        "size": None,
                        "response_time_ms": None,
                        "evidence": [
                            {
                                "source_url": page_url,
                                "snippet": endpoint["evidence"],
                            }
                        ],
                    }
                script_urls = extract_script_urls(page_url, document)
                script_results = await asyncio.gather(
                    *(limited_fetch(script_url) for script_url in script_urls)
                )
                for script_url, result in zip(script_urls, script_results):
                    if not result.status_code or not 200 <= result.status_code < 300 or result.redirected or result.error:
                        continue
                    scripts.append({"url": script_url, "status_code": result.status_code})
                    script = result.body.decode("utf-8", errors="replace")
                    for endpoint in extract_javascript_endpoints(
                        script_url, script, base_url=page_url
                    ):
                        if len(endpoints) >= MAX_JS_ENDPOINTS:
                            break
                        key = (
                            endpoint["method"],
                            endpoint["url"]
                            or f"template:{endpoint['template']}",
                        )
                        item = endpoints.setdefault(
                            key,
                            {
                                "url": endpoint["url"],
                                "discovered_url": endpoint["discovered_url"],
                                "original_observed_url": endpoint["original_observed_url"],
                                "method": endpoint["method"],
                                "relative_to_frontend": endpoint["relative_to_frontend"],
                                "is_api_endpoint": endpoint["is_api_endpoint"],
                                "classification": endpoint["classification"],
                                "is_template": endpoint["is_template"],
                                "resolved_url": endpoint.get("resolved_url"),
                                "resolved_origin": endpoint.get("resolved_origin"),
                                "resolution_base": endpoint.get("resolution_base"),
                                "resolution_rule": endpoint.get("resolution_rule"),
                                "resolution_status": (
                                    "unresolved"
                                    if endpoint["is_template"]
                                    or endpoint["relative_to_frontend"]
                                    else "resolved"
                                ),
                                "sources": [],
                                "verification_status": "discovered",
                                "status_code": None,
                                "content_type": None,
                                "request_body_fields": endpoint.get(
                                    "request_body_fields", []
                                ),
                                "request_content_type": endpoint.get(
                                    "request_content_type"
                                ),
                                "request_content_type_evidence": endpoint.get(
                                    "request_content_type_evidence"
                                ),
                                "size": None,
                                "response_time_ms": None,
                                "evidence": [],
                            },
                        )
                        if endpoint.get("request_body_fields"):
                            item["request_body_fields"] = endpoint[
                                "request_body_fields"
                            ]
                        if endpoint.get("request_content_type"):
                            item["request_content_type"] = endpoint[
                                "request_content_type"
                            ]
                            item["request_content_type_evidence"] = endpoint.get(
                                "request_content_type_evidence"
                            )
                        if endpoint.get("template"):
                            item["template"] = endpoint["template"]
                        if "javascript" not in item["sources"]:
                            item["sources"].append("javascript")
                        if len(item["evidence"]) < 5:
                            item["evidence"].append(
                                {"source_url": script_url, "snippet": endpoint["evidence"]}
                            )
                    if len(endpoints) >= MAX_JS_ENDPOINTS:
                        break
                await self._notify(
                    progress_callback,
                    "JavaScript Analysis",
                    "completed",
                    f"Analyzed {len(scripts)} JavaScript file(s).",
                )
            elif analyze_javascript:
                await self._notify(
                    progress_callback,
                    "JavaScript Analysis",
                    "skipped",
                    "The target did not return an HTML document.",
                )

            async def probe_path(path):
                url = urljoin(page_url, path)
                response = await limited_fetch(url)
                if response.error:
                    state = "inconclusive"
                elif response.redirected:
                    state = "blocked"
                elif response.status_code == 404:
                    state = "not_found"
                elif response.status_code in {401, 403}:
                    state = "blocked"
                elif generic_signature and response.signature_for(url) == generic_signature:
                    state = "not_found"
                elif (
                    response.content_type == "text/html"
                    and baseline.content_type == "text/html"
                ):
                    state = "inconclusive"
                elif response.status_code and 200 <= response.status_code < 300:
                    state = "verified"
                elif response.status_code and 300 <= response.status_code < 400:
                    state = "blocked"
                else:
                    state = "inconclusive"
                return {
                    "url": url,
                    "method": "GET",
                    "status_code": response.status_code,
                    "content_type": response.content_type,
                    "size": response.size,
                    "content_truncated": response.truncated,
                    "response_time_ms": round(response.elapsed_ms, 2),
                    "verification_status": state,
                    "sources": ["wordlist"],
                    "evidence": [],
                }

            probed = await asyncio.gather(*(probe_path(path) for path in entries))
            for item in probed:
                key = (item["method"], item["url"])
                prior = endpoints.get(key)
                if prior:
                    prior.update(
                        {
                            key: item[key]
                            for key in (
                                "status_code",
                                "content_type",
                                "size",
                                "content_truncated",
                                "response_time_ms",
                            )
                        }
                    )
                    prior["verification_status"] = item["verification_status"]
                    if "wordlist" not in prior["sources"]:
                        prior["sources"].append("wordlist")
                else:
                    endpoints[key] = item

            if gateway_origin:
                page_origin = urlunsplit(
                    (
                        urlsplit(page_url).scheme,
                        urlsplit(page_url).netloc,
                        "",
                        "",
                        "",
                    )
                )
                calibrations = {}
                for item in endpoints.values():
                    if (
                        "javascript" not in item["sources"]
                        or item.get("is_template")
                        or not item.get("url")
                    ):
                        continue
                    endpoint_url = item["url"]
                    try:
                        parsed_endpoint = urlsplit(endpoint_url)
                        endpoint_origin = (
                            normalize_origin(
                                urlunsplit(
                                    (
                                        parsed_endpoint.scheme,
                                        parsed_endpoint.netloc,
                                        "",
                                        "",
                                        "",
                                    )
                                )
                            ).rstrip("/")
                            if parsed_endpoint.scheme and parsed_endpoint.netloc
                            else None
                        )
                    except ValueError:
                        endpoint_origin = None

                    if item.get("relative_to_frontend"):
                        verification_origin = (
                            endpoint_origin
                            if endpoint_origin and endpoint_origin != page_origin
                            else gateway_origin
                        )
                        parsed_path = urlsplit(endpoint_url).path or "/"
                        verification_url = urlunsplit(
                            (
                                urlsplit(verification_origin).scheme,
                                urlsplit(verification_origin).netloc,
                                parsed_path,
                                "",
                                "",
                            )
                        )
                    elif endpoint_origin:
                        verification_origin = endpoint_origin
                        verification_url = endpoint_url
                    else:
                        continue

                    if verification_origin not in calibrations:
                        calibration_url = urljoin(
                            verification_origin,
                            f".microscan-missing-{uuid.uuid4().hex}",
                        )
                        calibration = await limited_fetch(calibration_url)
                        calibrations[verification_origin] = (
                            calibration.signature_for(calibration_url)
                            if calibration.status_code is not None
                            else None
                        )
                    gateway_fallback = calibrations[verification_origin]

                    if not _same_origin(verification_url, verification_origin):
                        item["resolution_status"] = "unresolved"
                        item["verification_status"] = "inconclusive"
                        continue
                    item["resolved_url"] = verification_url
                    item["resolved_origin"] = verification_origin
                    item["resolution_status"] = "resolved"
                    if item["method"] != "GET":
                        continue
                    response = await limited_fetch(verification_url)
                    item["verification_url"] = verification_url
                    item["verification_status"] = (
                        "inconclusive"
                        if response.error or response.redirected
                        else "blocked"
                        if response.status_code in {401, 403}
                        else "not_found"
                        if response.status_code == 404
                        or gateway_fallback is not None
                        and response.signature_for(verification_url) == gateway_fallback
                        else "inconclusive"
                        if response.content_type == "text/html"
                        else "verified"
                        if response.status_code and 200 <= response.status_code < 300
                        else "inconclusive"
                    )
                    item["status_code"] = response.status_code
                    item["content_type"] = response.content_type
                    if response.allow:
                        item["allow"] = response.allow
                    item["size"] = response.size
                    item["content_truncated"] = response.truncated
                    item["response_time_ms"] = round(response.elapsed_ms, 2)
                    if "gateway_verification" not in item["sources"]:
                        item["sources"].append("gateway_verification")

        result = {
            "target": page_url,
            "gateway_target": gateway_origin,
            "page_sources": page_sources,
            "scripts": scripts,
            "results": list(endpoints.values()),
            "summary": {
                "wordlist_paths": len(entries),
                "results": len(endpoints),
                "scripts_analyzed": len(scripts),
                "request_rate_limit": rate,
                "concurrency_limit": concurrency,
                "requests_made": requests_made[0],
                "requests_failed": requests_failed[0],
                "execution_time_limit_seconds": MAX_EXECUTION_SECONDS,
                "execution_time_limited": execution_limited[0],
                "javascript_endpoint_limit": MAX_JS_ENDPOINTS,
            },
        }
        await self._notify(
            progress_callback,
            "File Discovery",
            "completed",
            f"Collected {len(result['results'])} path and endpoint result(s).",
        )
        return result
