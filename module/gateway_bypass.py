import asyncio
import hashlib
import ipaddress
import json
import re
import socket
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import httpx


_STANDARD_PORT_RADIUS = 32
_MAX_STANDARD_PORT_RANGE = 10000
_FULL_PORT_START = 1
_FULL_PORT_END = 65535
_MAX_RESPONSE_BYTES = 64 * 1024
_PORT_PROBE_TIMEOUT = 0.05
_PORT_PROBE_CONCURRENCY = 512
_PORT_PROBE_BATCH_SIZE = 2048
_IDENTIFIER_SEGMENT = re.compile(
    r"(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})",
    re.IGNORECASE,
)
_DYNAMIC_PATH = re.compile(
    r"(?:\$\{[^}]+\}|\{[^/}]+\}|%7B[^/]*%7D|:[A-Za-z_][A-Za-z0-9_]*|\*)",
    re.IGNORECASE,
)
_DENIAL_SIGNAL = re.compile(
    r"\b(unauthori[sz]ed|not authorized|unauthenticated|forbidden|access denied|"
    r"access is denied|permission denied|not allowed|login required|"
    r"authentication required|not authenticated|invalid token|expired token|"
    r"token expired|token required)\b",
    re.IGNORECASE,
)
_SENSITIVE_KEY = re.compile(
    r"(?:authorization|auth(?:entication)?|cookie|session|password|passwd|secret|"
    r"credential|api[_-]?key|token)",
    re.IGNORECASE,
)


class GatewayBypass:
    def __init__(self, transport=None, port_probe=None):
        self._transport = transport
        self._port_probe = port_probe

    @staticmethod
    def _is_loopback(hostname):
        if not hostname:
            return False
        if hostname.lower() == "localhost":
            return True
        try:
            return ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _origin_parts(value):
        candidate = value.strip()
        if "://" not in candidate:
            candidate = f"http://{candidate}"
        try:
            parts = urlsplit(candidate)
            explicit_port = parts.port
        except ValueError:
            return None
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
        ):
            return None
        default_port = 443 if parts.scheme == "https" else 80
        port = explicit_port if explicit_port is not None else default_port
        hostname = parts.hostname.lower()
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        origin = f"{parts.scheme.lower()}://{display_host}:{port}"
        return {
            "identity": (parts.scheme.lower(), hostname, port),
            "origin": origin,
            "hostname": hostname,
            "port": port,
            "scheme": parts.scheme.lower(),
        }

    @classmethod
    def _gateway_origin(cls, target):
        origin = cls._origin_parts(target)
        if origin is None or not cls._is_loopback(origin["hostname"]):
            raise ValueError(
                "Gateway Bypass active checks are limited to loopback gateway targets."
            )
        return origin

    @staticmethod
    def _body_shape(value):
        record = value if isinstance(value, dict) else None
        if isinstance(value, list):
            record = next((item for item in value if isinstance(item, dict)), None)
        if not record:
            return []
        return [
            {
                "field": (
                    "[REDACTED FIELD]"
                    if _SENSITIVE_KEY.search(str(key))
                    else str(key)
                ),
                "type": type(child).__name__,
            }
            for key, child in list(record.items())[:10]
        ]

    @staticmethod
    def _service_probe_plan(endpoints):
        families = {}
        for endpoint in endpoints:
            segments = tuple(
                segment for segment in endpoint["path"].split("/") if segment
            )
            endpoint_key = (endpoint["method"], endpoint["path"], endpoint["query"])
            pattern = tuple(
                "{id}" if _IDENTIFIER_SEGMENT.fullmatch(segment) else segment
                for segment in segments
            )
            families.setdefault(pattern, []).append((endpoint_key, segments))

        identifier_endpoints = set()
        shared_prefixes = {}
        for pattern, family_records in families.items():
            variable_indexes = [
                index
                for index, segment in enumerate(pattern)
                if segment == "{id}"
                and len(
                    {
                        segments[index].lower()
                        for _, segments in family_records
                    }
                )
                > 1
            ]
            if not variable_indexes:
                continue
            for endpoint_key, _ in family_records:
                identifier_endpoints.add(endpoint_key)
            stable_prefix_segments = pattern[: min(variable_indexes)]
            for start in range(len(stable_prefix_segments)):
                for end in range(start + 1, len(stable_prefix_segments) + 1):
                    prefix = "/" + "/".join(stable_prefix_segments[start:end]) + "/"
                    shared_prefixes.setdefault(
                        prefix,
                        {
                            "method": "GET",
                            "path": prefix,
                            "query": "",
                            "query_parameters": [],
                            "source": "repeated_route_prefix",
                        },
                    )

        if shared_prefixes:
            probe_paths = list(shared_prefixes.values())
        else:
            probe_paths = [
                {
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "query": endpoint["query"],
                    "query_parameters": endpoint["query_parameters"],
                    "source": "discovered_endpoint",
                }
                for endpoint in endpoints
            ]
        return probe_paths, identifier_endpoints

    @classmethod
    def _discovery_inventory(cls, gateway_target, discoveries):
        gateway_origins = {}
        endpoints_by_gateway = {}
        skipped_endpoints = []
        target_parts = cls._origin_parts(gateway_target)
        if target_parts:
            gateway_origins[target_parts["identity"]] = target_parts
            endpoints_by_gateway[target_parts["identity"]] = []

        for item in discoveries if isinstance(discoveries, list) else []:
            if not isinstance(item, dict):
                continue
            route_url = (
                item.get("resolved_url")
                or item.get("verification_url")
                or item.get("url")
            )
            route_parts = None
            route_path = "/"
            route_query = ""
            if isinstance(route_url, str):
                try:
                    parsed_route = urlsplit(route_url)
                    route_path = parsed_route.path or "/"
                    route_query = parsed_route.query
                    route_parts = cls._origin_parts(
                        urlunsplit(
                            (
                                parsed_route.scheme,
                                parsed_route.netloc,
                                "",
                                "",
                                "",
                            )
                        )
                    )
                except ValueError:
                    route_parts = None
            if route_parts is None:
                continue

            gateway_origins.setdefault(route_parts["identity"], route_parts)
            endpoints_by_gateway.setdefault(route_parts["identity"], [])

            if not cls._is_loopback(route_parts["hostname"]):
                skipped_endpoints.append(
                    {
                        "method": str(item.get("method") or "UNKNOWN").upper(),
                        "path": route_path,
                        "reason": (
                            "Active Gateway and service checks are limited to "
                            "loopback origins."
                        ),
                    }
                )
                continue

            method = str(item.get("method") or "").upper()
            path = route_path
            if (
                item.get("template")
                or item.get("is_template")
                or item.get("verification_status") == "not_found"
            ):
                skipped_endpoints.append(
                    {
                        "method": method or "UNKNOWN",
                        "path": path,
                        "reason": "Discovery did not verify this endpoint as a found route.",
                    }
                )
                continue
            if (
                method != "GET"
                or not path.startswith("/")
                or path.startswith("//")
                or any(character.isspace() for character in path)
                or "\\" in path
                or _DYNAMIC_PATH.search(path)
            ):
                skipped_endpoints.append(
                    {
                        "method": method or "UNKNOWN",
                        "path": path,
                        "reason": (
                            "Only static discovered GET endpoints can be checked."
                        ),
                    }
                )
                continue
            endpoint = {
                "method": method,
                "path": path,
                "query": route_query,
                "query_parameters": sorted(
                    {
                        key
                        for key, _ in parse_qsl(
                            route_query,
                            keep_blank_values=True,
                        )
                    }
                ),
            }
            identity = (endpoint["method"], endpoint["path"], endpoint["query"])
            endpoints = endpoints_by_gateway[route_parts["identity"]]
            if not any(
                (existing["method"], existing["path"], existing["query"]) == identity
                for existing in endpoints
            ):
                endpoints.append(endpoint)

        return gateway_origins, endpoints_by_gateway, skipped_endpoints

    @staticmethod
    def _candidate_port_range(scan_mode, gateway_port, port_start, port_end):
        if scan_mode not in {"standard", "full"}:
            raise ValueError("scan_mode must be either 'standard' or 'full'.")
        if scan_mode == "full":
            return range(_FULL_PORT_START, _FULL_PORT_END + 1)

        if port_start is None and port_end is None:
            return range(
                max(1, gateway_port - _STANDARD_PORT_RADIUS),
                min(65535, gateway_port + _STANDARD_PORT_RADIUS) + 1,
            )
        if port_start is None or port_end is None:
            raise ValueError(
                "Both Gateway Bypass Standard Scan port range bounds are required."
            )

        normalized = []
        for value in (port_start, port_end):
            try:
                port = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "Gateway Bypass port range must use integer bounds."
                ) from exc
            if not 1 <= port <= 65535:
                raise ValueError(
                    "Gateway Bypass port bounds must be between 1 and 65535."
                )
            normalized.append(port)
        if normalized[0] > normalized[1]:
            raise ValueError("Gateway Bypass port range start must not exceed its end.")
        if normalized[1] - normalized[0] + 1 > _MAX_STANDARD_PORT_RANGE:
            raise ValueError(
                f"Standard Scan port ranges are limited to {_MAX_STANDARD_PORT_RANGE} ports."
            )
        return range(normalized[0], normalized[1] + 1)

    async def _port_is_open(self, hostname, port, semaphore, addresses=None):
        async with semaphore:
            if self._port_probe is not None:
                result = self._port_probe(hostname, port)
                if hasattr(result, "__await__"):
                    result = await result
                return bool(result)
            loop = asyncio.get_running_loop()
            for family, socktype, protocol, address in addresses:
                address = list(address)
                address[1] = port
                probe_socket = socket.socket(family, socktype, protocol)
                probe_socket.setblocking(False)
                try:
                    await asyncio.wait_for(
                        loop.sock_connect(probe_socket, tuple(address)),
                        timeout=_PORT_PROBE_TIMEOUT,
                    )
                    return True
                except (OSError, asyncio.TimeoutError):
                    continue
                finally:
                    probe_socket.close()
            return False

    async def _open_ports(self, hostname, ports, progress_callback=None):
        semaphore = asyncio.Semaphore(_PORT_PROBE_CONCURRENCY)
        addresses = None
        if self._port_probe is None:
            address_info = await asyncio.get_running_loop().getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )
            addresses = list(
                dict.fromkeys(
                    (family, socktype, protocol, address)
                    for family, socktype, protocol, _, address in address_info
                )
            )
        open_ports = []
        for offset in range(0, len(ports), _PORT_PROBE_BATCH_SIZE):
            batch = ports[offset : offset + _PORT_PROBE_BATCH_SIZE]
            results = await asyncio.gather(
                *(
                    self._port_is_open(hostname, port, semaphore, addresses)
                    for port in batch
                )
            )
            open_ports.extend(
                port for port, is_open in zip(batch, results) if is_open
            )
            if progress_callback:
                await progress_callback(hostname, offset + len(batch), len(ports))
        return open_ports

    @staticmethod
    def _url(origin, endpoint):
        host = f"[{origin['hostname']}]" if ":" in origin["hostname"] else origin["hostname"]
        return urlunsplit(
            (
                origin["scheme"],
                f"{host}:{origin['port']}",
                endpoint["path"],
                endpoint["query"],
                "",
            )
        )

    @staticmethod
    async def _read_limited(response):
        chunks = []
        size = 0
        truncated = False
        async for chunk in response.aiter_bytes():
            remaining = _MAX_RESPONSE_BYTES - size
            if remaining <= 0:
                truncated = True
                break
            chunks.append(chunk[:remaining])
            size += min(len(chunk), remaining)
            if len(chunk) > remaining:
                truncated = True
                break
        return b"".join(chunks), truncated

    async def _request(self, client, semaphore, url):
        async with semaphore:
            try:
                async with client.stream(
                    "GET",
                    url,
                    headers={"Accept": "application/json"},
                ) as response:
                    body, truncated = await self._read_limited(response)
                    content_type = (
                        response.headers.get("content-type", "")
                        .split(";", 1)[0]
                        .strip()
                        .lower()
                    )
                    body_text = body.decode("utf-8", errors="replace")
                    parsed_body = None
                    try:
                        parsed_body = json.loads(body_text) if body_text else None
                    except (json.JSONDecodeError, RecursionError):
                        pass
                    structured = isinstance(parsed_body, (dict, list))
                    denial_signal = bool(_DENIAL_SIGNAL.search(body_text))
                    return {
                        "status_code": response.status_code,
                        "headers": {
                            "content_type": content_type or None,
                            "allow": response.headers.get("allow"),
                            "www_authenticate_present": "www-authenticate"
                            in response.headers,
                            "cache_control": response.headers.get("cache-control"),
                            "vary": response.headers.get("vary"),
                            "x_content_type_options": response.headers.get(
                                "x-content-type-options"
                            ),
                            "x_frame_options": response.headers.get("x-frame-options"),
                        },
                        "body": {
                            "bytes_captured": len(body),
                            "truncated": truncated,
                            "sha256": hashlib.sha256(body).hexdigest(),
                            "format": (
                                "json"
                                if structured
                                else "xml"
                                if content_type.endswith("/xml")
                                or content_type.endswith("+xml")
                                else "other"
                            ),
                            "nonempty_structured_data": bool(parsed_body)
                            if structured
                            else False,
                            "shape": self._body_shape(parsed_body) if structured else [],
                        },
                        "api_response": (
                            "json" in content_type
                            or content_type.endswith("/xml")
                            or content_type.endswith("+xml")
                            or structured
                        ),
                        "access_denied": response.status_code in {401, 403}
                        or denial_signal,
                        "error": None,
                    }
            except httpx.TimeoutException:
                return {"error": "Request timed out."}
            except httpx.RequestError:
                return {"error": "HTTP request failed."}

    @staticmethod
    def _classify(gateway_response, direct_response):
        if not gateway_response or gateway_response.get("error"):
            return "inconclusive", "Gateway response was unavailable."
        if not direct_response or direct_response.get("error"):
            return "inconclusive", "Direct service response was unavailable."
        if not direct_response.get("api_response"):
            return (
                "inconclusive",
                "The direct response did not identify an HTTP/API service.",
            )
        if gateway_response.get("access_denied") and direct_response.get(
            "access_denied"
        ):
            return "protected", "The direct service also enforced an access-denial response."
        if (
            gateway_response.get("access_denied")
            and 200 <= direct_response.get("status_code", 0) < 300
            and direct_response["body"].get("nonempty_structured_data")
            and not direct_response["body"].get("truncated")
            and not direct_response.get("access_denied")
        ):
            return (
                "confirmed",
                "The Gateway denied the anonymous request while the direct service returned non-empty structured data.",
            )
        if (
            gateway_response.get("access_denied")
            and 200 <= direct_response.get("status_code", 0) < 300
        ):
            return (
                "potential",
                "The Gateway denied the anonymous request while the direct service returned a successful API response; authorization impact needs review.",
            )
        if direct_response.get("access_denied"):
            return "protected", "The direct service enforced an access-denial response."
        return (
            "inconclusive",
            "The observed responses did not establish a Gateway-only access control.",
        )

    @staticmethod
    def _compare_responses(gateway_response, direct_response):
        if (
            not gateway_response
            or gateway_response.get("error")
            or not direct_response
            or direct_response.get("error")
        ):
            return {"available": False}
        gateway_headers = gateway_response.get("headers", {})
        direct_headers = direct_response.get("headers", {})
        gateway_body = gateway_response.get("body", {})
        direct_body = direct_response.get("body", {})
        return {
            "available": True,
            "status_changed": gateway_response.get("status_code")
            != direct_response.get("status_code"),
            "content_type_changed": gateway_headers.get("content_type")
            != direct_headers.get("content_type"),
            "selected_headers_changed": any(
                gateway_headers.get(key) != direct_headers.get(key)
                for key in (
                    "allow",
                    "www_authenticate_present",
                    "cache_control",
                    "vary",
                    "x_content_type_options",
                    "x_frame_options",
                )
            ),
            "body_changed": gateway_body.get("sha256") != direct_body.get("sha256"),
        }

    async def analyze(
        self,
        gateway_target,
        discoveries,
        scan_mode="standard",
        port_start=None,
        port_end=None,
        progress_callback=None,
    ):
        try:
            gateway_origin = self._gateway_origin(gateway_target)
        except ValueError as exc:
            return {
                "status": "skipped",
                "reason": str(exc),
                "gateway_origins": [],
                "excluded_service_origins": [],
                "services": [],
                "skipped_endpoints": [],
            }

        gateway_origins, endpoints_by_gateway, skipped_endpoints = (
            self._discovery_inventory(
                gateway_target,
                discoveries,
            )
        )
        candidate_port_range = self._candidate_port_range(
            scan_mode,
            gateway_origin["port"],
            port_start,
            port_end,
        )
        discovered_gateway_origins = sorted(
            (
                {
                    "origin": gateway["origin"],
                    "port": gateway["port"],
                    "host": gateway["hostname"],
                }
                for gateway in gateway_origins.values()
            ),
            key=lambda item: (item["host"], item["port"], item["origin"]),
        )
        excluded_service_origins = []
        loopback_gateways = [
            gateway
            for gateway in gateway_origins.values()
            if self._is_loopback(gateway["hostname"])
        ]
        if not loopback_gateways:
            return {
                "status": "inconclusive",
                "reason": "Discovery did not provide loopback Gateway origins to compare.",
                "scan_mode": scan_mode,
                "port_range": {
                    "start": candidate_port_range.start,
                    "end": candidate_port_range.stop - 1,
                },
                "gateway_origins": discovered_gateway_origins,
                "excluded_service_origins": [],
                "services": [],
                "skipped_endpoints": skipped_endpoints,
            }

        endpoint_groups = {}
        for gateway in loopback_gateways:
            gateway_endpoints = endpoints_by_gateway.get(gateway["identity"], [])
            if not gateway_endpoints:
                continue
            probe_paths, identifier_endpoints = self._service_probe_plan(
                gateway_endpoints
            )
            comparison_endpoints = [
                endpoint
                for endpoint in gateway_endpoints
                if scan_mode == "full"
                or (
                    endpoint["method"],
                    endpoint["path"],
                    endpoint["query"],
                )
                not in identifier_endpoints
            ]
            if scan_mode == "standard":
                skipped_endpoints.extend(
                    {
                        "method": endpoint["method"],
                        "path": endpoint["path"],
                        "reason": (
                            "Standard Scan omits repeated resource-ID variants; "
                            "Full Scan includes them."
                        ),
                    }
                    for endpoint in gateway_endpoints
                    if (
                        endpoint["method"],
                        endpoint["path"],
                        endpoint["query"],
                    )
                    in identifier_endpoints
                )
            host_identity = (gateway["scheme"], gateway["hostname"])
            group = endpoint_groups.setdefault(
                host_identity,
                {
                    "hostname": gateway["hostname"],
                    "scheme": gateway["scheme"],
                    "endpoints": [],
                    "probe_paths": [],
                },
            )
            for probe_path in probe_paths:
                probe_identity = (
                    probe_path["method"],
                    probe_path["path"],
                    probe_path["query"],
                )
                if not any(
                    (
                        existing["method"],
                        existing["path"],
                        existing["query"],
                    )
                    == probe_identity
                    for existing in group["probe_paths"]
                ):
                    group["probe_paths"].append(probe_path)
            for endpoint in comparison_endpoints:
                endpoint_with_gateway = {**endpoint, "gateway": gateway}
                endpoint_identity = (
                    gateway["identity"],
                    endpoint["method"],
                    endpoint["path"],
                    endpoint["query"],
                )
                if not any(
                    (
                        existing["gateway"]["identity"],
                        existing["method"],
                        existing["path"],
                        existing["query"],
                    )
                    == endpoint_identity
                    for existing in group["endpoints"]
                ):
                    group["endpoints"].append(endpoint_with_gateway)

        if not endpoint_groups:
            return {
                "status": "inconclusive",
                "reason": "No eligible static GET endpoints were found in Discovery.",
                "scan_mode": scan_mode,
                "port_range": {
                    "start": candidate_port_range.start,
                    "end": candidate_port_range.stop - 1,
                },
                "gateway_origins": discovered_gateway_origins,
                "excluded_service_origins": [],
                "services": [],
                "skipped_endpoints": skipped_endpoints,
            }

        candidate_services = {}
        excluded_port_set = {
            gateway["port"] for gateway in loopback_gateways
        }
        ports_to_probe = [
            port for port in candidate_port_range if port not in excluded_port_set
        ]
        ports_scanned = 0

        async def report_port_progress(hostname, scanned, total):
            if progress_callback:
                await progress_callback(
                    {
                        "stage": "Gateway Bypass",
                        "status": "running",
                        "detail": (
                            f"Scanned {scanned} of {total} non-Gateway ports on "
                            f"{hostname}."
                        ),
                    }
                )

        unresolved_hosts = []
        for group in endpoint_groups.values():
            hostname = group["hostname"]
            scheme = group["scheme"]
            service_host = f"[{hostname}]" if ":" in hostname else hostname
            for gateway_port in sorted(excluded_port_set):
                if gateway_port in candidate_port_range:
                    excluded_service_origins.append(
                        {
                            "origin": f"{scheme}://{service_host}:{gateway_port}",
                            "port": gateway_port,
                            "reason": (
                                "The port appears in the input URL or a discovered "
                                "Gateway origin and is excluded from service candidates."
                            ),
                        }
                    )
            try:
                open_ports = await self._open_ports(
                    hostname,
                    ports_to_probe,
                    report_port_progress,
                )
            except socket.gaierror:
                unresolved_hosts.append(hostname)
                skipped_endpoints.extend(
                    {
                        "method": endpoint["method"],
                        "path": endpoint["path"],
                        "reason": (
                            "The loopback hostname could not be resolved; its ports "
                            "were not checked."
                        ),
                    }
                    for endpoint in group["endpoints"]
                )
                continue
            ports_scanned += len(ports_to_probe)
            for port in open_ports:
                service_identity = (scheme, hostname, port)
                service_origin = f"{scheme}://{service_host}:{port}"
                service = candidate_services.setdefault(
                    service_identity,
                    {
                        "origin": service_origin,
                        "port": port,
                        "hostname": hostname,
                        "scheme": scheme,
                        "endpoints": [],
                        "probe_paths": [],
                    },
                )
                service["endpoints"].extend(group["endpoints"])
                existing_probe_paths = {
                    (item["method"], item["path"], item["query"])
                    for item in service["probe_paths"]
                }
                service["probe_paths"].extend(
                    item
                    for item in group["probe_paths"]
                    if (item["method"], item["path"], item["query"])
                    not in existing_probe_paths
                )

        if not candidate_services:
            return {
                "status": "inconclusive",
                "reason": (
                    (
                        "Could not resolve loopback host(s): "
                        + ", ".join(sorted(set(unresolved_hosts)))
                        + "; their ports were not checked."
                    )
                    if unresolved_hosts
                    else "No HTTP-listening ports were found in the selected loopback port range after excluding Gateway ports."
                ),
                "scan_mode": scan_mode,
                "port_range": {
                    "start": candidate_port_range.start,
                    "end": candidate_port_range.stop - 1,
                },
                "ports_scanned": ports_scanned,
                "gateway_origins": discovered_gateway_origins,
                "excluded_service_origins": excluded_service_origins,
                "services": [],
                "skipped_endpoints": skipped_endpoints,
            }

        semaphore = asyncio.Semaphore(2)
        client_options = {
            "timeout": 3.0,
            "follow_redirects": False,
            "trust_env": False,
            "limits": httpx.Limits(max_connections=2, max_keepalive_connections=2),
        }
        if self._transport is not None:
            client_options["transport"] = self._transport

        services = []
        async with httpx.AsyncClient(**client_options) as client:
            for service in candidate_services.values():
                endpoint_results = []
                verified = False
                verification_evidence = None
                for probe_path in service["probe_paths"]:
                    direct_response = await self._request(
                        client,
                        semaphore,
                        self._url(service, probe_path),
                    )
                    if direct_response.get("api_response"):
                        verified = True
                        verification_evidence = {
                            "method": probe_path["method"],
                            "path": probe_path["path"],
                            "source": probe_path["source"],
                            "status_code": direct_response.get("status_code"),
                            "content_type": direct_response.get("headers", {}).get(
                                "content_type"
                            ),
                        }
                        break
                if not verified:
                    excluded_service_origins.append(
                        {
                            "origin": service["origin"],
                            "port": service["port"],
                            "reason": (
                                "This candidate port did not return an HTTP/API "
                                "response for the discovered endpoints or their "
                                "repeated route prefixes."
                            ),
                        }
                    )
                    continue

                for endpoint in service["endpoints"]:
                    gateway_response = await self._request(
                        client,
                        semaphore,
                        self._url(endpoint["gateway"], endpoint),
                    )
                    direct_response = await self._request(
                        client,
                        semaphore,
                        self._url(service, endpoint),
                    )
                    if direct_response.get("api_response"):
                        verified = True
                    status, reason = self._classify(
                        gateway_response,
                        direct_response,
                    )
                    endpoint_results.append(
                        {
                            "method": endpoint["method"],
                            "path": endpoint["path"],
                            "query_parameters": endpoint["query_parameters"],
                            "status": status,
                            "reason": reason,
                            "comparison": self._compare_responses(
                                gateway_response,
                                direct_response,
                            ),
                            "gateway": {
                                "request": {
                                    "method": "GET",
                                    "url": self._url(endpoint["gateway"], endpoint)
                                    .split("?", 1)[0],
                                    "headers": {"Accept": "application/json"},
                                    "query_values_redacted": bool(endpoint["query"]),
                                },
                                "response": gateway_response,
                            },
                            "direct": {
                                "request": {
                                    "method": "GET",
                                    "url": self._url(service, endpoint).split("?", 1)[0],
                                    "headers": {"Accept": "application/json"},
                                    "query_values_redacted": bool(endpoint["query"]),
                                },
                                "response": direct_response,
                            },
                        }
                    )
                services.append(
                    {
                        "origin": service["origin"],
                        "port": service["port"],
                        "verification_status": "verified",
                        "verification_evidence": verification_evidence,
                        "endpoints": endpoint_results,
                    }
                )

        endpoint_comparison_count = sum(
            len(service["endpoints"]) for service in services
        )
        return {
            "status": (
                "completed"
                if endpoint_comparison_count
                else "inconclusive"
            ),
            "reason": (
                None
                if endpoint_comparison_count
                else (
                    "A service origin was verified, but no eligible discovered "
                    "endpoints remained for Gateway/direct comparison."
                    if services
                    else "No non-Gateway port returned an HTTP/API response for the "
                    "discovered endpoints or their repeated route prefixes."
                )
            ),
            "scan_mode": scan_mode,
            "port_range": {
                "start": candidate_port_range.start,
                "end": candidate_port_range.stop - 1,
            },
            "ports_scanned": ports_scanned,
            "open_ports_found": len(candidate_services),
            "gateway_origins": discovered_gateway_origins,
            "excluded_service_origins": excluded_service_origins,
            "services": services,
            "skipped_endpoints": skipped_endpoints,
        }
