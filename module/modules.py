import ipaddress
import os
import re
from urllib.parse import urlsplit

from module.authentication_test import AuthenticationTest
from module.bola_analysis import BolaAnalyzer
from module.endpoint_selection import EndpointSelector
from module.rate_limit_test import RateLimitTest
from module.signin import LoginConfigurationError, Signin


_UNSELECTED = object()
_READ_ONLY_METHODS = {"GET"}
_MAX_AUTOMATIC_JWT_ENDPOINTS = 5
_MAX_AUTOMATIC_BOLA_ENDPOINTS = 5
_MAX_CONFIGURED_JWT_ENDPOINTS = 100
_MAX_AUTOMATIC_RATE_LIMIT_ENDPOINTS = 5
_DEFAULT_ACTIVE_BOLA_REQUEST_BUDGET = 10
_DYNAMIC_PATH_SEGMENT = re.compile(
    r"(?:\$\{[^}]+\}|\{[^}]+\}|:[A-Za-z_][A-Za-z0-9_]*|\*)"
)


class Modules:
    TEST_MODULE = EndpointSelector.TEST_MODULE

    def __init__(
        self,
        endpoint_selector=None,
        authentication_test=None,
        rate_limit_test=None,
    ):
        self.endpoint_selector = endpoint_selector or EndpointSelector()
        self.authentication_test = authentication_test or AuthenticationTest(
            self.endpoint_selector
        )
        self.rate_limit_test = rate_limit_test or RateLimitTest()

    def classify_endpoint(self, endpoint):
        return self.endpoint_selector.classify_endpoint(endpoint)

    def select_authentication_candidate(self, discovered_endpoints):
        return self.endpoint_selector.select_authentication_candidate(
            discovered_endpoints
        )

    @staticmethod
    def _endpoint_allowlist():
        # Endpoint selection now comes exclusively from the scoped Discovery inventory.
        # Keeping this compatibility method prevents callers from needing to change.
        return []

    @staticmethod
    def _is_local_target(target):
        try:
            hostname = urlsplit(Signin.normalize_target(target)).hostname
            if hostname is None:
                return False
            if hostname.lower() == "localhost":
                return True
            return ipaddress.ip_address(hostname).is_loopback
        except (LoginConfigurationError, ValueError):
            return False

    @staticmethod
    def _discovered_path(endpoint, target):
        raw_path = endpoint.get("path") or endpoint.get("target")
        if not isinstance(raw_path, str) or not raw_path.strip():
            return None, "Discovery did not provide an endpoint path."

        raw_path = raw_path.strip()
        try:
            parsed = urlsplit(raw_path)
        except ValueError:
            return None, "Discovered endpoint path is invalid."
        if parsed.scheme or parsed.netloc:
            if parsed.query or parsed.fragment:
                return None, "Discovered endpoint URL contains query or fragment data."
            try:
                discovered_origin = Signin.normalize_target(
                    f"{parsed.scheme}://{parsed.netloc}"
                )
                if discovered_origin != Signin.normalize_target(target):
                    return None, "Discovered endpoint URL is outside the configured target origin."
            except LoginConfigurationError:
                return None, "Discovered endpoint URL is invalid."
            raw_path = parsed.path or "/"
            parsed = urlsplit(raw_path)
        if parsed.query or parsed.fragment:
            return None, "Discovered endpoint path contains query or fragment data."
        if not raw_path.startswith("/"):
            raw_path = f"/{raw_path}"
        return raw_path, None

    def _automatic_candidate_reason(self, endpoint):
        method = str(endpoint.get("method") or "").upper()
        path = endpoint.get("path") or ""
        if method != "GET":
            return None
        segments = [
            segment.lower()
            for segment in path.strip("/").split("/")
            if segment
        ]
        if self.endpoint_selector.is_authentication_path(path):
            return None
        if any(
            segment in {"debug", "health", "metrics", "status"}
            for segment in segments
        ):
            return None

        if not segments:
            return None
        protected_terms = {
            "account",
            "admin",
            "billing",
            "customer",
            "data",
            "inventory",
            "invoice",
            "item",
            "member",
            "order",
            "payment",
            "product",
            "profile",
            "project",
            "record",
            "tenant",
            "user",
        }
        path_tokens = {
            token
            for segment in segments
            for token in re.split(r"[-_]", segment)
        }
        protected_resource = any(
            token in protected_terms
            or (token.endswith("s") and token[:-1] in protected_terms)
            for token in path_tokens
        )
        classification = endpoint.get("classification") or self.endpoint_selector.classify_endpoint(
            endpoint
        )["classification"]
        protected_resource = protected_resource or classification in {
            "administrative",
            "resource_by_id",
            "resource_collection",
            "user_or_account",
        }
        if not protected_resource:
            return None

        status = self.endpoint_selector.discovery_status(endpoint)
        if status == 200:
            return (
                "Discovery observed HTTP 200 for a protected-resource candidate; "
                "selected for an independent JWT check, not treated as a finding."
            )
        if status in {401, 403}:
            return (
                f"Discovery observed HTTP {status} for a protected-resource candidate; "
                "selected for an independent JWT check."
            )
        return (
            "Discovery path/type indicates a protected-resource candidate; "
            "Discovery status is only a selection signal."
        )

    @staticmethod
    def _automatic_endpoint_budget():
        raw = os.environ.get("MICROSCAN_JWT_ENDPOINT_BUDGET", "").strip()
        if not raw:
            return _MAX_AUTOMATIC_JWT_ENDPOINTS
        try:
            budget = int(raw)
        except ValueError as exc:
            raise ValueError(
                "MICROSCAN_JWT_ENDPOINT_BUDGET must be an integer between 1 and 100."
            ) from exc
        if not 1 <= budget <= _MAX_CONFIGURED_JWT_ENDPOINTS:
            raise ValueError(
                "MICROSCAN_JWT_ENDPOINT_BUDGET must be an integer between 1 and 100."
            )
        return budget

    @staticmethod
    def _active_bola_request_budget():
        raw = os.environ.get("MICROSCAN_BOLA_REQUEST_BUDGET", "").strip()
        if not raw:
            return _DEFAULT_ACTIVE_BOLA_REQUEST_BUDGET
        try:
            budget = int(raw)
        except ValueError as exc:
            raise ValueError(
                "MICROSCAN_BOLA_REQUEST_BUDGET must be an integer between 1 and 100."
            ) from exc
        if not 1 <= budget <= _MAX_CONFIGURED_JWT_ENDPOINTS:
            raise ValueError(
                "MICROSCAN_BOLA_REQUEST_BUDGET must be an integer between 1 and 100."
            )
        return budget

    def _active_bola_route_templates(self, target, endpoints, discovered_templates):
        routes = {}

        def add_template(method, raw_template, observed_identifier=None):
            if str(method or "").upper() != "GET" or not isinstance(raw_template, str):
                return
            template_path, path_error = self._discovered_path(
                {"path": raw_template}, target
            )
            if path_error or not template_path:
                return
            segments = template_path.strip("/").split("/")
            if not segments or not re.fullmatch(
                r"(?:\$\{[^}]+\}|\{[^}]+\}|:[A-Za-z_][A-Za-z0-9_]*|\*)",
                segments[-1],
            ):
                return
            if any(
                re.search(r"\$\{|\{|\}|:", segment)
                for segment in segments[:-1]
            ):
                return
            collection_path = "/" + "/".join(segments[:-1])
            if collection_path == "/":
                return
            resource_type = BolaAnalyzer._type_name(segments[-2])
            if resource_type not in BolaAnalyzer.COLLECTION_TYPES:
                return
            key = (collection_path, template_path)
            route = routes.setdefault(
                key,
                {
                    "collection_path": collection_path,
                    "template": template_path,
                    "placeholder": segments[-1],
                    "resource_type": resource_type,
                    "observed_identifiers": [],
                },
            )
            if (
                isinstance(observed_identifier, str)
                and observed_identifier not in route["observed_identifiers"]
            ):
                route["observed_identifiers"].append(observed_identifier)

        for item in discovered_templates or []:
            if not isinstance(item, dict):
                continue
            add_template(
                item.get("method"),
                item.get("template") or item.get("path"),
            )
        for endpoint in endpoints:
            if str(endpoint.get("method") or "").upper() != "GET":
                continue
            route = BolaAnalyzer._resource_route(endpoint)
            if (
                route
                and not route["is_collection"]
                and route["requested_id"] is not None
                and route["resource_type"] in BolaAnalyzer.COLLECTION_TYPES
            ):
                add_template(
                    "GET",
                    f"{route['collection_path']}/{{id}}",
                    observed_identifier=route["requested_id"],
                )
        return list(routes.values())

    @staticmethod
    def _automatic_route_group(path):
        segments = path.split("/")
        grouped_segments = []
        resource_segments = EndpointSelector.RESOURCE_COLLECTIONS | {
            "admin",
            "billing",
            "customer",
            "customers",
            "inventory",
            "inventories",
            "invoice",
            "invoices",
            "member",
            "members",
            "payment",
            "payments",
            "profile",
            "record",
            "records",
            "tenant",
            "tenants",
        }
        for index, segment in enumerate(segments):
            previous_segment = segments[index - 1].lower() if index else ""
            is_resource_identifier = previous_segment in resource_segments
            if (
                is_resource_identifier
                and (
                    segment.isdigit()
                    or re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12}",
                        segment,
                        re.IGNORECASE,
                    )
                    or re.fullmatch(r"\{[^/]+\}", segment)
                )
            ):
                grouped_segments.append("{id}")
            else:
                grouped_segments.append(segment)

        grouped_path = "/".join(grouped_segments)
        if path.endswith("/") and not grouped_path.endswith("/"):
            grouped_path += "/"
        return grouped_path

    def _rate_limit_candidates(self, endpoints):
        unsuitable_segments = (
            self.endpoint_selector.UNSUITABLE_PATH_SEGMENTS
            | self.endpoint_selector.SENSITIVE_PATH_SEGMENTS
            | self.endpoint_selector.REGISTRATION_PATH_SEGMENTS
            | self.endpoint_selector.NON_LOGIN_AUTH_PATH_SEGMENTS
        )
        supported_classifications = {
            "authentication",
            "resource_collection",
            "resource_by_id",
            "user_or_account",
        }
        candidates = []
        for discovery_index, endpoint in enumerate(endpoints):
            if endpoint.get("discovery_source") != "discovery":
                continue
            identity = (
                str(endpoint.get("method") or "").upper(),
                endpoint.get("path"),
            )
            if identity[0] != "GET" or endpoint.get("jwt_path_error"):
                continue
            path = identity[1]
            if not isinstance(path, str):
                continue
            segments = self.endpoint_selector._path_segments(path)
            if not segments or any(
                segment in unsuitable_segments for segment in segments
            ):
                continue
            if _DYNAMIC_PATH_SEGMENT.search(path):
                continue
            classification = self.endpoint_selector.classify_endpoint(endpoint)[
                "classification"
            ]
            if classification in supported_classifications:
                candidates.append(
                    (discovery_index, endpoint, identity, classification)
                )
        return candidates

    @staticmethod
    def _automatic_endpoint_priority(endpoint, discovery_index):
        status = EndpointSelector.discovery_status(endpoint)
        path = str(endpoint.get("path") or "").lower()
        tokens = set(re.split(r"[-_/]+", path))
        protected_probe = (
            bool(tokens & {"order", "orders"}) and "check" in tokens
        ) or ("admin" in tokens and "dashboard" in tokens)
        administrative = bool(tokens & {"admin", "administrator"})
        return (
            0 if protected_probe else 1 if administrative else 2,
            0 if status == 200 else 1 if status in {401, 403} else 2,
            0 if not re.search(r"/\{[^/]+\}", path) else 1,
            discovery_index,
        )

    def evaluate_authentication_test(
        self,
        target,
        discovered_endpoints=None,
        selected_candidate=_UNSELECTED,
    ):
        if selected_candidate is _UNSELECTED:
            selected_candidate = self.select_authentication_candidate(
                discovered_endpoints or []
            )
        return self.authentication_test.evaluate(
            target,
            selected_candidate,
            discovered_endpoints,
        )

    def analyze_endpoints(
        self,
        target,
        results,
        auto_jwt_local_lab=False,
        discovered_inventory=None,
        discovered_route_templates=None,
        scan_mode="standard",
        progress_callback=None,
        cancellation_event=None,
        rate_limit_testing=False,
        jwt_testing=True,
        bola_testing=True,
    ):
        if scan_mode not in {"standard", "full"}:
            raise ValueError("scan_mode must be either 'standard' or 'full'.")

        analyzed = []
        seen = set()
        for endpoint in results:
            if not isinstance(endpoint, dict):
                continue
            method = str(endpoint.get("method") or "").upper()
            path, path_error = self._discovered_path(endpoint, target)
            if path is None:
                path = endpoint.get("path") or endpoint.get("target") or "/"
            elif _DYNAMIC_PATH_SEGMENT.search(path):
                path_error = "Discovered endpoint path is an unresolved dynamic template."
                if not isinstance(path, str):
                    path = "/"
            identity = (method, path)
            if identity in seen:
                continue
            seen.add(identity)
            endpoint["method"] = method or None
            endpoint["path"] = path
            endpoint["jwt_path_error"] = path_error
            endpoint["discovery_source"] = "discovery"
            endpoint["discovered"] = True
            classification = self.endpoint_selector.classify_endpoint(endpoint)
            endpoint.update(
                {
                    "classification": classification["classification"],
                    "classification_reason": classification["reason"],
                    "applicable_tests": classification["applicable_tests"],
                    "test_results": [],
                }
            )
            analyzed.append(endpoint)

        authentication_inventory = (
            discovered_inventory
            if discovered_inventory is not None
            else analyzed
        )
        endpoints_by_identity = {
            (endpoint.get("method") or "", endpoint.get("path")): endpoint
            for endpoint in analyzed
        }
        active_bola_enabled = bool(
            bola_testing
            and auto_jwt_local_lab
            and self._is_local_target(target)
        )
        active_bola_budget = (
            {
                "configured": self._active_bola_request_budget(),
                "used": 0,
            }
            if active_bola_enabled
            else None
        )
        active_bola_route_templates = (
            self._active_bola_route_templates(
                target,
                analyzed,
                discovered_route_templates,
            )
            if active_bola_enabled
            else []
        )
        auto_mode_reason = None
        selected_reasons = {}
        eligible_identities = set()
        automatic_skip_reasons = {}
        selection_budget = {
            "mode": None,
            "configured": None,
            "used": None,
            "remaining": None,
        }
        if not jwt_testing:
            selection_mode = "not_selected"
            selection_budget["mode"] = selection_mode
            auto_mode_reason = "JWT authentication was not selected for this scan."
        elif jwt_testing:
            selection_mode = "automatic_local_lab"
            selection_budget["mode"] = selection_mode
            candidates_by_group = {}
            for discovery_index, endpoint in enumerate(analyzed):
                if endpoint.get("discovery_source") != "discovery":
                    continue
                identity = (endpoint.get("method") or "", endpoint.get("path"))
                if endpoint.get("jwt_path_error"):
                    continue
                reason = self._automatic_candidate_reason(endpoint)
                if reason:
                    eligible_identities.add(identity)
                    group = (identity[0], self._automatic_route_group(identity[1]))
                    candidates_by_group.setdefault(group, []).append(
                        (discovery_index, endpoint, identity, reason)
                    )

            representatives = []
            for group, candidates in candidates_by_group.items():
                representative = min(
                    candidates,
                    key=lambda candidate: self._automatic_endpoint_priority(
                        candidate[1], candidate[0]
                    ),
                )
                representatives.append((group, representative))

            endpoint_budget = (
                None
                if scan_mode == "full"
                else self._automatic_endpoint_budget()
            )
            ordered_representatives = sorted(
                    representatives,
                    key=lambda item: self._automatic_endpoint_priority(
                        item[1][1], item[1][0]
                    ),
                )
            selected_groups = {
                group
                for group, _ in (
                    ordered_representatives
                    if endpoint_budget is None
                    else ordered_representatives[:endpoint_budget]
                )
            }
            selection_budget.update(
                {
                    "configured": endpoint_budget,
                    "used": len(selected_groups),
                    "remaining": (
                        None
                        if endpoint_budget is None
                        else max(endpoint_budget - len(selected_groups), 0)
                    ),
                }
            )
            representative_by_group = {
                group: candidate for group, candidate in representatives
            }
            for group, candidates in candidates_by_group.items():
                representative = representative_by_group[group]
                representative_identity = representative[2]
                if group in selected_groups:
                    if scan_mode == "full":
                        for _, _, identity, reason in candidates:
                            selected_reasons[identity] = reason
                    else:
                        selected_reasons[representative_identity] = representative[3]
                        for _, _, identity, _ in candidates:
                            if identity != representative_identity:
                                automatic_skip_reasons[identity] = (
                                    f"Grouped with representative GET {representative_identity[1]} "
                                    "because it has the same route shape; this endpoint was not "
                                    "tested and its result is not inferred."
                                )
                else:
                    for _, _, identity, _ in candidates:
                        automatic_skip_reasons[identity] = (
                            f"Automatic selection is limited to "
                            f"{endpoint_budget} endpoint groups per scan; "
                            "higher-priority candidates were selected first."
                        )
        else:
            selection_mode = "not_confirmed"
            selection_budget["mode"] = selection_mode
            auto_mode_reason = (
                "Automatic JWT selection is disabled for this scan; enable the JWT "
                "authentication module to select eligible discovered GET endpoints."
            )

        rate_limit_candidates = self._rate_limit_candidates(analyzed)
        bola_candidates = []
        for discovery_index, endpoint in enumerate(analyzed):
            if (
                endpoint.get("discovery_source") != "discovery"
                or str(endpoint.get("method") or "").upper() != "GET"
                or endpoint.get("jwt_path_error")
            ):
                continue
            resource_route = BolaAnalyzer._resource_route(endpoint)
            if (
                resource_route
                and resource_route["resource_type"] in BolaAnalyzer.COLLECTION_TYPES
            ):
                bola_candidates.append((discovery_index, endpoint, resource_route))
        ordered_bola_candidates = sorted(
            bola_candidates,
            key=lambda candidate: (
                0 if candidate[2]["is_collection"] else 1,
                candidate[0],
            ),
        )
        bola_limit = (
            None
            if scan_mode == "full"
            else _MAX_AUTOMATIC_BOLA_ENDPOINTS
        )
        selected_bola_groups = set()
        selected_bola_endpoints = set()
        for _, endpoint, _ in ordered_bola_candidates:
            identity = (
                str(endpoint.get("method") or "").upper(),
                endpoint.get("path"),
            )
            group = (identity[0], self._automatic_route_group(identity[1]))
            if group in selected_bola_groups:
                continue
            if bola_limit is not None and len(selected_bola_groups) >= bola_limit:
                break
            selected_bola_groups.add(group)
            selected_bola_endpoints.add(identity)

        self.authentication_test.reset_scan_state()
        shared_session = None
        needs_shared_session = bool(
            (jwt_testing and selected_reasons)
            or (rate_limit_testing and rate_limit_candidates)
            or (
                bola_testing
                and selected_bola_endpoints
                and (not jwt_testing or not selected_reasons)
            )
        )
        if needs_shared_session:
            if progress_callback:
                progress_callback(
                    {
                        "stage": "Authentication Setup",
                        "status": "running",
                        "detail": "Preparing one authenticated session for selected modules.",
                    }
                )
            shared_session = self.authentication_test.prepare_authenticated_session(
                target,
                authentication_inventory,
            )
            if progress_callback:
                progress_callback(
                    {
                        "stage": "Authentication Setup",
                        "status": (
                            "completed"
                            if shared_session["available"]
                            else "skipped"
                        ),
                        "detail": shared_session["reason"],
                    }
                )
        try:
            selected_count = len(selected_reasons)
            for index, endpoint in enumerate(analyzed, start=1):
                if cancellation_event and cancellation_event.is_set():
                    break
                identity = (endpoint.get("method") or "", endpoint.get("path"))
                endpoint["jwt_eligible"] = identity in eligible_identities
                endpoint["jwt_selection_mode"] = selection_mode
                endpoint["jwt_selection_budget"] = dict(selection_budget)
                reason = selected_reasons.get(identity)

                def report_progress():
                    if progress_callback:
                        progress_callback(
                            {
                                "stage": "Security Testing",
                                "status": "running",
                                "detail": (
                                    f"Assessed endpoint record {index} of {len(analyzed)}; "
                                        f"{selected_count} JWT endpoint(s) selected; "
                                    f"{max(len(analyzed) - index, 0)} endpoint record(s) remain."
                                ),
                            }
                        )

                if not jwt_testing:
                    endpoint["jwt_selected"] = False
                    endpoint["jwt_selection_reason"] = (
                        "JWT authentication was not selected for this scan."
                    )
                    continue
                if endpoint.get("jwt_path_error"):
                    endpoint["jwt_selected"] = False
                    endpoint["jwt_selection_reason"] = endpoint["jwt_path_error"]
                    endpoint["test_results"].append(
                        self.authentication_test.skipped_result(
                            endpoint, endpoint["jwt_selection_reason"]
                        )
                    )
                    report_progress()
                    continue
                if not reason:
                    if identity in automatic_skip_reasons:
                        skip_reason = automatic_skip_reasons[identity]
                    elif (endpoint.get("method") or "") not in _READ_ONLY_METHODS:
                        skip_reason = (
                            f"{endpoint.get('method') or 'Unknown'} is not enabled for JWT "
                            "testing; only GET is supported."
                        )
                    elif auto_mode_reason:
                        skip_reason = auto_mode_reason
                    elif self.endpoint_selector.is_authentication_path(identity[1]):
                        skip_reason = (
                            "Authentication, login, and registration routes are excluded from "
                            "the JWT protected-resource matrix."
                        )
                    else:
                        skip_reason = (
                            "Discovery did not identify a protected-resource candidate or a "
                            "401/403 response."
                        )
                    endpoint["jwt_selected"] = False
                    endpoint["jwt_selection_reason"] = skip_reason
                    endpoint["test_results"].append(
                        self.authentication_test.skipped_result(
                            endpoint, skip_reason
                        )
                    )
                    report_progress()
                    continue

                if identity[0] not in _READ_ONLY_METHODS:
                    endpoint["jwt_selected"] = False
                    endpoint["jwt_selection_reason"] = (
                        f"{identity[0] or 'Unknown'} is not enabled for JWT testing; "
                        "only GET is supported."
                    )
                    endpoint["test_results"].append(
                        self.authentication_test.skipped_result(
                            endpoint, endpoint["jwt_selection_reason"]
                        )
                    )
                    report_progress()
                    continue

                endpoint["jwt_selected"] = True
                endpoint["jwt_selection_reason"] = reason
                endpoint["applicable_tests"] = list(
                    dict.fromkeys(endpoint["applicable_tests"] + [self.TEST_MODULE])
                )
                candidate = {
                    "endpoint": endpoint,
                    "path": endpoint["path"],
                    "method": identity[0],
                    "reason": reason,
                }
                resource_route = BolaAnalyzer._resource_route(endpoint)
                if (
                    active_bola_budget is not None
                    and resource_route
                    and resource_route["is_collection"]
                    and resource_route["resource_type"]
                    in BolaAnalyzer.COLLECTION_TYPES
                ):
                    candidate["active_bola_context"] = {
                        "collection_path": resource_route["collection_path"],
                        "resource_type": resource_route["resource_type"],
                        "route_templates": [
                            route
                            for route in active_bola_route_templates
                            if route["collection_path"]
                            == resource_route["collection_path"]
                        ],
                        "budget_state": active_bola_budget,
                    }
                result = self.evaluate_authentication_test(
                    target,
                    authentication_inventory,
                    selected_candidate=candidate,
                )
                endpoint["test_results"].append(result)
                report_progress()
            discovered_rate_candidates = rate_limit_candidates

            if rate_limit_testing:
                rate_limit_selection = "user_opt_in"
                if scan_mode == "full":
                    selected_rate_candidates = discovered_rate_candidates
                else:
                    priority = {
                        "authentication": 0,
                        "user_or_account": 1,
                        "resource_collection": 2,
                        "resource_by_id": 3,
                    }
                    ordered_candidates = sorted(
                        discovered_rate_candidates,
                        key=lambda candidate: (
                            priority[candidate[3]],
                            candidate[0],
                        ),
                    )
                    selected_groups = set()
                    selected_rate_candidates = []
                    for candidate in ordered_candidates:
                        route_group = self._automatic_route_group(
                            candidate[2][1]
                        )
                        group = (candidate[2][0], route_group)
                        if group in selected_groups:
                            continue
                        selected_groups.add(group)
                        selected_rate_candidates.append(candidate)
                        if (
                            len(selected_rate_candidates)
                            >= _MAX_AUTOMATIC_RATE_LIMIT_ENDPOINTS
                        ):
                            break
            else:
                rate_limit_selection = "not_enabled"
                selected_rate_candidates = []

            selected_rate_identities = {
                candidate[2] for candidate in selected_rate_candidates
            }
            selected_rate_endpoints = {
                id(candidate[1]) for candidate in selected_rate_candidates
            }
            rate_limit_tested_count = 0
            rate_limit_request_budget = RateLimitTest.SCAN_REQUEST_BUDGET
            for endpoint in analyzed:
                identity = (
                    str(endpoint.get("method") or "").upper(),
                    endpoint.get("path"),
                )
                is_discovered = endpoint.get("discovery_source") == "discovery"
                is_selected = (
                    identity in selected_rate_identities
                    and id(endpoint) in selected_rate_endpoints
                )
                endpoint["rate_limit_selected"] = is_selected
                endpoint["rate_limit_selection_mode"] = rate_limit_selection
                endpoint["rate_limit_selection_reason"] = (
                    "Selected from discovered GET authentication/resource endpoints."
                    if is_selected
                    else (
                        "Rate-limit checks only use endpoints returned by Discovery."
                        if not is_discovered
                        else (
                            "Rate-limit testing was not enabled for this scan."
                            if rate_limit_selection == "not_enabled"
                            else "Endpoint does not match the rate-limit selection criteria."
                        )
                    )
                )
                if (
                    not is_selected
                    or (cancellation_event and cancellation_event.is_set())
                    or rate_limit_request_budget <= 0
                ):
                    if is_selected and rate_limit_request_budget <= 0:
                        endpoint["rate_limit_selection_reason"] = (
                            "Per-scan rate-limit request budget was exhausted before "
                            "this endpoint could be tested."
                        )
                    continue
                rate_limit_tested_count += 1
                authenticated_headers = (
                    self.authentication_test.get_cached_authenticated_headers(target)
                )
                result = self.rate_limit_test.analyze(
                    target,
                    endpoint,
                    scan_mode=scan_mode,
                    cancellation_event=cancellation_event,
                    request_budget=rate_limit_request_budget,
                    headers=authenticated_headers,
                )
                requests_sent = result.get("request_count", 0)
                rate_limit_request_budget = max(
                    rate_limit_request_budget - requests_sent,
                    0,
                )
                endpoint["applicable_tests"] = list(
                    dict.fromkeys(
                        endpoint["applicable_tests"] + [RateLimitTest.TEST_MODULE]
                    )
                )
                endpoint["test_results"].append(result)
                if progress_callback:
                    progress_callback(
                        {
                            "stage": "Rate Limit Testing",
                            "status": "running",
                            "detail": (
                                f"Tested {rate_limit_tested_count} of "
                                f"{len(selected_rate_endpoints)} selected endpoint(s)."
                            ),
                        }
                    )
            if bola_testing:
                cached_headers = (
                    self.authentication_test.get_cached_authenticated_headers(target)
                )
                if progress_callback:
                    progress_callback(
                        {
                            "stage": "BOLA Testing",
                            "status": "running",
                            "detail": (
                                f"Collecting authenticated evidence from "
                                f"{len(selected_bola_endpoints)} selected endpoint group(s)."
                            ),
                        }
                    )
                for _, endpoint, resource_route in ordered_bola_candidates:
                    identity = (
                        str(endpoint.get("method") or "").upper(),
                        endpoint.get("path"),
                    )
                    is_selected = identity in selected_bola_endpoints
                    endpoint["bola_selected"] = is_selected
                    endpoint["bola_selection_reason"] = (
                        "Selected for authenticated BOLA evidence collection."
                        if is_selected
                        else "BOLA endpoint-group selection limit was reached."
                    )
                    if not is_selected:
                        continue

                    endpoint["applicable_tests"] = list(
                        dict.fromkeys(
                            endpoint["applicable_tests"]
                            + [EndpointSelector.BOLA_MODULE]
                        )
                    )
                    if BolaAnalyzer._response_evidence(endpoint) is None:
                        if cached_headers:
                            endpoint["authenticated_session_check"] = (
                                self.authentication_test.probe_authenticated_endpoint(
                                    target,
                                    endpoint,
                                    cached_headers,
                                )
                            )
                            endpoint["shared_authentication"] = (
                                shared_session["discovery"]
                                if shared_session
                                else {}
                            )
                        elif not any(
                            result.get("test_module") == self.TEST_MODULE
                            for result in endpoint["test_results"]
                        ):
                            reason = (
                                shared_session["reason"]
                                if shared_session
                                else "No authenticated session was established for this scan."
                            )
                            endpoint["authenticated_session_check"] = {
                                "status": "skipped",
                                "request_attempted": False,
                                "reason": reason,
                                "evidence": None,
                            }
                            endpoint["shared_authentication"] = (
                                shared_session["discovery"]
                                if shared_session
                                else {}
                            )

                    if (
                        active_bola_enabled
                        and resource_route["is_collection"]
                        and active_bola_budget is not None
                        and not any(
                            result.get("active_bola_tests")
                            for result in endpoint["test_results"]
                        )
                    ):
                        endpoint["active_bola_tests"] = (
                            self.authentication_test._active_bola_test_results(
                                target=target,
                                collection_path=resource_route["collection_path"],
                                resource_type=resource_route["resource_type"],
                                route_templates=[
                                    route
                                    for route in active_bola_route_templates
                                    if route["collection_path"]
                                    == resource_route["collection_path"]
                                ],
                                responses={},
                                authenticated_evidence=(
                                    BolaAnalyzer._response_evidence(endpoint)
                                ),
                                authenticated_headers=cached_headers,
                                budget_state=active_bola_budget,
                            )
                        )
                bola_data = BolaAnalyzer(self.endpoint_selector).analyze(analyzed)
                if progress_callback:
                    active_test_count = sum(
                        len(endpoint.get("active_bola_tests", []))
                        + sum(
                            len(result.get("active_bola_tests", []))
                            for result in endpoint.get("test_results", [])
                        )
                        for endpoint in analyzed
                    )
                    progress_callback(
                        {
                            "stage": "BOLA Testing",
                            "status": "completed",
                            "detail": (
                                f"Produced {len(bola_data['assessments'])} passive assessment(s) "
                                f"and {active_test_count} "
                                "active detail-check record(s)."
                            ),
                        }
                    )
            else:
                bola_data = {"baselines": [], "assessments": []}
            endpoints_by_identity = {
                (endpoint.get("method"), endpoint.get("path")): endpoint
                for endpoint in analyzed
            }
            for baseline in bola_data["baselines"]:
                endpoint = endpoints_by_identity.get(
                    (baseline.get("method"), baseline.get("collection_endpoint"))
                )
                if endpoint is not None:
                    endpoint["bola_baseline"] = baseline
            for assessment in bola_data["assessments"]:
                endpoint = endpoints_by_identity.get(
                    (assessment.get("method"), assessment.get("resource_endpoint"))
                )
                if endpoint is not None:
                    endpoint["bola_assessment"] = assessment
        finally:
            self.authentication_test.reset_scan_state()
        return analyzed
