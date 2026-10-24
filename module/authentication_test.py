import base64
import hashlib
import json
import re
import secrets
from urllib.parse import urljoin, urlsplit

import httpx

from module.endpoint_selection import EndpointSelector
from module.signin import LoginConfigurationError, LoginError, Signin


def _invalid_signature_token():
    def encode_segment(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    header = encode_segment(
        json.dumps(
            {"alg": "HS256", "typ": "JWT"},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    payload = encode_segment(
        json.dumps(
            {"sub": "microscan-invalid-signature-probe"},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signature = encode_segment(secrets.token_bytes(32))
    return f"{header}.{payload}.{signature}"


class AuthenticationTest:
    INVALID_TOKEN = _invalid_signature_token()
    TIMEOUT_SECONDS = 8
    MAX_EVIDENCE_RECORDS = 3
    MAX_EVIDENCE_FIELDS = 20
    MAX_EVIDENCE_NODES = 250
    MAX_EVIDENCE_BODY_BYTES = 1024 * 1024
    _BODY_METADATA_KEYS = {
        "message",
        "error",
        "errors",
        "status",
        "success",
        "authenticated",
        "code",
        "detail",
        "exception",
        "traceback",
        "stack",
        "timestamp",
        "requestid",
        "request_id",
        "error_code",
        "error_description",
        "error_message",
        "title",
        "type",
        "instance",
        "traceid",
        "trace_id",
    }
    _BODY_WRAPPER_KEYS = {
        "data",
        "result",
        "results",
        "payload",
        "items",
        "records",
        "content",
    }
    _BODY_RESOURCE_KEYS = _BODY_WRAPPER_KEYS | {
        "user",
        "account",
        "profile",
        "order",
        "inventory",
        "product",
        "customer",
        "resource",
    }
    _RESOURCE_IDENTIFIER_FIELDS = {"id", "_id", "uuid", "guid"}
    _RESOURCE_DATA_FIELDS = {
        "name",
        "title",
        "description",
        "sku",
        "order_id",
        "user_id",
        "customer_id",
        "product_id",
        "amount",
        "total",
        "price",
        "quantity",
        "balance",
        "revenue",
        "created_at",
        "updated_at",
        "role",
        "department",
    }
    _SENSITIVE_KEY_PARTS = (
        "token",
        "password",
        "secret",
        "authorization",
        "cookie",
        "credential",
        "email",
        "phone",
        "address",
    )

    def __init__(self, endpoint_selector=None):
        self.endpoint_selector = endpoint_selector or EndpointSelector()
        self._login_cache = {}

    def reset_scan_state(self):
        self._login_cache.clear()

    def _signin_once(self, target, configuration):
        fingerprint = hashlib.sha256(
            json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        cache_key = (target, fingerprint)
        cached = self._login_cache.get(cache_key)
        if cached is None:
            try:
                cached = {"token_info": Signin().signin(target, configuration)}
            except LoginConfigurationError as exc:
                cached = {"error_type": "configuration", "reason": str(exc)}
            except LoginError as exc:
                cached = {
                    "error_type": "login",
                    "reason": str(exc),
                    "status_code": exc.status_code,
                }
            self._login_cache[cache_key] = cached

        if cached.get("error_type") == "configuration":
            raise LoginConfigurationError(cached["reason"])
        if cached.get("error_type") == "login":
            raise LoginError(cached["reason"], status_code=cached.get("status_code"))
        return dict(cached["token_info"])

    @staticmethod
    def _scope_url(target, path):
        origin = Signin.normalize_target(target)
        candidate_path = (path or "").strip()
        if not candidate_path:
            raise ValueError("A protected endpoint path is required.")
        configured_path = urlsplit(candidate_path)
        if (
            configured_path.scheme
            or configured_path.netloc
            or configured_path.query
            or configured_path.fragment
        ):
            raise ValueError(
                "Protected endpoint must be a path without query or fragment data."
            )
        absolute = urljoin(f"{origin}/", candidate_path)
        base = urlsplit(origin)
        parsed = urlsplit(absolute)
        if (
            parsed.scheme != base.scheme
            or parsed.netloc.lower() != base.netloc.lower()
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise ValueError("Request is outside the configured target origin.")
        return absolute

    def _run_http_request(self, method, url, headers=None):
        return httpx.request(
            method,
            url,
            headers=headers,
            timeout=self.TIMEOUT_SECONDS,
            follow_redirects=False,
        )

    @classmethod
    def _body_evidence(cls, response):
        content = response.content
        body_too_large = len(content) > cls.MAX_EVIDENCE_BODY_BYTES
        try:
            if body_too_large:
                raise ValueError("Response body exceeds the evidence parsing limit.")
            body = response.json()
        except (ValueError, json.JSONDecodeError):
            body = None
            is_json = False
        else:
            is_json = True

        json_keys = []
        empty_collection_paths = []
        resource_records = []
        error_payload_observed = False
        visited_nodes = 0
        traversal_truncated = body_too_large

        def is_sensitive_key(key):
            lowered = str(key).lower()
            return any(part in lowered for part in cls._SENSITIVE_KEY_PARTS)

        def safe_field_type(value):
            if isinstance(value, bool):
                return "<redacted:boolean>"
            if isinstance(value, (int, float)):
                return "<redacted:number>"
            if isinstance(value, str):
                return "<redacted:string>"
            if value is None:
                return "<redacted:null>"
            return "<redacted:value>"

        def walk(
            value,
            path="$",
            parent_is_error=False,
            array_item=False,
            parent_key=None,
        ):
            nonlocal error_payload_observed, visited_nodes, traversal_truncated
            if visited_nodes >= cls.MAX_EVIDENCE_NODES:
                traversal_truncated = True
                return
            visited_nodes += 1

            if isinstance(value, dict):
                for key in value:
                    if (
                        isinstance(key, str)
                        and not is_sensitive_key(key)
                        and key not in json_keys
                        and len(json_keys) < cls.MAX_EVIDENCE_FIELDS
                    ):
                        json_keys.append(key[:64])
                error_keys = {
                    key.lower()
                    for key in value
                    if isinstance(key, str)
                    and key.lower()
                    in {"error", "errors", "exception", "traceback", "stack"}
                }
                object_indicates_denial = cls._body_object_indicates_denial(value)
                if error_keys or object_indicates_denial:
                    error_payload_observed = True

                record_fields = [
                    (key, child)
                    for key, child in value.items()
                    if isinstance(key, str)
                    and key.lower() not in cls._BODY_METADATA_KEYS
                    and key.lower() not in cls._BODY_WRAPPER_KEYS
                    and not is_sensitive_key(key)
                    and not isinstance(child, (dict, list))
                    and child not in (None, "")
                ]
                field_names = {key.lower() for key, _ in record_fields}
                has_resource_identifier = bool(
                    field_names & cls._RESOURCE_IDENTIFIER_FIELDS
                )
                has_resource_field = bool(
                    field_names & cls._RESOURCE_DATA_FIELDS
                )
                is_error_object = (
                    bool(error_keys) or object_indicates_denial
                ) and not record_fields
                single_field_resource = (
                    len(record_fields) == 1
                    and (has_resource_identifier or has_resource_field)
                    and parent_key is not None
                    and parent_key.lower() in cls._BODY_RESOURCE_KEYS
                )
                record_shape = (
                    (
                        has_resource_identifier
                        and (
                            len(record_fields) >= 2
                            or array_item
                            or parent_key in cls._BODY_RESOURCE_KEYS
                        )
                    )
                    or (len(record_fields) >= 2 and has_resource_field)
                    or (array_item and has_resource_field)
                    or single_field_resource
                )
                if (
                    not parent_is_error
                    and not is_error_object
                    and len(resource_records) < cls.MAX_EVIDENCE_RECORDS
                    and record_shape
                ):
                    resource_records.append(
                        {
                            "path": path[:160],
                            "fields": {
                                key[:64]: safe_field_type(child)
                                for key, child in record_fields[
                                    : cls.MAX_EVIDENCE_FIELDS
                                ]
                            },
                        }
                    )

                for key, child in value.items():
                    key_name = str(key).lower()
                    if is_sensitive_key(key_name):
                        continue
                    is_error = parent_is_error or key_name in {
                        "error",
                        "errors",
                        "exception",
                        "traceback",
                        "stack",
                    }
                    walk(
                        child,
                        f"{path}.{key}"[:160],
                        is_error,
                        False,
                        key_name,
                    )
            elif isinstance(value, list):
                if not value:
                    empty_collection_paths.append(path[:160])
                for index, child in enumerate(value[: cls.MAX_EVIDENCE_RECORDS]):
                    walk(child, f"{path}[{index}]", parent_is_error, True)
                if len(value) > cls.MAX_EVIDENCE_RECORDS:
                    traversal_truncated = True

        if is_json:
            walk(body)

        http_denial = response.status_code in {401, 403}
        body_denial = cls._body_indicates_denial(response)
        record_count_observed = len(resource_records)
        body_available = bool(response.content)
        return {
            "response_is_json": is_json,
            "body_available": body_available,
            "body_summary_partial": traversal_truncated,
            "body_truncated": body_too_large,
            "body_summary_limit_bytes": cls.MAX_EVIDENCE_BODY_BYTES,
            "json_keys": json_keys,
            "authorization_denial_detected": http_denial or body_denial,
            "http_status_denial": http_denial,
            "body_denial_signal": body_denial,
            "error_payload_observed": error_payload_observed,
            "resource_records_observed": record_count_observed > 0,
            "resource_record_count_observed": record_count_observed,
            "resource_record_sample_count": record_count_observed,
            "resource_record_samples": resource_records,
            "empty_collection_observed": bool(empty_collection_paths),
            "empty_collection_paths": empty_collection_paths[
                : cls.MAX_EVIDENCE_RECORDS
            ],
            "identifiable_business_data": record_count_observed > 0,
        }

    @classmethod
    def _body_object_indicates_denial(cls, body):
        denial_terms = (
            "unauthorized",
            "not authorized",
            "forbidden",
            "invalid token",
            "login required",
            "access denied",
            "authentication required",
            "authentication failed",
            "authorization failed",
            "invalid credentials",
            "not authenticated",
            "permission denied",
        )

        def normalized_key(key):
            return str(key).lower().replace("-", "_")

        authorization_flags = {
            "authenticated",
            "is_authenticated",
            "authorized",
            "is_authorized",
            "authentication_success",
            "authorization_success",
            "access_granted",
        }
        if any(
            normalized_key(key) in authorization_flags and value is False
            for key, value in body.items()
        ):
            return True

        business_fields = cls._RESOURCE_IDENTIFIER_FIELDS | cls._RESOURCE_DATA_FIELDS
        has_business_record_fields = any(
            normalized_key(key) in business_fields
            and not isinstance(value, (dict, list))
            and value not in (None, "")
            for key, value in body.items()
        )
        diagnostic_keys = {"message", "error", "errors", "detail", "title"}
        auth_key_prefixes = ("auth_", "authentication_", "authorization_")
        for key, value in body.items():
            key_name = normalized_key(key)
            is_auth_field = (
                key_name in {"auth", "authentication", "authorization"}
                or key_name.startswith(auth_key_prefixes)
                or key_name in {"error_code", "error_description"}
            )
            if is_auth_field and isinstance(value, str):
                lowered_value = value.lower().replace("_", " ").replace("-", " ")
                if any(term in lowered_value for term in denial_terms):
                    return True

            if (
                not has_business_record_fields
                and key_name in diagnostic_keys
                and isinstance(value, str)
            ):
                lowered_value = value.lower().replace("_", " ").replace("-", " ")
                if any(term in lowered_value for term in denial_terms):
                    return True

            if key_name in {"code", "status_code", "error_code"} and isinstance(
                value, str
            ):
                code = value.upper().replace("-", "_")
                if code.startswith(
                    (
                        "AUTH_",
                        "AUTHENTICATION_",
                        "AUTHORIZATION_",
                        "ACCESS_DENIED",
                        "PERMISSION_DENIED",
                        "UNAUTHORIZED",
                        "FORBIDDEN",
                        "INVALID_TOKEN",
                    )
                ):
                    return True

        problem_status = body.get("status", body.get("status_code"))
        return (
            isinstance(problem_status, int)
            and problem_status in {401, 403}
            and any(key in body for key in ("title", "detail", "type"))
        )

    @classmethod
    def _body_indicates_denial(cls, response):
        if len(response.content) > cls.MAX_EVIDENCE_BODY_BYTES:
            return False
        try:
            body = response.json()
        except (ValueError, json.JSONDecodeError):
            body = None

        def contains_denial(value):
            if isinstance(value, dict):
                return cls._body_object_indicates_denial(value) or any(
                    contains_denial(child) for child in value.values()
                )
            if isinstance(value, list):
                return any(contains_denial(child) for child in value)
            return False

        return contains_denial(body)

    @classmethod
    def _is_denied(cls, response):
        if response is None:
            return False
        return (
            response.status_code in {401, 403}
            or cls._body_indicates_denial(response)
        )

    @classmethod
    def _response_evidence(cls, response):
        body_evidence = cls._body_evidence(response)
        challenge = response.headers.get("www-authenticate", "")
        challenge_scheme = challenge.split(None, 1)[0] if challenge else None
        if challenge_scheme and not re.fullmatch(
            r"[A-Za-z0-9._-]+", challenge_scheme
        ):
            challenge_scheme = None
        http_denial = body_evidence["http_status_denial"]
        body_denial = body_evidence["body_denial_signal"]
        challenge_denial = challenge_scheme is not None
        authorization_denied = http_denial or body_denial or challenge_denial
        return {
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", "").split(";", 1)[0],
            "body_bytes": len(response.content),
            **body_evidence,
            "protected_data_observed": body_evidence["resource_records_observed"],
            "authorization_denial_detected": authorization_denied,
            "authentication_denied": authorization_denied,
            "denial_basis": (
                "http_status"
                if http_denial
                else "response_body"
                if body_denial
                else "authentication_challenge"
                if challenge_denial
                else None
            ),
            "observed_challenge_scheme": challenge_scheme,
        }

    @staticmethod
    def _test_result(status, reason, evidence, tested_endpoint=None):
        return {
            "test_module": EndpointSelector.TEST_MODULE,
            "status": status,
            "reason": reason,
            "tested_endpoint": tested_endpoint,
            "evidence": evidence,
        }

    @classmethod
    def skipped_result(cls, endpoint, reason):
        method = str(endpoint.get("method") or "UNKNOWN").upper()
        path = endpoint.get("path") or endpoint.get("target") or "/"
        cases = [
            {
                "test_case": test_case,
                "method": method,
                "path": path,
                "request_condition": "No request sent.",
                "status": "skipped",
                "reason": reason,
                "evidence": None,
                "executed": False,
                "request_attempted": False,
            }
            for test_case in (
                "without_token",
                "invalid_token",
                "valid_token",
                "expired_token",
            )
        ]
        return {
            "test_module": EndpointSelector.TEST_MODULE,
            "status": "skipped",
            "reason": reason,
            "method": method,
            "tested_endpoint": path,
            "evidence": [],
            "test_cases": cases,
        }

    @staticmethod
    def _case_result(test_case, method, path, condition, check, denied_only=False):
        resource_samples = check.get("resource_record_samples")
        has_resource_records = (
            check.get("resource_records_observed") is True
            and isinstance(resource_samples, list)
            and bool(resource_samples)
        )
        status_code_denial = check.get("status_code") in {401, 403}
        challenge_denial = bool(check.get("observed_challenge_scheme"))
        denial_signal = any(
            (
                check.get("authentication_denied"),
                check.get("authorization_denial_detected"),
                check.get("http_status_denial"),
                check.get("body_denial_signal"),
                status_code_denial,
                challenge_denial,
                check.get("denial_basis"),
            )
        )
        evidence_incomplete = bool(
            check.get("body_summary_partial") or check.get("body_truncated")
        )
        evidence = {
            key: check.get(key)
            for key in (
                "status_code",
                "content_type",
                "body_bytes",
                "json_keys",
                "protected_data_observed",
                "authentication_denied",
                "denial_basis",
                "authentication_required",
                "observed_challenge_scheme",
                "response_is_json",
                "body_available",
                "body_summary_partial",
                "body_truncated",
                "body_summary_limit_bytes",
                "authorization_denial_detected",
                "http_status_denial",
                "body_denial_signal",
                "error_payload_observed",
                "resource_records_observed",
                "resource_record_count_observed",
                "resource_record_sample_count",
                "resource_record_samples",
                "empty_collection_observed",
                "empty_collection_paths",
                "identifiable_business_data",
            )
            if key in check
        }
        if denial_signal:
            evidence["authentication_denied"] = True
            evidence["authorization_denial_detected"] = True
            if not evidence.get("denial_basis"):
                evidence["denial_basis"] = (
                    "http_status"
                    if status_code_denial
                    else "authentication_challenge"
                    if challenge_denial
                    else "response_body"
                    if check.get("body_denial_signal")
                    else None
                )
        if evidence_incomplete:
            evidence["body_summary_partial"] = True
        if check.get("execution_status"):
            status = "inconclusive"
            reason = check.get("reason", "The request did not complete.")
        elif has_resource_records and not denied_only:
            if denial_signal or evidence_incomplete:
                status = "potential"
                if denial_signal and evidence_incomplete:
                    reason = (
                        "The same response also indicated authorization denial, and its "
                        "evidence summary is partial or truncated. Sanitized record-shaped "
                        "evidence is retained, but the conflict requires verification."
                    )
                elif denial_signal:
                    reason = (
                        "The same response also indicated authorization denial. Sanitized "
                        "record-shaped evidence is retained, but the conflict requires "
                        "verification."
                    )
                else:
                    reason = (
                        "Sanitized record-shaped resource evidence was observed, but the "
                        "response evidence summary is partial or truncated."
                    )
            elif check.get("authentication_required") is False:
                status = "not_detected_in_this_test"
                reason = (
                    "The response returned structured data, but explicit endpoint policy "
                    "metadata marks the resource as public; no JWT weakness was detected in "
                    "this test."
                )
            elif (
                check.get("authentication_required") is True
                and not check.get("authentication_denied")
                and test_case
                in {
                    "without_token",
                    "invalid_token",
                    "expired_token",
                }
            ):
                status = "confirmed"
                vulnerability = {
                    "without_token": "Missing JWT",
                    "invalid_token": "Invalid JWT accepted",
                    "expired_token": "Expired JWT accepted",
                }[test_case]
                reason = (
                    f"Structured resource data was returned for the {test_case} request, "
                    "and explicit endpoint policy metadata states that authentication is "
                    f"required; this confirms {vulnerability} in this test."
                )
            else:
                status = "potential"
                record_count = check.get("resource_record_sample_count", 1)
                reason = (
                    f"Up to {record_count} record-like resource object(s) with identifiable "
                    "business fields were present in the response for this request condition. "
                    "This is a potential unauthorized-data exposure; intended policy and "
                    "ownership of the returned records remain unverified."
                )
                if check.get("authentication_denied"):
                    reason += (
                        " The same response also indicated authorization denial. Sanitized "
                        "record-field evidence is retained; verify whether these are resource "
                        "records or an error-envelope artifact."
                    )
                if check.get("body_summary_partial"):
                    reason += " The response summary is partial."
        elif denial_signal:
            if evidence_incomplete or (
                not check.get("body_available")
                or not check.get("response_is_json")
            ):
                status = "inconclusive"
                reason = (
                    "Authorization denial was indicated, but the response body was unavailable, "
                    "non-JSON, or only partially summarized; resource disclosure could not be "
                    "reliably excluded."
                )
            elif check.get("denial_basis") == "response_body":
                status = "not_detected_in_this_test"
                reason = (
                    "The response body explicitly indicated an authorization denial despite "
                    "the HTTP status. No protected data was observed; this result applies only "
                    "to this test case."
                )
            elif check.get("denial_basis") == "authentication_challenge":
                status = "not_detected_in_this_test"
                reason = (
                    "The server returned an authentication challenge and no protected data was "
                    "observed. This result applies only to this test case."
                )
            elif check.get("denial_basis") == "http_status":
                status = "not_detected_in_this_test"
                reason = (
                    f"The server returned HTTP {check.get('status_code')} and no protected "
                    "resource records were identified in the JSON body. This is evidence that "
                    "this request condition was rejected, limited to this test case."
                )
            else:
                status = "not_detected_in_this_test"
                reason = (
                    "The available response evidence indicated an authorization denial and no "
                    "protected data was observed. This result applies only to this test case."
                )
        elif isinstance(check.get("status_code"), int) and (
            200 <= check["status_code"] < 300
        ):
            status = "inconclusive"
            reason = (
                "The successful HTTP response contained no observable resource data or explicit "
                "authorization decision; the available body is insufficient to assess this case."
            )
        else:
            status = "inconclusive"
            reason = (
                "The response did not establish the endpoint's expected authorization policy "
                "or provide enough evidence to assess this test case."
            )
        return {
            "test_case": test_case,
            "method": method,
            "path": path,
            "request_condition": condition,
            "status": status,
            "reason": reason,
            "evidence": evidence,
            "unverified": (
                "Whether this endpoint is intended to require authentication."
                if status == "potential"
                or (
                    status == "not_detected_in_this_test"
                    and check.get("authentication_required") is None
                )
                else None
            ),
            "executed": True,
            "request_attempted": True,
        }

    def evaluate(self, target, selected_endpoint, discovered_endpoints=None):
        if selected_endpoint is None:
            return self._test_result(
                "skipped",
                "No suitable discovered GET endpoint was available; MicroScan will not invent a probe path.",
                [],
            )

        protected_path = selected_endpoint["path"]
        method = str(selected_endpoint.get("method") or "GET").upper()
        selection_reason = selected_endpoint["reason"]
        candidate_endpoint = selected_endpoint.get("endpoint")
        if method != "GET":
            return self.skipped_result(
                {"method": method, "path": protected_path},
                "Only explicitly allowlisted GET endpoints are currently probed.",
            )
        try:
            url = self._scope_url(target, protected_path)
        except (LoginConfigurationError, ValueError) as exc:
            result = self.skipped_result(
                {"method": method, "path": protected_path},
                str(exc),
            )
            result["endpoint_selection_reason"] = selection_reason
            return result

        unauthenticated_checks = []
        responses = {}
        for label, headers in (
            ("without_credentials", None),
            ("invalid_bearer_token", {"Authorization": f"Bearer {self.INVALID_TOKEN}"}),
        ):
            try:
                response = self._run_http_request(method, url, headers=headers)
                responses[label] = response
                unauthenticated_checks.append(
                    {"request": label, **self._response_evidence(response)}
                )
            except httpx.TimeoutException:
                unauthenticated_checks.append(
                    {
                        "request": label,
                        "execution_status": "error",
                        "reason": "Request timed out.",
                    }
                )
            except httpx.RequestError:
                unauthenticated_checks.append(
                    {
                        "request": label,
                        "execution_status": "error",
                        "reason": "Request failed to reach the configured target.",
                    }
                )

        login_candidates = self.endpoint_selector.discover_login_candidates(
            discovered_endpoints
        )
        discovery = {
            "tested_endpoint": {
                "method": method,
                "path": protected_path,
                "discovery_status": (
                    self.endpoint_selector.discovery_status(candidate_endpoint)
                    if candidate_endpoint
                    else None
                ),
            },
            "endpoint_selection_reason": selection_reason,
            "discovered_login_endpoints": login_candidates,
            "authentication_mechanism": "unknown",
            "note": (
                "Login endpoints are reported only when discovered. No login schema or "
                "credentials are inferred."
            ),
        }
        challenges = [
            item.get("observed_challenge_scheme")
            for item in unauthenticated_checks
            if item.get("observed_challenge_scheme")
        ]
        if challenges:
            discovery["authentication_mechanism"] = challenges[0].lower()

        authenticated_check = {
            "status": "skipped",
            "request_attempted": False,
            "reason": (
                "No user-provided login configuration is available; unauthenticated checks ran, "
                "but authenticated coverage is unavailable."
            ),
            "evidence": None,
        }
        try:
            auth_config, discovered_login_candidates, configuration_note = (
                Signin.configured_auth(discovered_endpoints)
            )
            discovery["discovered_login_endpoints"] = discovered_login_candidates
            if auth_config is None:
                authenticated_check["reason"] = configuration_note
            else:
                token_info = self._signin_once(target, auth_config)
                token = token_info.pop("token")
                scheme = token_info.get("auth_scheme") or (
                    challenges[0] if challenges else None
                )
                scheme_source = token_info.get("auth_scheme_source") or (
                    "observed_challenge" if challenges else None
                )
                mechanism = token_info["mechanism"]
                if scheme and "scheme unknown" in mechanism:
                    token_format = "JWT over " if mechanism.startswith("jwt ") else ""
                    source_label = {
                        "configured": "configured",
                        "login_response": "login response",
                        "observed_challenge": "challenge observed",
                        "jwt_format_default": "inferred from JWT format",
                    }.get(scheme_source, "observed")
                    mechanism = f"{token_format}{scheme} ({source_label})"
                discovery["authentication_mechanism"] = mechanism
                if not scheme:
                    authenticated_check["reason"] = (
                        "Login succeeded and a token was obtained, but the API did not provide "
                        "an authorization scheme. Configure auth_scheme in MICROSCAN_AUTH_CONFIG."
                    )
                elif not re.fullmatch(r"[A-Za-z0-9-]+", token_info["auth_header"]):
                    authenticated_check["reason"] = (
                        "Login succeeded, but configured auth_header is invalid."
                    )
                else:
                    try:
                        response = self._run_http_request(
                            method,
                            url,
                            headers={
                                token_info["auth_header"]: f"{scheme} {token}"
                            },
                        )
                        responses["authenticated"] = response
                        authenticated_check = {
                            "status": "tested",
                            "request_attempted": True,
                            "reason": self._authenticated_probe_reason(scheme_source),
                            "login_status": token_info["http_status"],
                            "auth_scheme_source": scheme_source,
                            "login_response_content_type": token_info[
                                "response_content_type"
                            ],
                            "evidence": self._response_evidence(response),
                        }
                    except httpx.TimeoutException:
                        authenticated_check = {
                            "status": "error",
                            "request_attempted": True,
                            "reason": "Authenticated endpoint request timed out.",
                            "login_status": token_info["http_status"],
                            "evidence": None,
                        }
                    except httpx.RequestError:
                        authenticated_check = {
                            "status": "error",
                            "request_attempted": True,
                            "reason": (
                                "Authenticated endpoint request failed to reach the "
                                "configured target."
                            ),
                            "login_status": token_info["http_status"],
                            "evidence": None,
                        }
                token = None
        except LoginConfigurationError as exc:
            authenticated_check = {
                "status": "error",
                "request_attempted": False,
                "reason": str(exc),
                "evidence": None,
            }
        except LoginError as exc:
            authenticated_check = {
                "status": "error",
                "request_attempted": False,
                "reason": str(exc),
                "login_status": exc.status_code,
                "evidence": None,
            }
        finally:
            token = None

        evidence = [
            {"request": "endpoint_selection", "reason": selection_reason},
            *unauthenticated_checks,
        ]
        if authenticated_check.get("evidence"):
            evidence.append(
                {"request": "authenticated", **authenticated_check["evidence"]}
            )
        if authenticated_check["status"] != "tested":
            evidence.append(
                {
                    "request": "authenticated",
                    "execution_status": authenticated_check["status"],
                    "reason": authenticated_check["reason"],
                }
            )

        unauthenticated_by_name = {
            check["request"]: check for check in unauthenticated_checks
        }
        authentication_required = (
            candidate_endpoint.get("authentication_required")
            if isinstance(candidate_endpoint, dict)
            and isinstance(candidate_endpoint.get("authentication_required"), bool)
            else None
        )
        without_token_check = dict(
            unauthenticated_by_name.get("without_credentials", {})
        )
        invalid_token_check = dict(
            unauthenticated_by_name.get("invalid_bearer_token", {})
        )
        if authentication_required is not None:
            without_token_check["authentication_required"] = authentication_required
            invalid_token_check["authentication_required"] = authentication_required
        test_cases = [
            self._case_result(
                "without_token",
                method,
                protected_path,
                "No Authorization header.",
                without_token_check,
            ),
            self._case_result(
                "invalid_token",
                method,
                protected_path,
                (
                    "Structurally valid JWT with an intentionally random, invalid "
                    "HS256 signature sent as a Bearer token; token value is omitted."
                ),
                invalid_token_check,
            ),
        ]
        authenticated_evidence = authenticated_check.get("evidence")
        if authenticated_check.get("status") == "tested" and authenticated_evidence:
            valid_check = {
                **authenticated_evidence,
                "reason": authenticated_check.get("reason"),
            }
            if (
                valid_check.get("authentication_denied")
                and valid_check.get("protected_data_observed")
            ):
                valid_case_status = "inconclusive"
                valid_reason = (
                    "The authenticated response contains conflicting denial and resource-data "
                    "signals; the valid-token outcome cannot be determined reliably."
                )
            elif valid_check.get("authentication_denied"):
                valid_case_status = "inconclusive"
                valid_reason = (
                    "The endpoint denied the configured token; token validity or endpoint "
                    "authorization requirements could not be established."
                )
            elif valid_check.get("protected_data_observed"):
                valid_case_status = "not_detected_in_this_test"
                valid_reason = (
                    "The configured token returned structured resource data. This is a "
                    "positive-control result and is assessed independently of other cases."
                )
            else:
                valid_case_status = "inconclusive"
                valid_reason = (
                    "The configured-token response did not contain resource data or an explicit "
                    "authorization decision; this case is inconclusive."
                )
            test_cases.append(
                {
                    "test_case": "valid_token",
                    "method": method,
                    "path": protected_path,
                    "request_condition": (
                        "Token obtained using the configured login flow; token value omitted."
                    ),
                    "status": valid_case_status,
                    "reason": valid_reason,
                    "unverified": None,
                    "executed": True,
                    "request_attempted": True,
                    "evidence": {
                        key: valid_check[key]
                        for key in (
                            "status_code",
                            "content_type",
                            "body_bytes",
                            "json_keys",
                            "protected_data_observed",
                            "authentication_denied",
                            "denial_basis",
                            "response_is_json",
                            "body_available",
                            "body_summary_partial",
                            "body_truncated",
                            "body_summary_limit_bytes",
                            "authorization_denial_detected",
                            "http_status_denial",
                            "body_denial_signal",
                            "error_payload_observed",
                            "resource_records_observed",
                            "resource_record_count_observed",
                            "resource_record_sample_count",
                            "resource_record_samples",
                            "empty_collection_observed",
                            "empty_collection_paths",
                            "identifiable_business_data",
                        )
                        if key in valid_check
                    },
                }
            )
        else:
            request_attempted = authenticated_check.get("request_attempted", False)
            test_cases.append(
                {
                    "test_case": "valid_token",
                    "method": method,
                    "path": protected_path,
                    "request_condition": (
                        "Authenticated request attempted but no response was available."
                        if request_attempted
                        else "No valid token request sent."
                    ),
                    "status": (
                        "error"
                        if authenticated_check.get("status") == "error"
                        and request_attempted
                        else "inconclusive"
                        if request_attempted
                        else "skipped"
                    ),
                    "reason": authenticated_check.get("reason"),
                    "evidence": None,
                    "executed": bool(request_attempted),
                    "request_attempted": bool(request_attempted),
                }
            )
        test_cases.append(
            {
                "test_case": "expired_token",
                "method": method,
                "path": protected_path,
                "request_condition": "No request sent.",
                "status": "skipped",
                "reason": (
                    "Expired-token probing is not implemented; MicroScan will not infer "
                    "a signing key or forge an expired token."
                ),
                "evidence": None,
                "executed": False,
                "request_attempted": False,
                "implementation_status": "not_implemented",
            }
        )

        case_statuses = [case.get("status") for case in test_cases]
        if "confirmed" in case_statuses:
            status = "confirmed"
            reason = next(
                case["reason"]
                for case in test_cases
                if case.get("status") == "confirmed"
            )
        elif "potential" in case_statuses:
            status = "potential"
            reason = next(
                case["reason"]
                for case in test_cases
                if case.get("status") == "potential"
            )
        elif "inconclusive" in case_statuses or "error" in case_statuses:
            status = "inconclusive"
            reason = (
                "One or more independent JWT test cases could not be assessed from "
                "sufficient response evidence."
            )
        else:
            cases_by_name = {case["test_case"]: case for case in test_cases}
            without_token = cases_by_name.get("without_token")
            invalid_token = cases_by_name.get("invalid_token")
            valid_token = cases_by_name.get("valid_token")
            if (
                without_token
                and invalid_token
                and valid_token
                and without_token.get("status") == "not_detected_in_this_test"
                and invalid_token.get("status") == "not_detected_in_this_test"
                and valid_token.get("status") == "not_detected_in_this_test"
            ):
                status = "not_vulnerable_in_test"
                reason = (
                    "No-token and invalid-token requests were denied without resource records, "
                    "and the configured-token request returned resource records. This is limited "
                    "to these cases; expired-token coverage may remain incomplete."
                )
            else:
                status = "inconclusive"
                reason = (
                    "The endpoint's authorization behavior and expected access policy could not "
                    "be established from the available independent test-case evidence."
                )

        result = self._test_result(status, reason, evidence, protected_path)
        result.update(
            {
                "endpoint_selection_reason": selection_reason,
                "method": method,
                "discovery": discovery,
                "unauthenticated_checks": unauthenticated_checks,
                "authenticated_check": authenticated_check,
                "authentication_mechanism": discovery["authentication_mechanism"],
                "test_cases": test_cases,
            }
        )
        return result

    @staticmethod
    def _authenticated_probe_reason(scheme_source):
        if scheme_source == "jwt_format_default":
            return (
                "Configured login succeeded; the JWT-shaped token was sent using the "
                "conventional Bearer scheme because the response did not declare a scheme."
            )
        if scheme_source == "login_response":
            return (
                "Configured login succeeded; the token was sent using the scheme declared "
                "by the login response."
            )
        if scheme_source == "observed_challenge":
            return (
                "Configured login succeeded; the token was sent using the scheme observed "
                "in the endpoint's authentication challenge."
            )
        return (
            "Configured login succeeded; the token was sent using the explicitly configured "
            "authorization scheme."
        )
