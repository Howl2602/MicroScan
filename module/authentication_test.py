import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from urllib.parse import quote, urljoin, urlsplit

import httpx

from module.endpoint_selection import EndpointSelector
from module.signin import LoginConfigurationError, LoginError, Signin


logger = logging.getLogger(__name__)
_OWNER_FINGERPRINT_SALT = secrets.token_bytes(32)


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
    MAX_EVIDENCE_TRAVERSAL_LIMIT = 25
    MAX_EVIDENCE_FIELDS = 20
    MAX_EVIDENCE_NODES = 250
    MAX_EVIDENCE_BODY_BYTES = 1024 * 1024
    MAX_ACTIVE_BOLA_CANDIDATES = 100
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
    _RESOURCE_IDENTIFIER_SUFFIXES = ("id", "uuid", "guid")
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
    _OWNER_IDENTITY_FIELDS = {
        "customername",
        "ownername",
        "username",
        "customer",
        "owner",
    }

    @staticmethod
    def _owner_fingerprint(value):
        if not isinstance(value, str) or not value.strip():
            return None
        normalized = value.strip().casefold().encode("utf-8")
        return hmac.new(
            _OWNER_FINGERPRINT_SALT,
            normalized,
            hashlib.sha256,
        ).hexdigest()

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

    def _signin_candidates(self, target, configuration, candidates, discovery):
        candidate_configurations = configuration.get("_candidate_configurations", {})
        if candidate_configurations:
            configured_login_endpoint = configuration.get("login_endpoint")
            configured_login_parts = urlsplit(configured_login_endpoint or "")
            configured_login_path = (
                configured_login_parts.path
                if configured_login_parts.scheme or configured_login_parts.netloc
                else configured_login_endpoint
            )
            eligible_candidates = [
                candidate
                for candidate in candidates
                if candidate.get("path") in candidate_configurations
            ]
            if configuration.get("explicit_login_endpoint"):
                eligible_candidates = [
                    candidate
                    for candidate in eligible_candidates
                    if candidate.get("path") == configured_login_path
                ]
            candidates_to_try = eligible_candidates[:Signin.MAX_LOGIN_CANDIDATES]
        elif configuration.get("explicit_login_endpoint") or not candidates:
            configured_path = configuration.get("login_endpoint")
            if not configured_path:
                try:
                    token_info = self._signin_once(target, configuration)
                except (LoginConfigurationError, LoginError) as exc:
                    discovery["login_attempt_status"] = "unavailable"
                    raise LoginError(str(exc), status_code=exc.status_code) from exc
                discovery["login_attempt_status"] = "succeeded"
                discovery["token_or_session_detected"] = bool(
                    token_info.get("token") or token_info.get("cookie")
                )
                return token_info
            candidates_to_try = [
                {
                    "method": configuration.get("method", "POST"),
                    "path": configured_path,
                    "evidence_source": ["explicit_configuration"],
                }
            ]
        else:
            candidates_to_try = candidates[:Signin.MAX_LOGIN_CANDIDATES]

        last_status = None
        for candidate in candidates_to_try:
            discovery["selected_login_route"] = candidate["path"]
            discovery["selected_login_method"] = candidate.get("method", "POST")
            discovery["selected_login_evidence_source"] = candidate.get(
                "evidence_source", []
            )
            candidate_configuration = {
                **configuration,
                "login_endpoint": (
                    configuration.get("login_endpoint")
                    if configuration.get("explicit_login_endpoint")
                    else candidate["path"]
                ),
                "method": candidate.get("method", "POST"),
            }
            candidate_contract = configuration.get(
                "_candidate_configurations", {}
            ).get(candidate["path"])
            if candidate_contract:
                candidate_configuration.update(candidate_contract)
            try:
                token_info = self._signin_once(target, candidate_configuration)
            except LoginConfigurationError as exc:
                logger.info(
                    "Login candidate not attempted | method=%s | route=%s | reason=%s",
                    candidate_configuration["method"],
                    candidate["path"],
                    str(exc),
                )
                discovery["login_attempts"].append(
                    {
                        "method": candidate_configuration["method"],
                        "path": candidate["path"],
                        "status": "not_attempted",
                        "reason": str(exc),
                    }
                )
                break
            except LoginError as exc:
                last_status = exc.status_code
                logger.info(
                    "Login candidate failed | method=%s | route=%s | http_status=%s | reason=%s",
                    candidate_configuration["method"],
                    candidate["path"],
                    exc.status_code if exc.status_code is not None else "unavailable",
                    str(exc),
                )
                discovery["login_attempts"].append(
                    {
                        "method": candidate_configuration["method"],
                        "path": candidate["path"],
                        "status": "failed",
                        "http_status": exc.status_code,
                        "reason": str(exc),
                    }
                )
                continue

            discovery["login_attempts"].append(
                {
                    "method": candidate_configuration["method"],
                    "path": candidate["path"],
                    "status": "succeeded",
                    "http_status": token_info.get("http_status"),
                }
            )
            discovery["login_attempt_status"] = "succeeded"
            discovery["token_or_session_detected"] = bool(
                token_info.get("token") or token_info.get("cookie")
            )
            return token_info

        discovery["login_attempt_status"] = (
            "failed"
            if any(item.get("status") == "failed" for item in discovery["login_attempts"])
            else "unavailable"
        )
        if not candidates_to_try:
            reason = "No eligible login candidate was found; valid-token testing was skipped."
        else:
            attempt_details = [
                f"{item['method']} {item['path']}: "
                f"{item.get('reason') or item.get('status', 'not attempted')}"
                for item in discovery["login_attempts"]
            ]
            reason = (
                "Automatic login failed or could not run for eligible candidates within the "
                f"{Signin.MAX_LOGIN_CANDIDATES}-request limit; no token or session was available. "
                + "; ".join(attempt_details)
            )
        raise LoginError(reason, status_code=last_status)

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
    def _evidence_traversal_limit(cls):
        configured = os.environ.get("MICROSCAN_EVIDENCE_TRAVERSAL_LIMIT", "").strip()
        if not configured:
            return cls.MAX_EVIDENCE_RECORDS
        try:
            limit = int(configured)
        except ValueError as exc:
            raise ValueError(
                "MICROSCAN_EVIDENCE_TRAVERSAL_LIMIT must be an integer between "
                f"1 and {cls.MAX_EVIDENCE_TRAVERSAL_LIMIT}."
            ) from exc
        if not 1 <= limit <= cls.MAX_EVIDENCE_TRAVERSAL_LIMIT:
            raise ValueError(
                "MICROSCAN_EVIDENCE_TRAVERSAL_LIMIT must be an integer between "
                f"1 and {cls.MAX_EVIDENCE_TRAVERSAL_LIMIT}."
            )
        return limit

    @classmethod
    def _body_evidence(cls, response):
        traversal_limit = cls._evidence_traversal_limit()
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
        resource_identifiers = []
        owner_identity_fingerprints = []
        pagination = {
            "detected": False,
            "markers": [],
            "has_more": None,
            "next_page_available": False,
            "current_page": None,
            "total_pages": None,
        }
        error_payload_observed = False
        visited_nodes = 0
        traversal_truncated = body_too_large
        evidence_limitations = []
        if body_too_large:
            evidence_limitations.append("response_exceeded_evidence_parse_limit")
        pagination_keys = {
            "hasmore",
            "has_more",
            "next",
            "nextpage",
            "next_page",
            "nextcursor",
            "next_cursor",
            "currentpage",
            "current_page",
            "pagenumber",
            "page_number",
            "totalpages",
            "total_pages",
        }

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
                if "json_node_traversal_limit" not in evidence_limitations:
                    evidence_limitations.append("json_node_traversal_limit")
                return
            visited_nodes += 1

            if isinstance(value, dict):
                for key, child in value.items():
                    if not isinstance(key, str):
                        continue
                    normalized_key = key.lower().replace("-", "_")
                    if normalized_key in pagination_keys:
                        pagination["detected"] = True
                        if normalized_key not in pagination["markers"]:
                            pagination["markers"].append(normalized_key)
                        if normalized_key in {"hasmore", "has_more"} and isinstance(child, bool):
                            pagination["has_more"] = child
                        elif normalized_key in {"next", "nextpage", "next_page", "nextcursor", "next_cursor"}:
                            pagination["next_page_available"] = child not in (None, "", False)
                        elif normalized_key in {"currentpage", "current_page", "pagenumber", "page_number"} and isinstance(child, int):
                            pagination["current_page"] = child
                        elif normalized_key in {"totalpages", "total_pages"} and isinstance(child, int):
                            pagination["total_pages"] = child
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
                if not parent_is_error and not is_error_object and record_shape:
                    if len(resource_records) >= traversal_limit:
                        traversal_truncated = True
                        if "resource_record_sample_limit" not in evidence_limitations:
                            evidence_limitations.append("resource_record_sample_limit")
                    else:
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
                        for key, child in record_fields:
                            normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
                            if normalized_key not in cls._OWNER_IDENTITY_FIELDS:
                                continue
                            fingerprint = cls._owner_fingerprint(child)
                            if fingerprint is None:
                                continue
                            owner_evidence = {
                                "field": key[:64],
                                "fingerprint": fingerprint,
                                "path": path[:160],
                            }
                            if owner_evidence not in owner_identity_fingerprints:
                                owner_identity_fingerprints.append(owner_evidence)
                        for key, child in record_fields:
                            normalized_key = key.lower().replace("_", "")
                            if not (
                                normalized_key in cls._RESOURCE_IDENTIFIER_FIELDS
                                or normalized_key.endswith(cls._RESOURCE_IDENTIFIER_SUFFIXES)
                            ):
                                continue
                            if isinstance(child, bool) or not isinstance(child, (str, int)):
                                continue
                            identifier = str(child).strip()
                            if (
                                not identifier
                                or len(identifier) > 128
                                or any(ord(character) < 32 for character in identifier)
                            ):
                                continue
                            if (
                                len(resource_identifiers)
                                >= traversal_limit * 10
                            ):
                                traversal_truncated = True
                                if "resource_identifier_limit" not in evidence_limitations:
                                    evidence_limitations.append("resource_identifier_limit")
                                break
                            item = {
                                "field": key[:64],
                                "value": identifier,
                                "path": path[:160],
                            }
                            if item not in resource_identifiers:
                                resource_identifiers.append(item)
                            if len(resource_identifiers) >= traversal_limit * 10:
                                traversal_truncated = True
                                if "resource_identifier_limit" not in evidence_limitations:
                                    evidence_limitations.append("resource_identifier_limit")
                                break

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
                for index, child in enumerate(value[:traversal_limit]):
                    walk(child, f"{path}[{index}]", parent_is_error, True)
                if len(value) > traversal_limit:
                    traversal_truncated = True
                    if "array_item_traversal_limit" not in evidence_limitations:
                        evidence_limitations.append("array_item_traversal_limit")

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
            "response_body_over_evidence_limit": body_too_large,
            "evidence_limitations": evidence_limitations,
            "evidence_traversal_limit": traversal_limit,
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
            "resource_identifiers": resource_identifiers,
            "owner_identity_fingerprints": owner_identity_fingerprints,
            "pagination": pagination,
            "empty_collection_observed": bool(empty_collection_paths),
            "empty_collection_paths": empty_collection_paths[
                : traversal_limit
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

    def _active_bola_test_results(
        self,
        target,
        collection_path,
        resource_type,
        route_templates,
        responses,
        authenticated_evidence,
        authenticated_headers,
        budget_state,
    ):
        from module.bola_analysis import BolaAnalyzer

        baseline_status, baseline_reason = (
            BolaAnalyzer._baseline_status(authenticated_evidence)
            if isinstance(authenticated_evidence, dict)
            else (
                "unavailable",
                "No authenticated collection response was captured.",
            )
        )
        baseline_identifiers = (
            BolaAnalyzer._typed_identifiers(authenticated_evidence, resource_type)
            if isinstance(authenticated_evidence, dict)
            else []
        )
        baseline_ids = {
            item["value"]
            for item in baseline_identifiers
            if item.get("resource_type") == resource_type
        }
        baseline_owner_fingerprints = {
            item["fingerprint"]
            for item in (
                authenticated_evidence.get("owner_identity_fingerprints", [])
                if isinstance(authenticated_evidence, dict)
                else []
            )
            if isinstance(item, dict)
            and isinstance(item.get("fingerprint"), str)
        }
        baseline_owner_established = len(baseline_owner_fingerprints) == 1

        observed_ids = []
        for response in responses.values():
            evidence = self._response_evidence(response)
            for identifier in BolaAnalyzer._typed_identifiers(evidence, resource_type):
                if (
                    identifier.get("resource_type") == resource_type
                    and identifier["value"] not in observed_ids
                ):
                    observed_ids.append(identifier["value"])
        for route in route_templates:
            if route.get("collection_path") != collection_path:
                continue
            for identifier in route.get("observed_identifiers", []):
                if (
                    isinstance(identifier, str)
                    and identifier not in observed_ids
                ):
                    observed_ids.append(identifier)
        if isinstance(authenticated_evidence, dict):
            for identifier in baseline_identifiers:
                if (
                    identifier.get("resource_type") == resource_type
                    and identifier["value"] not in observed_ids
                ):
                    observed_ids.append(identifier["value"])

        candidates = []
        for identifier in sorted(
            observed_ids,
            key=lambda value: (value in baseline_ids, observed_ids.index(value)),
        ):
            for route in route_templates:
                if route.get("collection_path") != collection_path:
                    continue
                candidate_path = route["template"].replace(
                    route["placeholder"], quote(identifier, safe="")
                )
                if any(item["path"] == candidate_path for item in candidates):
                    continue
                candidates.append(
                    {
                        "method": "GET",
                        "path": candidate_path,
                        "route_template": route["template"],
                        "identifier_out_of_baseline": identifier not in baseline_ids,
                        "baseline_status": baseline_status,
                    }
                )
                if len(candidates) >= self.MAX_ACTIVE_BOLA_CANDIDATES:
                    break
            if len(candidates) >= self.MAX_ACTIVE_BOLA_CANDIDATES:
                break

        if not candidates:
            reason = (
                "Authenticated session is unavailable; no detail request was sent."
                if not isinstance(authenticated_headers, dict)
                else "The authenticated collection baseline is unavailable."
                if baseline_status == "unavailable"
                else "No identifiers were observed in captured responses."
                if not observed_ids
                else "No discovered detail-route template matched this collection."
            )
            return [
                {
                    "test_type": "active_bola_detail",
                    "method": "GET",
                    "path": collection_path,
                    "selected": False,
                    "sent": False,
                    "response_received": False,
                    "http_status": None,
                    "content_type": None,
                    "outcome": "not_attempted",
                    "assessment": "inconclusive",
                    "baseline_status": baseline_status,
                    "reason": reason,
                    "baseline_limitation": baseline_reason,
                    "request_budget": {
                        "configured": budget_state["configured"],
                        "used": budget_state["used"],
                        "remaining": max(
                            budget_state["configured"] - budget_state["used"],
                            0,
                        ),
                    },
                }
            ]

        results = []
        for candidate in candidates:
            selected = (
                isinstance(authenticated_headers, dict)
                and baseline_status in {"complete", "partial"}
                and budget_state["used"] < budget_state["configured"]
            )
            if not isinstance(authenticated_headers, dict):
                reason = "Authenticated session is unavailable; no detail request was sent."
                outcome = "not_attempted"
            elif baseline_status not in {"complete", "partial"}:
                reason = (
                    "Authenticated collection baseline is unavailable; comparison would "
                    "not be reliable."
                )
                outcome = "not_attempted"
            elif not selected:
                reason = "The BOLA-specific request budget is exhausted."
                outcome = "not_attempted"
            else:
                reason = None
                outcome = "request_sent"

            record = {
                "test_type": "active_bola_detail",
                "method": candidate["method"],
                "path": candidate["path"],
                "route_template": candidate["route_template"],
                "selected": selected,
                "sent": False,
                "response_received": False,
                "http_status": None,
                "content_type": None,
                "outcome": outcome,
                "assessment": "inconclusive",
                "baseline_status": candidate["baseline_status"],
                "identifier_comparison": (
                    "out_of_observed_baseline"
                    if candidate["identifier_out_of_baseline"]
                    else "in_observed_baseline"
                ),
                "reason": reason,
                "baseline_limitation": baseline_reason,
            }
            if selected:
                budget_state["used"] += 1
                record["sent"] = True
                try:
                    url = self._scope_url(target, candidate["path"])
                    response = self._run_http_request(
                        "GET",
                        url,
                        headers=authenticated_headers,
                    )
                except httpx.TimeoutException:
                    record.update(
                        {
                            "outcome": "request_timeout",
                            "reason": "Authenticated detail request timed out.",
                        }
                    )
                except httpx.RequestError:
                    record.update(
                        {
                            "outcome": "request_error",
                            "reason": "Authenticated detail request failed to reach the local target.",
                        }
                    )
                else:
                    detail_evidence = self._response_evidence(response)
                    status_code = detail_evidence["status_code"]
                    content_type = detail_evidence["content_type"]
                    response_owner_fields = [
                        {
                            "field": item["field"],
                            "fingerprint": item["fingerprint"],
                        }
                        for item in detail_evidence.get(
                            "owner_identity_fingerprints", []
                        )
                        if isinstance(item, dict)
                        and isinstance(item.get("field"), str)
                        and isinstance(item.get("fingerprint"), str)
                    ]
                    response_owner_fingerprints = {
                        item["fingerprint"] for item in response_owner_fields
                    }
                    owner_relation = "identity_unavailable"
                    if baseline_owner_established and response_owner_fingerprints:
                        if response_owner_fingerprints == baseline_owner_fingerprints:
                            owner_relation = "matches_authenticated_baseline"
                        elif response_owner_fingerprints.isdisjoint(
                            baseline_owner_fingerprints
                        ):
                            owner_relation = "differs_from_authenticated_baseline"
                    object_returned = bool(
                        200 <= status_code < 300
                        and detail_evidence["response_is_json"]
                        and detail_evidence["resource_records_observed"]
                        and not detail_evidence["authentication_denied"]
                    )
                    record.update(
                        {
                            "response_received": True,
                            "http_status": status_code,
                            "content_type": content_type,
                            "outcome": (
                                "object_response"
                                if object_returned
                                else "response_received"
                            ),
                            "assessment": (
                                "confirmed"
                                if object_returned
                                and candidate["identifier_out_of_baseline"]
                                and owner_relation
                                == "differs_from_authenticated_baseline"
                                else "not_detected"
                                if object_returned
                                and owner_relation
                                == "matches_authenticated_baseline"
                                else "potential"
                                if object_returned
                                and candidate["identifier_out_of_baseline"]
                                else "not_detected"
                                if status_code in {401, 403, 404}
                                else "inconclusive"
                            ),
                            "owner_identity_evidence": {
                                "comparison": owner_relation,
                                "authenticated_baseline_established": (
                                    baseline_owner_established
                                ),
                                "authenticated_baseline_fingerprints": sorted(
                                    baseline_owner_fingerprints
                                ),
                                "response_fields": response_owner_fields,
                            },
                            "reason": (
                                "An authenticated request for an identifier absent from the "
                                "observed collection baseline returned a JSON resource object "
                                "whose owner field differs from the consistent owner identity "
                                "in the authenticated collection baseline."
                                if object_returned
                                and candidate["identifier_out_of_baseline"]
                                and owner_relation
                                == "differs_from_authenticated_baseline"
                                else
                                "An authenticated request for an identifier absent from the "
                                "observed collection baseline returned a JSON resource object. "
                                "This is potential evidence only; authorization policy and "
                                "resource ownership were not established."
                                if object_returned
                                and candidate["identifier_out_of_baseline"]
                                else "The response did not establish unauthorized object access."
                            ),
                        }
                    )
            results.append(record)
        request_budget = {
            "configured": budget_state["configured"],
            "used": budget_state["used"],
            "remaining": max(
                budget_state["configured"] - budget_state["used"],
                0,
            ),
        }
        for result in results:
            result["request_budget"] = request_budget
        return results

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
                "response_body_over_evidence_limit",
                "evidence_limitations",
                "evidence_traversal_limit",
                "body_summary_limit_bytes",
                "authorization_denial_detected",
                "http_status_denial",
                "body_denial_signal",
                "error_payload_observed",
                "resource_records_observed",
                "resource_record_count_observed",
                "resource_record_sample_count",
                "resource_record_samples",
                "resource_identifiers",
                "owner_identity_fingerprints",
                "pagination",
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
        public_login_candidates = [
            {
                "method": item.get("method"),
                "path": item.get("path"),
                "discovery_status": item.get("discovery_status"),
                "evidence_source": item.get("evidence_source", []),
                "allow_header_methods": item.get("allow_header_methods", []),
                "request_content_type": item.get("request_content_type"),
            }
            for item in login_candidates
        ]
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
            "discovered_login_endpoints": public_login_candidates,
            "authentication_mechanism": "unknown",
            "login_discovery_status": "found" if login_candidates else "not_found",
            "login_attempt_status": "not_attempted",
            "authentication_result": "unavailable",
            "token_or_session_detected": False,
            "selected_login_route": None,
            "selected_login_method": None,
            "selected_login_evidence_source": [],
            "login_attempts": [],
            "note": "Login discovery and authentication are independent of API discovery.",
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
        authenticated_headers = None
        try:
            auth_config, discovered_login_candidates, configuration_note = (
                Signin.configured_auth(discovered_endpoints)
            )
            discovery["discovered_login_endpoints"] = [
                {
                    "method": item.get("method"),
                    "path": item.get("path"),
                    "discovery_status": item.get("discovery_status"),
                    "evidence_source": item.get("evidence_source", []),
                    "allow_header_methods": item.get("allow_header_methods", []),
                    "request_content_type": item.get("request_content_type"),
                }
                for item in discovered_login_candidates
            ]
            discovery["login_discovery_status"] = (
                "found" if discovered_login_candidates else "not_found"
            )
            if auth_config is None:
                authenticated_check["reason"] = configuration_note
                discovery["login_attempt_status"] = "unavailable"
                logger.info(
                    "Login executor not called | candidates=%d | selected_route=none | "
                    "reason=%s",
                    len(discovered_login_candidates),
                    configuration_note,
                )
            else:
                logger.info(
                    "Login executor ready | candidates=%d | "
                    "request_limit=%d",
                    len(discovered_login_candidates),
                    Signin.MAX_LOGIN_CANDIDATES,
                )
                token_info = self._signin_candidates(
                    target,
                    auth_config,
                    discovered_login_candidates,
                    discovery,
                )
                token = token_info.pop("token")
                cookie = token_info.pop("cookie", None)
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
                if not scheme and not cookie:
                    authenticated_check["reason"] = (
                        "Login succeeded and a token was obtained, but the API did not provide "
                        "an authorization scheme. Configure auth_scheme in MICROSCAN_AUTH_CONFIG."
                    )
                elif not cookie and not re.fullmatch(
                    r"[A-Za-z0-9-]+", token_info["auth_header"]
                ):
                    authenticated_check["reason"] = (
                        "Login succeeded, but configured auth_header is invalid."
                    )
                else:
                    authenticated_headers = (
                        {"Cookie": cookie}
                        if cookie
                        else {
                            token_info["auth_header"]: f"{scheme} {token}"
                        }
                    )
                    try:
                        response = self._run_http_request(
                            method,
                            url,
                            headers=authenticated_headers,
                        )
                        responses["authenticated"] = response
                        authenticated_check = {
                            "status": "tested",
                            "request_attempted": True,
                            "reason": (
                                "Login returned a session cookie; the cookie was used for "
                                "the protected-endpoint request."
                                if cookie
                                else self._authenticated_probe_reason(scheme_source)
                            ),
                            "login_status": token_info["http_status"],
                            "auth_scheme_source": scheme_source,
                            "login_response_content_type": token_info[
                                "response_content_type"
                            ],
                            "evidence": self._response_evidence(response),
                        }
                        if authenticated_check["evidence"].get("status_code") == 401:
                            discovery["authentication_result"] = "failed"
                        elif authenticated_check["evidence"].get("status_code") == 403:
                            discovery["authentication_result"] = "inconclusive"
                        elif authenticated_check["evidence"].get("authentication_denied"):
                            discovery["authentication_result"] = "inconclusive"
                        elif authenticated_check["evidence"].get("protected_data_observed"):
                            discovery["authentication_result"] = "success"
                        else:
                            discovery["authentication_result"] = "inconclusive"
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
            discovery["login_attempt_status"] = "unavailable"
            authenticated_check = {
                "status": "error",
                "request_attempted": False,
                "reason": str(exc),
                "evidence": None,
            }
        except LoginError as exc:
            discovery["login_attempt_status"] = (
                "failed"
                if any(
                    item.get("status") == "failed"
                    for item in discovery["login_attempts"]
                )
                else "unavailable"
            )
            discovery["authentication_result"] = (
                "failed"
                if discovery["login_attempt_status"] == "failed"
                else "unavailable"
            )
            authenticated_check = {
                "status": "error",
                "request_attempted": False,
                "reason": str(exc),
                "login_status": exc.status_code,
                "evidence": None,
            }
        finally:
            token = None

        active_bola_tests = []
        active_bola_context = selected_endpoint.get("active_bola_context")
        if isinstance(active_bola_context, dict):
            active_bola_tests = self._active_bola_test_results(
                target=target,
                collection_path=active_bola_context["collection_path"],
                resource_type=active_bola_context["resource_type"],
                route_templates=active_bola_context["route_templates"],
                responses=responses,
                authenticated_evidence=authenticated_check.get("evidence"),
                authenticated_headers=(
                    authenticated_headers
                    if authenticated_check.get("status") == "tested"
                    and isinstance(authenticated_check.get("evidence"), dict)
                    and authenticated_check["evidence"].get("status_code")
                    not in {401, 403}
                    else None
                ),
                budget_state=active_bola_context["budget_state"],
            )

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
                            "response_body_over_evidence_limit",
                            "evidence_limitations",
                            "evidence_traversal_limit",
                            "body_summary_limit_bytes",
                            "authorization_denial_detected",
                            "http_status_denial",
                            "body_denial_signal",
                            "error_payload_observed",
                            "resource_records_observed",
                            "resource_record_count_observed",
                            "resource_record_sample_count",
                            "resource_record_samples",
                            "resource_identifiers",
                            "owner_identity_fingerprints",
                            "pagination",
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
                "active_bola_tests": active_bola_tests,
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
