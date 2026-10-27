import hashlib
import json
import logging
import re
from urllib.parse import urlsplit

from module.authentication_test import AuthenticationTest
from module.endpoint_selection import EndpointSelector


logger = logging.getLogger(__name__)


class BolaAnalyzer:
    """Correlate already captured response identifiers; this module sends no requests."""

    ID_SEGMENT = re.compile(
        r"(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*)$",
        re.IGNORECASE,
    )
    SELF_SEGMENTS = {"me", "self", "current", "profile"}
    GENERIC_ID_FIELDS = {"id", "_id", "uuid", "guid", "resourceid"}
    WRAPPER_SEGMENTS = {"data", "result", "payload", "response"}
    COLLECTION_TYPES = {"user", "account", "post", "order", "product", "item", "project"}

    def __init__(self, endpoint_selector=None):
        self.endpoint_selector = endpoint_selector or EndpointSelector()

    @staticmethod
    def _type_name(value):
        normalized = re.sub(r"[^a-z0-9]", "", str(value).lower())
        if normalized.endswith("ies") and len(normalized) > 3:
            return normalized[:-3] + "y"
        if normalized.endswith("s") and not normalized.endswith("ss"):
            return normalized[:-1]
        return normalized

    @classmethod
    def _resource_route(cls, endpoint):
        path = endpoint.get("path") or endpoint.get("target") or ""
        if not isinstance(path, str):
            return None
        try:
            parsed = urlsplit(path)
        except ValueError:
            return None
        if parsed.query or parsed.fragment:
            return None
        segments = [segment for segment in parsed.path.strip("/").split("/") if segment]
        if not segments or any("${" in segment or "{" in segment or "}" in segment for segment in segments):
            return None

        last = segments[-1]
        if cls.ID_SEGMENT.fullmatch(last):
            if len(segments) < 2:
                return None
            collection_segments = segments[:-1]
            requested_id = last
            is_collection = False
        elif last.lower() in cls.SELF_SEGMENTS:
            if len(segments) < 2:
                return None
            collection_segments = segments[:-1]
            requested_id = None
            is_collection = False
        else:
            collection_segments = segments
            requested_id = None
            is_collection = True

        resource_segment = collection_segments[-1]
        resource_type = cls._type_name(resource_segment)
        collection_path = "/" + "/".join(collection_segments)
        return {
            "path": parsed.path or "/",
            "collection_path": collection_path,
            "resource_type": resource_type,
            "requested_id": requested_id,
            "is_collection": is_collection,
        }

    @staticmethod
    def _response_evidence(endpoint):
        for result in endpoint.get("test_results", []) or []:
            if not isinstance(result, dict) or result.get("test_module") != "jwt_authentication":
                continue
            check = result.get("authenticated_check")
            evidence = check.get("evidence") if isinstance(check, dict) else None
            if isinstance(evidence, dict):
                return evidence
            for case in result.get("test_cases", []) or []:
                if (
                    isinstance(case, dict)
                    and case.get("test_case") == "valid_token"
                    and case.get("request_attempted")
                    and isinstance(case.get("evidence"), dict)
                ):
                    return case["evidence"]
        return None

    @classmethod
    def _evidence_diagnostic(cls, endpoint, evidence):
        jwt_result = next(
            (
                result
                for result in endpoint.get("test_results", []) or []
                if isinstance(result, dict)
                and result.get("test_module") == "jwt_authentication"
            ),
            {},
        )
        authenticated_check = jwt_result.get("authenticated_check")
        authenticated_check = (
            authenticated_check if isinstance(authenticated_check, dict) else None
        )
        valid_case = next(
            (
                case
                for case in jwt_result.get("test_cases", []) or []
                if isinstance(case, dict) and case.get("test_case") == "valid_token"
            ),
            {},
        )
        request_attempted = (
            authenticated_check.get("request_attempted")
            if authenticated_check
            else None
        )
        if request_attempted is None:
            request_attempted = valid_case.get("request_attempted")
        discovery = jwt_result.get("discovery")
        discovery = discovery if isinstance(discovery, dict) else {}
        login_status = discovery.get("login_attempt_status")
        token_detected = discovery.get("token_or_session_detected")
        if request_attempted or isinstance(evidence, dict):
            authentication_available = True
        elif isinstance(token_detected, bool):
            authentication_available = token_detected
        elif login_status in {"failed", "unavailable"}:
            authentication_available = False
        else:
            authentication_available = None
        unauthenticated_statuses = [
            check.get("status_code")
            for check in jwt_result.get("unauthenticated_checks", []) or []
            if isinstance(check, dict) and isinstance(check.get("status_code"), int)
        ]
        status = evidence.get("status_code") if isinstance(evidence, dict) else None
        content_type = (
            evidence.get("content_type") if isinstance(evidence, dict) else None
        )
        selection_reason = (
            endpoint.get("jwt_selection_reason")
            or jwt_result.get("endpoint_selection_reason")
            or jwt_result.get("reason")
        )

        if isinstance(evidence, dict):
            response_status = status
            if isinstance(response_status, str) and response_status.isdigit():
                response_status = int(response_status)
            if response_status in {401, 403}:
                capture_outcome = "captured_authenticated_denial"
                skip_reason = "authenticated_response_denied"
            elif response_status == 404:
                capture_outcome = "captured_authenticated_not_found"
                skip_reason = "authenticated_response_not_found"
            elif not isinstance(response_status, int) or not 200 <= response_status < 300:
                capture_outcome = "captured_unsuccessful_authenticated_response"
                skip_reason = "authenticated_response_not_successful"
            elif not evidence.get("response_is_json"):
                capture_outcome = "captured_non_json_response"
                skip_reason = "response_not_json"
            elif evidence.get("error_payload_observed"):
                capture_outcome = "captured_json_error_response"
                skip_reason = "error_payload_not_correlated"
            elif not evidence.get("resource_records_observed"):
                capture_outcome = "captured_json_without_resource_record"
                skip_reason = "no_resource_record_in_response"
            else:
                capture_outcome = "captured_json_resource_evidence"
                skip_reason = None
            request_outcome = "response_captured"
        elif endpoint.get("jwt_selected") is False:
            capture_outcome = "authenticated_request_not_sent"
            request_outcome = "not_attempted"
            selection_text = str(selection_reason or "").lower()
            if "grouped with representative" in selection_text:
                skip_reason = "grouped_with_representative_route"
            elif "limited to" in selection_text:
                skip_reason = "automatic_selection_budget"
            else:
                skip_reason = "not_selected_for_authenticated_check"
        elif request_attempted:
            capture_outcome = "authenticated_request_failed_or_evidence_missing"
            request_outcome = (
                "request_failed"
                if authenticated_check and authenticated_check.get("status") == "error"
                else "response_evidence_missing"
            )
            skip_reason = (
                "authenticated_request_error"
                if request_outcome == "request_failed"
                else "authenticated_response_evidence_missing"
            )
        elif authenticated_check:
            capture_outcome = "authenticated_request_not_sent"
            if login_status in {"failed", "unavailable"}:
                request_outcome = "authentication_unavailable"
            else:
                request_outcome = "not_attempted"
            if login_status == "failed":
                skip_reason = "login_failed_no_authenticated_request"
            elif login_status == "unavailable":
                skip_reason = "login_unavailable_no_authenticated_request"
            else:
                skip_reason = "authentication_unavailable_or_request_not_attempted"
        else:
            capture_outcome = "no_authenticated_check_recorded"
            request_outcome = "not_attempted"
            skip_reason = "no_authenticated_check_recorded"

        return {
            "http_status": status,
            "content_type": content_type,
            "authentication_available": authentication_available,
            "authenticated_request_attempted": bool(request_attempted),
            "request_outcome": request_outcome,
            "jwt_selected": endpoint.get("jwt_selected"),
            "selection_reason": selection_reason,
            "login_attempt_status": login_status,
            "capture_outcome": capture_outcome,
            "skip_reason": skip_reason,
            "unauthenticated_statuses": unauthenticated_statuses,
        }

    @classmethod
    def _log_evidence_diagnostic(cls, endpoint, evidence):
        diagnostic = cls._evidence_diagnostic(endpoint, evidence)
        logger.info(
            "Passive BOLA response evidence | endpoint=%s | method=%s | "
            "request_outcome=%s | http_status=%s | content_type=%s | authentication_available=%s | "
            "authenticated_request_attempted=%s | "
            "evidence_capture=%s | skip_reason=%s | unauthenticated_statuses=%s",
            endpoint.get("path") or endpoint.get("target") or "/",
            str(endpoint.get("method") or "UNKNOWN").upper(),
            diagnostic["request_outcome"],
            diagnostic["http_status"] or "unavailable",
            diagnostic["content_type"] or "unavailable",
            (
                str(diagnostic["authentication_available"]).lower()
                if diagnostic["authentication_available"] is not None
                else "unknown"
            ),
            str(diagnostic["authenticated_request_attempted"]).lower(),
            diagnostic["capture_outcome"],
            diagnostic["skip_reason"] or "none",
            diagnostic["unauthenticated_statuses"],
        )

    @classmethod
    def _typed_identifiers(cls, evidence, route_type):
        identifiers = []
        for item in evidence.get("resource_identifiers", []) or []:
            if not isinstance(item, dict):
                continue
            field = item.get("field")
            value = item.get("value")
            if not isinstance(field, str) or not isinstance(value, (str, int)):
                continue
            normalized_field = field.lower().replace("_", "")
            if normalized_field in cls.GENERIC_ID_FIELDS:
                evidence_path = item.get("path")
                parent_match = (
                    re.search(r"\.([A-Za-z][A-Za-z0-9_-]*)(?:\[\d+\])?$", evidence_path)
                    if isinstance(evidence_path, str)
                    else None
                )
                parent_type = (
                    cls._type_name(parent_match.group(1))
                    if parent_match
                    else ""
                )
                resource_type = (
                    parent_type
                    if parent_type and parent_type not in cls.WRAPPER_SEGMENTS
                    else route_type
                )
            else:
                prefix = normalized_field
                for suffix in ("uuid", "guid", "id"):
                    if prefix.endswith(suffix):
                        prefix = prefix[: -len(suffix)]
                        break
                resource_type = cls._type_name(prefix) if prefix else route_type
            identifiers.append(
                {
                    "field": field[:64],
                    "value": str(value)[:128],
                    "resource_type": resource_type or route_type,
                }
            )
        return identifiers

    @classmethod
    def _baseline_status(cls, evidence):
        pagination = evidence.get("pagination")
        pagination = pagination if isinstance(pagination, dict) else {}
        status_code = evidence.get("status_code")
        if isinstance(status_code, str) and status_code.isdigit():
            status_code = int(status_code)
        if not isinstance(status_code, int) or not 200 <= status_code < 300:
            return "unavailable", "The captured response did not have a successful HTTP status."
        limitations = evidence.get("evidence_limitations")
        limitations = limitations if isinstance(limitations, list) else []
        if (
            evidence.get("response_body_over_evidence_limit")
            or "response_exceeded_evidence_parse_limit" in limitations
        ):
            return (
                "partial",
                "Response content exceeded the evidence parsing limit; JSON was not fully analyzed and wire-level truncation is unknown.",
            )
        if not evidence.get("response_is_json") or not evidence.get("body_available"):
            return "unavailable", "No complete JSON response body was captured."
        if evidence.get("error_payload_observed"):
            return "unavailable", "The captured response resembles a generic error payload."
        if not evidence.get("resource_records_observed"):
            return "unavailable", "No resource-shaped objects were present in the captured response."
        if evidence.get("body_summary_partial") or evidence.get("body_truncated"):
            reason_map = {
                "array_item_traversal_limit": (
                    f"Resource arrays were intentionally limited to the first "
                    f"{evidence.get('evidence_traversal_limit', AuthenticationTest.MAX_EVIDENCE_RECORDS)} items during evidence traversal."
                ),
                "json_node_traversal_limit": (
                    f"JSON evidence traversal reached the "
                    f"{AuthenticationTest.MAX_EVIDENCE_NODES}-node limit."
                ),
                "resource_record_sample_limit": (
                    f"Resource record samples were limited to "
                    f"{evidence.get('evidence_traversal_limit', AuthenticationTest.MAX_EVIDENCE_RECORDS)} records."
                ),
                "resource_identifier_limit": "Resource identifier capture reached its configured bound.",
            }
            details = [
                reason_map[reason]
                for reason in limitations
                if reason in reason_map
            ]
            return (
                "partial",
                " ".join(details)
                if details
                else "Evidence traversal or summary was limited; the captured body is not known to be wire-truncated.",
            )
        if not evidence.get("resource_identifiers"):
            return "partial", "Resource objects were observed, but no recognized identifiers were captured."
        if pagination.get("detected"):
            current_page = pagination.get("current_page")
            total_pages = pagination.get("total_pages")
            explicitly_complete = (
                pagination.get("has_more") is False
                or isinstance(current_page, int)
                and isinstance(total_pages, int)
                and current_page >= total_pages
            )
            if pagination.get("next_page_available") or pagination.get("has_more") is True:
                return "partial", "Pagination indicates additional collection data was not captured."
            if not explicitly_complete:
                return "partial", "Pagination metadata was observed but completeness is not established."
        return "complete", "Captured collection response was parseable and had no unresolved pagination marker."

    @staticmethod
    def _request_reference(endpoint):
        method = str(endpoint.get("method") or "UNKNOWN").upper()
        path = endpoint.get("path") or "/"
        return f"valid_token {method} {path}"

    @staticmethod
    def _response_fingerprint(evidence):
        if not isinstance(evidence, dict):
            return None
        safe_summary = {
            key: evidence.get(key)
            for key in (
                "status_code",
                "content_type",
                "json_keys",
                "resource_record_samples",
                "resource_identifiers",
                "pagination",
            )
            if key in evidence
        }
        encoded = json.dumps(safe_summary, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def analyze(self, endpoints):
        baselines_by_path = {}
        baselines = []
        details = []
        endpoint_routes = []

        for endpoint in endpoints or []:
            if not isinstance(endpoint, dict):
                continue
            classification = endpoint.get("classification") or self.endpoint_selector.classify_endpoint(
                endpoint
            )["classification"]
            if classification not in {
                "resource_collection",
                "resource_by_id",
                "user_or_account",
            }:
                continue
            route = self._resource_route(endpoint)
            if route is None:
                continue
            endpoint_routes.append((endpoint, classification, route))
            evidence = self._response_evidence(endpoint)
            self._log_evidence_diagnostic(endpoint, evidence)
            if not route["is_collection"] or route["resource_type"] not in self.COLLECTION_TYPES:
                continue

            status, status_reason = (
                self._baseline_status(evidence)
                if isinstance(evidence, dict)
                else ("unavailable", "No authenticated response evidence was captured by existing tests.")
            )
            identifiers = (
                self._typed_identifiers(evidence, route["resource_type"])
                if isinstance(evidence, dict)
                else []
            )
            identifiers = [
                item
                for item in identifiers
                if item["resource_type"] == route["resource_type"]
            ]
            baseline = {
                "method": endpoint.get("method"),
                "collection_endpoint": route["path"],
                "request_reference": self._request_reference(endpoint),
                "http_status": evidence.get("status_code") if evidence else None,
                "content_type": evidence.get("content_type") if evidence else None,
                "response_diagnostic": self._evidence_diagnostic(endpoint, evidence),
                "response_fingerprint": self._response_fingerprint(evidence),
                "resource_type": route["resource_type"],
                "identifiers": identifiers,
                "record_count_observed": (
                    evidence.get("resource_record_count_observed")
                    if evidence
                    else None
                ),
                "pagination": evidence.get("pagination", {}) if evidence else {},
                "baseline_status": status,
                "evidence_summary": status_reason,
                "limitations": [
                    "This reflects only response evidence captured by existing scan checks.",
                    "Collection contents may be filtered or account-scoped; completeness is not proof of authorization policy.",
                ],
            }
            baselines.append(baseline)
            baselines_by_path.setdefault(
                (route["collection_path"].rstrip("/") or "/", route["resource_type"]),
                [],
            ).append(baseline)

        for endpoint, classification, route in endpoint_routes:
            if route["is_collection"] and route["resource_type"] in self.COLLECTION_TYPES:
                continue
            if classification not in {"resource_by_id", "user_or_account"}:
                continue

            evidence = self._response_evidence(endpoint)
            referenced_baselines = baselines_by_path.get(
                (route["collection_path"].rstrip("/") or "/", route["resource_type"]),
                [],
            )
            baseline = next(
                (
                    item
                    for item in referenced_baselines
                    if item.get("baseline_status") in {"complete", "partial"}
                ),
                None,
            )
            result = self._assess_detail(endpoint, route, evidence, baseline)
            details.append(result)

        return {"baselines": baselines, "assessments": details}

    def _assess_detail(self, endpoint, route, evidence, baseline):
        path = route["path"]
        method = str(endpoint.get("method") or "UNKNOWN").upper()
        base = {
            "method": method,
            "resource_endpoint": path,
            "request_reference": self._request_reference(endpoint),
            "resource_type": route["resource_type"],
            "requested_resource_id": route["requested_id"],
            "returned_resource_id": None,
            "baseline_source": (
                {
                    "collection_endpoint": baseline["collection_endpoint"],
                    "method": baseline["method"],
                    "request_reference": baseline["request_reference"],
                }
                if baseline
                else None
            ),
            "baseline_status": baseline["baseline_status"] if baseline else "unavailable",
            "correlation_status": "not_comparable",
            "http_status": evidence.get("status_code") if evidence else None,
            "content_type": evidence.get("content_type") if evidence else None,
            "response_diagnostic": self._evidence_diagnostic(endpoint, evidence),
            "response_fingerprint": self._response_fingerprint(evidence),
            "assessment": "skipped",
            "evidence_summary": "",
            "confidence": "low",
            "limitations": [
                "Passive correlation uses only sanitized response evidence already captured by existing scan checks.",
                "A baseline is not proof of the complete set of resources the account may access.",
                "No additional requests were sent by BOLA analysis.",
            ],
        }
        if not isinstance(evidence, dict):
            diagnostic = base["response_diagnostic"]
            request_outcome = diagnostic.get("request_outcome")
            if request_outcome == "not_attempted":
                base["assessment"] = "not_tested"
                reason = diagnostic.get("skip_reason") or "not_selected_for_authenticated_check"
                base["evidence_summary"] = (
                    "No authenticated response evidence exists because this endpoint "
                    f"was not sent: {reason}."
                )
                base["limitations"].append(
                    "No endpoint request was made for this route; no positive or negative conclusion is inferred."
                )
            elif request_outcome == "authentication_unavailable":
                base["assessment"] = "inconclusive"
                base["evidence_summary"] = (
                    "No authenticated response evidence exists because authentication "
                    f"was unavailable: {diagnostic.get('skip_reason')}."
                )
                base["limitations"].append(
                    "The endpoint was not tested with an authenticated session."
                )
            elif request_outcome == "request_failed":
                base["assessment"] = "inconclusive"
                base["evidence_summary"] = (
                    "An authenticated request was attempted but failed before a response "
                    f"could be captured: {diagnostic.get('skip_reason')}."
                )
                base["limitations"].append(
                    "No response was available to correlate."
                )
            else:
                base["evidence_summary"] = "No authenticated JSON response evidence is available for this endpoint."
                base["limitations"].append("No authenticated response evidence was captured by existing checks.")
            return base

        status = evidence.get("status_code")
        if isinstance(status, str) and status.isdigit():
            status = int(status)
        if status in {401, 403}:
            base.update(
                {
                    "assessment": "inconclusive",
                    "evidence_summary": f"Captured authenticated request returned HTTP {status}; authorization prevented resource correlation.",
                    "confidence": "low",
                }
            )
            return base
        if status == 404:
            base.update(
                {
                    "assessment": "not_detected",
                    "evidence_summary": "Captured authenticated request returned HTTP 404; no resource disclosure was established for this request.",
                    "confidence": "low",
                }
            )
            return base
        if not isinstance(status, int) or not 200 <= status < 300:
            base["evidence_summary"] = "Captured response did not establish a successful resource observation."
            base["assessment"] = "inconclusive"
            return base
        if not evidence.get("response_is_json") or not evidence.get("body_available"):
            base["evidence_summary"] = "Successful response was not a captured JSON resource body; SPA fallback and generic responses are not correlated."
            base["assessment"] = "skipped"
            return base
        if evidence.get("error_payload_observed") or evidence.get("authentication_denied"):
            base["evidence_summary"] = "Captured JSON response contains an error or denial signal, not reliable resource evidence."
            base["assessment"] = "inconclusive"
            return base
        if evidence.get("body_summary_partial") or evidence.get("body_truncated"):
            base["evidence_summary"] = "Captured response evidence is incomplete."
            base["assessment"] = "inconclusive"
            return base
        if not evidence.get("resource_records_observed"):
            base["evidence_summary"] = "No resource-shaped object was identified in the captured JSON response."
            base["assessment"] = "skipped"
            return base

        identifiers = self._typed_identifiers(evidence, route["resource_type"])
        compatible = [
            item for item in identifiers
            if item["resource_type"] == route["resource_type"]
        ]
        incompatible = [item for item in identifiers if item not in compatible]
        if incompatible and not compatible:
            base["evidence_summary"] = "Captured identifiers refer to a different resource type than the endpoint route."
            base["assessment"] = "inconclusive"
            return base
        if not compatible:
            base["correlation_status"] = "no_identifier"
            base["assessment"] = "inconclusive"
            base["evidence_summary"] = "A resource-shaped response was captured, but no compatible identifier was available."
            return base

        returned = next(
            (
                item for item in compatible
                if item["field"].lower().replace("_", "") not in self.GENERIC_ID_FIELDS
            ),
            compatible[0],
        )
        base["returned_resource_id"] = returned["value"]
        if baseline is None:
            base["assessment"] = "inconclusive"
            base["evidence_summary"] = "A resource identifier was captured, but no related collection baseline is available."
            return base
        if baseline["baseline_status"] != "complete":
            base["assessment"] = "inconclusive"
            base["evidence_summary"] = "The related collection baseline is partial; absence cannot be interpreted."
            return base

        baseline_values = {
            item["value"]
            for item in baseline["identifiers"]
            if item["resource_type"] == route["resource_type"]
        }
        if returned["value"] in baseline_values:
            base.update(
                {
                    "correlation_status": "matched",
                    "assessment": "not_detected",
                    "evidence_summary": "Returned resource identifier appears in the captured collection baseline.",
                    "confidence": "medium",
                }
            )
        else:
            base.update(
                {
                    "correlation_status": "out_of_baseline",
                    "assessment": "potential",
                    "evidence_summary": "Successful captured response contains a compatible resource identifier absent from the apparently complete observed collection response.",
                    "confidence": "low",
                    "limitations": [
                        *base["limitations"],
                        "Out-of-baseline is not proof of unauthorized access; filtering, pagination, and collection semantics may explain the difference.",
                        "Ownership and access policy were not independently established.",
                    ],
                }
            )
        return base
