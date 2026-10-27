import unittest
import os
import threading
from unittest.mock import patch

import httpx

from module.authentication_test import AuthenticationTest
from module.bola_analysis import BolaAnalyzer
from module.modules import Modules
from module.pentest_report import build_pentest_report


def captured_evidence(
    identifiers=None,
    *,
    status=200,
    records=True,
    json_body=True,
    body=True,
    pagination=None,
    partial=False,
    error=False,
):
    return {
        "status_code": status,
        "content_type": "application/json" if json_body else "text/html",
        "response_is_json": json_body,
        "body_available": body,
        "body_summary_partial": partial,
        "body_truncated": False,
        "error_payload_observed": error,
        "resource_records_observed": records,
        "resource_record_count_observed": len(identifiers or []),
        "resource_identifiers": identifiers or [],
        "pagination": pagination or {"detected": False},
    }


def endpoint(method, path, evidence):
    return {
        "method": method,
        "path": path,
        "test_results": [
            {
                "test_module": "jwt_authentication",
                "authenticated_check": {"evidence": evidence},
            }
        ],
    }


def identifier(value, field="id", path="$"):
    return {"field": field, "value": value, "path": path}


class BolaAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = BolaAnalyzer()

    def analyze_order(self, detail_id, detail_evidence=None, baseline_evidence=None):
        inventory = [
            endpoint(
                "GET",
                "/api/orders",
                baseline_evidence
                or captured_evidence(
                    [
                        identifier(1, path="$.orders[0]"),
                        identifier(2, path="$.orders[1]"),
                    ]
                ),
            ),
            endpoint(
                "GET",
                f"/api/orders/{detail_id}",
                detail_evidence
                or captured_evidence([identifier(detail_id, path="$")]),
            ),
        ]
        return self.analyzer.analyze(inventory)

    def test_collection_ids_correlate_with_resource_by_id_responses(self):
        result = self.analyze_order(1)
        baseline = result["baselines"][0]
        assessment = result["assessments"][0]

        self.assertEqual(baseline["baseline_status"], "complete")
        self.assertEqual(assessment["correlation_status"], "matched")
        self.assertEqual(assessment["assessment"], "not_detected")
        self.assertEqual(assessment["requested_resource_id"], "1")
        self.assertEqual(baseline["record_count_observed"], 2)
        self.assertEqual(len(baseline["response_fingerprint"]), 64)
        self.assertEqual(len(assessment["response_fingerprint"]), 64)

    def test_out_of_baseline_is_potential_not_confirmed(self):
        assessment = self.analyze_order(3)["assessments"][0]

        self.assertEqual(assessment["correlation_status"], "out_of_baseline")
        self.assertEqual(assessment["assessment"], "potential")
        self.assertNotEqual(assessment["assessment"], "confirmed")
        self.assertEqual(assessment["returned_resource_id"], "3")

    def test_response_without_identifier_is_inconclusive(self):
        result = self.analyze_order(
            3,
            detail_evidence=captured_evidence([], records=True),
        )
        assessment = result["assessments"][0]

        self.assertEqual(assessment["correlation_status"], "no_identifier")
        self.assertEqual(assessment["assessment"], "inconclusive")
        self.assertIsNone(assessment["returned_resource_id"])

    def test_partial_paginated_collection_cannot_support_absence_claim(self):
        result = self.analyze_order(
            3,
            baseline_evidence=captured_evidence(
                [identifier(1, path="$.orders[0]"), identifier(2, path="$.orders[1]")],
                pagination={"detected": True, "has_more": True},
            ),
        )
        baseline = result["baselines"][0]
        assessment = result["assessments"][0]

        self.assertEqual(baseline["baseline_status"], "partial")
        self.assertEqual(assessment["assessment"], "inconclusive")
        self.assertNotEqual(assessment["correlation_status"], "out_of_baseline")

    def test_different_resource_types_do_not_match_same_numeric_identifier(self):
        result = self.analyzer.analyze(
            [
                endpoint(
                    "GET",
                    "/api/users",
                    captured_evidence([identifier(1, path="$.users[0]")]),
                ),
                endpoint(
                    "GET",
                    "/api/orders/1",
                    captured_evidence([identifier(1, path="$")]),
                ),
            ]
        )

        assessment = result["assessments"][0]
        self.assertEqual(assessment["resource_type"], "order")
        self.assertIsNone(assessment["baseline_source"])
        self.assertEqual(assessment["assessment"], "inconclusive")

    def test_nested_foreign_identifier_is_not_correlated_as_route_resource(self):
        result = self.analyze_order(
            1,
            detail_evidence=captured_evidence(
                [identifier(1, field="id", path="$.customer")]
            ),
        )
        assessment = result["assessments"][0]

        self.assertEqual(assessment["correlation_status"], "not_comparable")
        self.assertEqual(assessment["assessment"], "inconclusive")

    def test_authorization_and_not_found_statuses_are_not_confirmed(self):
        expected = {401: "inconclusive", 403: "inconclusive", 404: "not_detected"}
        for status, assessment_status in expected.items():
            with self.subTest(status=status):
                result = self.analyze_order(
                    1,
                    detail_evidence=captured_evidence(
                        [identifier(1)], status=status
                    ),
                )
                assessment = result["assessments"][0]
                self.assertEqual(assessment["assessment"], assessment_status)
                self.assertNotEqual(assessment["assessment"], "confirmed")

    def test_spa_and_error_responses_are_not_resource_observations(self):
        for evidence, expected in (
            (
                captured_evidence(
                    [identifier(3)],
                    json_body=False,
                    records=False,
                ),
                "skipped",
            ),
            (
                captured_evidence(
                    [identifier(3)],
                    records=False,
                    error=True,
                ),
                "inconclusive",
            ),
        ):
            with self.subTest(evidence=evidence):
                result = self.analyze_order(3, detail_evidence=evidence)
                self.assertEqual(
                    result["assessments"][0]["assessment"],
                    expected,
                )

    def test_identifier_capture_excludes_sensitive_values(self):
        response = httpx.Response(
            200,
            json={
                "orders": [
                    {
                        "id": 1,
                        "name": "sample",
                        "password": "secret-password",
                        "access_token": "secret-token",
                    }
                ]
            },
            request=httpx.Request("GET", "http://localhost/api/orders"),
        )

        evidence = AuthenticationTest._body_evidence(response)
        serialized = repr(evidence)
        self.assertIn({"field": "id", "value": "1", "path": "$.orders[0]"}, evidence["resource_identifiers"])
        self.assertNotIn("secret-password", serialized)
        self.assertNotIn("secret-token", serialized)

    def test_five_item_collection_records_intentional_traversal_limit(self):
        response = httpx.Response(
            200,
            json={
                "orders": [
                    {"id": index, "name": f"order-{index}"}
                    for index in range(1, 6)
                ]
            },
            request=httpx.Request("GET", "http://localhost/api/orders"),
        )

        evidence = AuthenticationTest._body_evidence(response)
        status, reason = BolaAnalyzer._baseline_status(
            {
                **evidence,
                "status_code": 200,
            }
        )

        self.assertEqual(len(evidence["resource_identifiers"]), 3)
        self.assertTrue(evidence["body_summary_partial"])
        self.assertFalse(evidence["body_truncated"])
        self.assertIn("array_item_traversal_limit", evidence["evidence_limitations"])
        self.assertEqual(status, "partial")
        self.assertIn("intentionally limited", reason)
        self.assertNotIn("response content exceeded", reason)

    def test_traversal_limit_configuration_is_bounded_and_reported(self):
        response = httpx.Response(
            200,
            json={
                "orders": [
                    {"id": index, "name": f"order-{index}"}
                    for index in range(1, 6)
                ]
            },
            request=httpx.Request("GET", "http://localhost/api/orders"),
        )
        with patch.dict(os.environ, {"MICROSCAN_EVIDENCE_TRAVERSAL_LIMIT": "5"}):
            evidence = AuthenticationTest._body_evidence(response)
            status, _ = BolaAnalyzer._baseline_status(
                {
                    **evidence,
                    "status_code": 200,
                }
            )

        self.assertEqual(evidence["evidence_traversal_limit"], 5)
        self.assertEqual(
            [item["value"] for item in evidence["resource_identifiers"]],
            ["1", "2", "3", "4", "5"],
        )
        self.assertFalse(evidence["body_summary_partial"])
        self.assertEqual(status, "complete")

    def test_traversal_limit_still_marks_unexamined_array_items_partial(self):
        response = httpx.Response(
            200,
            json={
                "orders": [
                    {"id": index, "name": f"order-{index}"}
                    for index in range(1, 7)
                ]
            },
            request=httpx.Request("GET", "http://localhost/api/orders"),
        )
        with patch.dict(os.environ, {"MICROSCAN_EVIDENCE_TRAVERSAL_LIMIT": "5"}):
            evidence = AuthenticationTest._body_evidence(response)
            status, reason = BolaAnalyzer._baseline_status(
                {
                    **evidence,
                    "status_code": 200,
                }
            )

        self.assertTrue(evidence["body_summary_partial"])
        self.assertIn("array_item_traversal_limit", evidence["evidence_limitations"])
        self.assertEqual(status, "partial")
        self.assertIn("first 5 items", reason)

    def test_traversal_limit_rejects_values_outside_safe_bounds(self):
        response = httpx.Response(
            200,
            json={"orders": []},
            request=httpx.Request("GET", "http://localhost/api/orders"),
        )
        for value in ("0", "26", "invalid"):
            with self.subTest(value=value), patch.dict(
                os.environ,
                {"MICROSCAN_EVIDENCE_TRAVERSAL_LIMIT": value},
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "MICROSCAN_EVIDENCE_TRAVERSAL_LIMIT",
                ):
                    AuthenticationTest._body_evidence(response)

    def test_oversized_response_is_distinguished_from_traversal_cap(self):
        response = httpx.Response(
            200,
            content=b" " * (AuthenticationTest.MAX_EVIDENCE_BODY_BYTES + 1),
            headers={"content-type": "application/json"},
            request=httpx.Request("GET", "http://localhost/api/orders"),
        )

        evidence = AuthenticationTest._body_evidence(response)
        status, reason = BolaAnalyzer._baseline_status(
            {
                **evidence,
                "status_code": 200,
            }
        )

        self.assertTrue(evidence["response_body_over_evidence_limit"])
        self.assertIn(
            "response_exceeded_evidence_parse_limit",
            evidence["evidence_limitations"],
        )
        self.assertEqual(status, "partial")
        self.assertIn("wire-level truncation is unknown", reason)

    def test_grouped_detail_route_stays_skipped_and_logs_not_requested(self):
        detail = {
            "method": "GET",
            "path": "/api/orders/2",
            "jwt_selected": False,
            "jwt_selection_reason": (
                "Grouped with representative GET /api/orders/1 because it has the same route shape."
            ),
            "test_results": [
                {
                    "test_module": "jwt_authentication",
                    "status": "skipped",
                    "test_cases": [
                        {
                            "test_case": "valid_token",
                            "request_attempted": False,
                            "status": "skipped",
                        }
                    ],
                }
            ],
        }

        with self.assertLogs("module.bola_analysis", level="INFO") as captured:
            result = self.analyzer.analyze([detail])

        assessment = result["assessments"][0]
        self.assertEqual(assessment["assessment"], "not_tested")
        self.assertEqual(assessment["correlation_status"], "not_comparable")
        self.assertIn("http_status=unavailable", captured.output[0])
        self.assertIn("evidence_capture=authenticated_request_not_sent", captured.output[0])
        self.assertIn("skip_reason=grouped_with_representative_route", captured.output[0])
        diagnostic = assessment["response_diagnostic"]
        self.assertEqual(diagnostic["request_outcome"], "not_attempted")
        self.assertEqual(diagnostic["selection_reason"], detail["jwt_selection_reason"])
        report = build_pentest_report(
            [
                {
                    **detail,
                    "classification": "resource_by_id",
                    "discovery_source": "discovery",
                    "discovered": True,
                    "bola_assessment": assessment,
                }
            ]
        )
        self.assertEqual(
            report["bola_assessments"][0]["response_diagnostic"]["skip_reason"],
            "grouped_with_representative_route",
        )
        self.assertEqual(assessment["assessment"], "not_tested")

    def test_users_missing_auth_evidence_does_not_reuse_unauthenticated_status(self):
        users = {
            "method": "GET",
            "path": "/api/users",
            "jwt_selected": True,
            "test_results": [
                {
                    "test_module": "jwt_authentication",
                    "status": "inconclusive",
                    "unauthenticated_checks": [
                        {"request": "without_credentials", "status_code": 401},
                        {"request": "invalid_bearer_token", "status_code": 401},
                    ],
                    "authenticated_check": {
                        "status": "skipped",
                        "request_attempted": False,
                        "reason": "No user-provided login configuration is available.",
                        "evidence": None,
                    },
                    "discovery": {"login_attempt_status": "unavailable"},
                }
            ],
        }

        with self.assertLogs("module.bola_analysis", level="INFO") as captured:
            result = self.analyzer.analyze([users])

        baseline = result["baselines"][0]
        self.assertEqual(baseline["baseline_status"], "unavailable")
        self.assertIsNone(baseline["http_status"])
        self.assertIn("http_status=unavailable", captured.output[0])
        self.assertIn("authentication_available=false", captured.output[0])
        self.assertIn("skip_reason=login_unavailable_no_authenticated_request", captured.output[0])
        self.assertIn("unauthenticated_statuses=[401, 401]", captured.output[0])
        self.assertNotIn("No user-provided login", captured.output[0])
        report = build_pentest_report(
            [
                {
                    **users,
                    "classification": "resource_collection",
                    "discovery_source": "discovery",
                    "discovered": True,
                    "bola_baseline": baseline,
                }
            ]
        )
        diagnostic = report["bola_baselines"][0]["response_diagnostic"]
        self.assertEqual(diagnostic["request_outcome"], "authentication_unavailable")
        self.assertFalse(diagnostic["authentication_available"])
        self.assertIsNone(diagnostic["http_status"])

    def test_authenticated_http_status_and_request_failure_are_logged_safely(self):
        denied = endpoint(
            "GET",
            "/api/orders/1",
            captured_evidence([identifier(1)], status=401),
        )
        denied["test_results"][0]["authenticated_check"]["request_attempted"] = True
        failed = {
            "method": "GET",
            "path": "/api/orders/2",
            "jwt_selected": True,
            "test_results": [
                {
                    "test_module": "jwt_authentication",
                    "authenticated_check": {
                        "status": "error",
                        "request_attempted": True,
                        "reason": "Authenticated endpoint request timed out.",
                        "evidence": None,
                    },
                }
            ],
        }

        with self.assertLogs("module.bola_analysis", level="INFO") as captured:
            result = self.analyzer.analyze([denied, failed])

        self.assertEqual(result["assessments"][0]["http_status"], 401)
        self.assertEqual(result["assessments"][0]["assessment"], "inconclusive")
        self.assertIn("http_status=401", captured.output[0])
        self.assertIn("authentication_available=true", captured.output[1])
        self.assertIn(
            "evidence_capture=authenticated_request_failed_or_evidence_missing",
            captured.output[1],
        )
        self.assertIn("skip_reason=authenticated_request_error", captured.output[1])
        self.assertEqual(
            result["assessments"][0]["response_diagnostic"]["request_outcome"],
            "response_captured",
        )
        self.assertEqual(
            result["assessments"][0]["response_diagnostic"]["content_type"],
            "application/json",
        )
        self.assertEqual(
            result["assessments"][1]["response_diagnostic"]["request_outcome"],
            "request_failed",
        )
        self.assertEqual(result["assessments"][1]["assessment"], "inconclusive")

    def test_module_pipeline_attaches_passive_results_without_extra_requests(self):
        class EvidenceOnlyAuthentication:
            def __init__(self):
                self.evaluated = []

            @staticmethod
            def reset_scan_state():
                return None

            @staticmethod
            def skipped_result(endpoint_data, reason):
                return {
                    "test_module": "jwt_authentication",
                    "status": "skipped",
                    "reason": reason,
                    "test_cases": [],
                }

            def evaluate(self, target, selected_candidate, discovered_endpoints):
                candidate = selected_candidate["endpoint"]
                self.evaluated.append(candidate["path"])
                evidence = (
                    captured_evidence(
                        [identifier(1, path="$.orders[0]"), identifier(2, path="$.orders[1]")]
                    )
                    if candidate["path"] == "/api/orders"
                    else captured_evidence([identifier(3)])
                )
                return {
                    "test_module": "jwt_authentication",
                    "status": "tested",
                    "authenticated_check": {"evidence": evidence},
                    "test_cases": [
                        {
                            "test_case": "valid_token",
                            "status": "not_detected_in_this_test",
                            "request_attempted": True,
                        }
                    ],
                }

        authentication = EvidenceOnlyAuthentication()
        modules = Modules(authentication_test=authentication)
        with patch.object(Modules, "_endpoint_allowlist", return_value=[]):
            results = modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                [
                    {"method": "GET", "path": "/api/orders"},
                    {"method": "GET", "path": "/api/orders/3"},
                ],
                auto_jwt_local_lab=True,
            )

        self.assertEqual(len(authentication.evaluated), 2)
        self.assertTrue(any(item.get("bola_baseline") for item in results))
        self.assertTrue(any(item.get("bola_assessment") for item in results))
        report = build_pentest_report(results)
        self.assertEqual(report["summary"]["request_count"], 2)
        self.assertEqual(report["summary"]["bola_assessment_count"], 1)
        self.assertEqual(report["summary"]["bola_potential_count"], 1)

    def test_pipeline_sends_authenticated_check_to_one_representative_id_route(self):
        class RecordingAuthentication:
            def __init__(self):
                self.evaluated_paths = []

            @staticmethod
            def reset_scan_state():
                return None

            @staticmethod
            def skipped_result(endpoint_data, reason):
                return {
                    "test_module": "jwt_authentication",
                    "status": "skipped",
                    "reason": reason,
                    "test_cases": [
                        {
                            "test_case": "valid_token",
                            "request_attempted": False,
                            "status": "skipped",
                        }
                    ],
                }

            def evaluate(self, target, selected_candidate, discovered_endpoints):
                path = selected_candidate["path"]
                self.evaluated_paths.append(path)
                evidence = captured_evidence(
                    [identifier(1, path="$")],
                    status=200,
                )
                return {
                    "test_module": "jwt_authentication",
                    "status": "tested",
                    "authenticated_check": {
                        "status": "tested",
                        "request_attempted": True,
                        "evidence": evidence,
                    },
                    "test_cases": [
                        {
                            "test_case": "valid_token",
                            "status": "not_detected_in_this_test",
                            "request_attempted": True,
                        }
                    ],
                }

        authentication = RecordingAuthentication()
        modules = Modules(authentication_test=authentication)
        paths = [f"/api/orders/{index}" for index in range(1, 6)]
        with patch.object(Modules, "_endpoint_allowlist", return_value=[]):
            analyzed = modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                [{"method": "GET", "path": path} for path in paths],
                auto_jwt_local_lab=True,
            )

        self.assertEqual(len(authentication.evaluated_paths), 1)
        self.assertEqual(authentication.evaluated_paths[0], paths[0])
        unselected = [
            endpoint
            for endpoint in analyzed
            if endpoint["path"] != authentication.evaluated_paths[0]
        ]
        self.assertEqual(len(unselected), 4)
        self.assertTrue(
            all("Grouped with representative" in item["jwt_selection_reason"] for item in unselected)
        )
        self.assertTrue(
            all(
                item["bola_assessment"]["assessment"] == "not_tested"
                and item["bola_assessment"]["correlation_status"] == "not_comparable"
                for item in unselected
            )
        )
        representative = analyzed[0]["bola_assessment"]
        self.assertEqual(
            representative["response_diagnostic"]["request_outcome"],
            "response_captured",
        )
        self.assertEqual(
            representative["response_diagnostic"]["http_status"],
            200,
        )
        self.assertEqual(
            representative["response_diagnostic"]["content_type"],
            "application/json",
        )
        self.assertTrue(
            all(
                item["bola_assessment"]["response_diagnostic"]["request_outcome"]
                == "not_attempted"
                for item in unselected
            )
        )
        report = build_pentest_report(analyzed)
        self.assertEqual(
            report["summary"]["jwt_selection_budgets"],
            [
                {
                    "mode": "automatic_local_lab",
                    "configured": 5,
                    "used": 1,
                    "remaining": 4,
                }
            ],
        )

    def test_active_bola_detail_request_is_independent_of_jwt_selection_budget(self):
        requests = []

        def response(method, url, status, payload):
            return httpx.Response(
                status,
                json=payload,
                headers={"content-type": "application/json"},
                request=httpx.Request(method, url),
            )

        def mocked_request(method, url, headers=None):
            requests.append((method, url, headers))
            if url.endswith("/api/orders/2") or url.endswith("/api/orders/3"):
                order_id = int(url.rsplit("/", 1)[-1])
                return response(
                    method,
                    url,
                    200,
                    {
                        "order": {
                            "id": order_id,
                            "customerName": "userB",
                            "amount": 30,
                        }
                    },
                )
            if url.endswith("/api/orders/1"):
                return response(
                    method,
                    url,
                    200,
                    {
                        "order": {
                            "id": 1,
                            "customerName": "userA",
                            "amount": 10,
                        }
                    },
                )
            if (
                url.endswith("/api/orders")
                and headers
                and headers.get("Authorization", "").startswith("Bearer ")
            ):
                return response(
                    method,
                    url,
                    200,
                    {
                        "orders": [
                            {"id": 1, "customerName": "userA", "amount": 10},
                            {"id": 4, "customerName": "userA", "amount": 40},
                            {"id": 5, "customerName": "userA", "amount": 50},
                        ],
                        "has_more": True,
                    },
                )
            if url.endswith("/api/orders/3"):
                return response(
                    method,
                    url,
                    200,
                    {"order": {"id": 3, "amount": 30}},
                )
            if headers and headers.get("Authorization") == "Bearer lab-token":
                return response(
                    method,
                    url,
                    200,
                    {
                        "orders": [
                            {"id": 1, "amount": 10},
                            {"id": 2, "amount": 20},
                        ],
                        "has_more": True,
                    },
                )
            return response(
                method,
                url,
                200,
                {
                    "orders": [
                        {"id": 1, "customerName": "userA", "amount": 10},
                        {"id": 4, "customerName": "userA", "amount": 40},
                        {"id": 5, "customerName": "userA", "amount": 50},
                    ],
                    "has_more": True,
                },
            )

        def token_info(_target, _configuration):
            return {
                "token": "lab-token",
                "cookie": None,
                "auth_scheme": "Bearer",
                "auth_scheme_source": "configured",
                "mechanism": "JWT over Bearer",
                "auth_header": "Authorization",
                "http_status": 200,
                "response_content_type": "application/json",
            }

        modules = Modules()
        endpoints = [
            {
                "method": "GET",
                "path": "/api/orders",
                "responses": [{"sc": 200}],
            },
            {
                "method": "GET",
                "path": "/api/orders/1",
                "responses": [{"sc": 200}],
            },
            *[
                {
                    "method": "GET",
                    "path": f"/api/orders/{order_id}",
                    "responses": [{"sc": 200}],
                }
                for order_id in ("2", "3", "4", "5")
            ],
            {
                "method": "GET",
                "path": "/api/users",
                "responses": [{"sc": 200}],
            },
        ]
        with patch.dict(
            os.environ,
            {
                "MICROSCAN_JWT_ENDPOINT_BUDGET": "1",
                "MICROSCAN_BOLA_REQUEST_BUDGET": "3",
            },
        ), patch.object(Modules, "_endpoint_allowlist", return_value=[]), patch(
            "module.authentication_test.Signin.configured_auth",
            return_value=({"payload": {"username": "lab"}}, [], None),
        ), patch.object(
            AuthenticationTest, "_signin_once", side_effect=token_info
        ), patch.object(
            AuthenticationTest, "_run_http_request", side_effect=mocked_request
        ):
            analyzed = modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                endpoints,
                auto_jwt_local_lab=True,
                discovered_route_templates=[
                    {
                        "method": "GET",
                        "template": "/api/orders/${encodeURIComponent(id)}",
                    },
                    {
                        "method": "GET",
                        "template": "http://outside.invalid/api/orders/{id}",
                    },
                ],
            )

        order_collection = next(
            item for item in analyzed if item["path"] == "/api/orders"
        )
        self.assertTrue(order_collection["jwt_selected"])
        self.assertEqual(order_collection["jwt_selection_budget"]["used"], 1)
        self.assertEqual(order_collection["jwt_selection_budget"]["remaining"], 0)
        self.assertFalse(
            next(item for item in analyzed if item["path"] == "/api/users")[
                "jwt_selected"
            ]
        )
        self.assertFalse(
            next(item for item in analyzed if item["path"] == "/api/orders/1")[
                "jwt_selected"
            ]
        )
        active_tests = order_collection["test_results"][0]["active_bola_tests"]
        sent_tests = [item for item in active_tests if item["sent"]]
        self.assertEqual(len(sent_tests), 3)
        self.assertEqual(
            [item["path"] for item in sent_tests],
            ["/api/orders/2", "/api/orders/3", "/api/orders/1"],
        )
        self.assertEqual(
            [item["assessment"] for item in sent_tests],
            ["confirmed", "confirmed", "not_detected"],
        )
        self.assertEqual(
            [
                item["path"]
                for item in active_tests
                if item["path"] in {"/api/orders/4", "/api/orders/5"}
                and not item["sent"]
            ],
            ["/api/orders/4", "/api/orders/5"],
        )
        self.assertTrue(
            all(
                item["request_budget"]["configured"] == 3
                for item in active_tests
            )
        )

        self.assertEqual(sent_tests[0]["baseline_status"], "partial")
        self.assertEqual(
            sent_tests[0]["route_template"],
            "/api/orders/${encodeURIComponent(id)}",
        )
        self.assertTrue(sent_tests[0]["selected"])
        self.assertTrue(sent_tests[0]["response_received"])
        self.assertEqual(sent_tests[0]["http_status"], 200)
        self.assertEqual(
            sent_tests[0]["owner_identity_evidence"]["comparison"],
            "differs_from_authenticated_baseline",
        )
        self.assertEqual(
            sent_tests[0]["owner_identity_evidence"]["response_fields"][0]["field"],
            "customerName",
        )
        self.assertTrue(
            any(
                method == "GET"
                and url.endswith("/api/orders/3")
                and headers == {"Authorization": "Bearer lab-token"}
                for method, url, headers in requests
            )
        )
        self.assertTrue(
            any(
                method == "GET"
                and url.endswith("/api/orders/2")
                and headers
                and headers.get("Authorization", "").startswith("Bearer ")
                for method, url, headers in requests
            )
        )
        self.assertFalse(any("outside.invalid" in url for _, url, _ in requests))
        self.assertTrue(
            all(
                url.startswith("http://127.0.0.1:8085/")
                for _, url, _ in requests
            )
        )
        self.assertNotIn("userA", repr(sent_tests))
        self.assertNotIn("userB", repr(sent_tests))

        report = build_pentest_report(analyzed)
        self.assertEqual(report["summary"]["request_count"], 3)
        self.assertEqual(report["summary"]["bola_active_request_count"], 3)
        self.assertEqual(report["summary"]["bola_active_potential_count"], 0)
        self.assertIn(
            "Pagination indicates additional collection data",
            sent_tests[0]["baseline_limitation"],
        )
        self.assertEqual(
            report["summary"]["bola_request_budgets"],
            [{"configured": 3, "used": 3, "remaining": 0}],
        )
        self.assertTrue(
            any(
                finding["test_case"] == "active_bola_detail"
                and finding["status"] == "confirmed"
                for finding in report["findings"]
            )
        )

    def test_full_scan_selects_all_eligible_groups_without_probing_auth_or_templates(self):
        requests = []

        def mocked_request(method, url, headers=None):
            requests.append((method, url))
            return httpx.Response(
                401,
                json={"message": "unauthorized"},
                request=httpx.Request(method, url),
            )

        endpoints = [
            {"method": "GET", "path": path, "responses": [{"sc": 200}]}
            for path in (
                "/api/orders",
                "/api/users",
                "/api/products",
                "/api/accounts",
                "/api/projects",
                "/api/inventory",
                "/api/billing",
                "/api/orders/1",
                "/api/orders/2",
                "/api/orders/{id}",
                "/api/auth/session",
            )
        ]
        modules = Modules()
        with patch.dict(
            os.environ,
            {
                "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]",
                "MICROSCAN_JWT_ENDPOINT_BUDGET": "1",
                "MICROSCAN_BOLA_REQUEST_BUDGET": "1",
                "MICROSHIELD_USERNAME": "",
                "MICROSHIELD_PASSWORD": "",
                "MICROSCAN_LOGIN_PAYLOAD": "",
                "MICROSCAN_AUTH_CONFIG": "",
                "MICROSCAN_LOGIN_ENDPOINT": "",
            },
            clear=True,
        ), patch.object(
            AuthenticationTest, "_run_http_request", side_effect=mocked_request
        ):
            analyzed = modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                endpoints,
                auto_jwt_local_lab=True,
                scan_mode="full",
            )

        selected = [item for item in analyzed if item["jwt_selected"]]
        self.assertEqual(len(selected), 9)
        self.assertTrue(all(item["jwt_eligible"] for item in selected))
        self.assertTrue(
            all(
                item["jwt_selection_budget"]["configured"] is None
                and item["jwt_selection_budget"]["used"] == 8
                and item["jwt_selection_budget"]["remaining"] is None
                for item in analyzed
            )
        )
        dynamic = next(item for item in analyzed if item["path"] == "/api/orders/{id}")
        self.assertFalse(dynamic["jwt_selected"])
        self.assertIn("unresolved dynamic template", dynamic["jwt_selection_reason"])
        auth_route = next(
            item for item in analyzed if item["path"] == "/api/auth/session"
        )
        self.assertFalse(auth_route["jwt_selected"])
        self.assertIn("authentication", auth_route["jwt_selection_reason"].lower())
        self.assertTrue(all("{id}" not in url for _, url in requests))
        self.assertTrue(
            all(
                any(url.endswith(f"/api/orders/{identifier}") for _, url in requests)
                for identifier in ("1", "2")
            )
        )
        self.assertFalse(
            any(
                "limited to 1 endpoint groups" in item["jwt_selection_reason"]
                for item in analyzed
            )
        )

        report = build_pentest_report(analyzed, scan_mode="full")
        summary = report["summary"]
        self.assertEqual(summary["scan_mode"], "full")
        self.assertEqual(summary["eligible_endpoints"], 9)
        self.assertEqual(summary["selected_endpoints"], 9)
        self.assertEqual(summary["actually_tested_endpoints"], 9)
        self.assertEqual(summary["excluded_endpoints"], 2)
        self.assertEqual(summary["eligible_but_not_selected_endpoints"], 0)
        self.assertEqual(summary["test_cases_attempted"], summary["request_count"])
        self.assertLessEqual(
            summary["test_cases_completed"], summary["total_test_cases"]
        )

    def test_cancellation_stops_before_starting_another_endpoint(self):
        requests = []
        cancellation_event = threading.Event()

        def mocked_request(method, url, headers=None):
            requests.append(url)
            return httpx.Response(
                401,
                json={"message": "unauthorized"},
                request=httpx.Request(method, url),
            )

        def cancel_after_first_endpoint(event):
            cancellation_event.set()

        endpoints = [
            {"method": "GET", "path": path, "responses": [{"sc": 200}]}
            for path in ("/api/orders", "/api/users", "/api/products")
        ]
        with patch.dict(
            os.environ,
            {
                "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]",
                "MICROSHIELD_USERNAME": "",
                "MICROSHIELD_PASSWORD": "",
                "MICROSCAN_LOGIN_PAYLOAD": "",
                "MICROSCAN_AUTH_CONFIG": "",
                "MICROSCAN_LOGIN_ENDPOINT": "",
            },
            clear=True,
        ), patch.object(
            AuthenticationTest, "_run_http_request", side_effect=mocked_request
        ):
            analyzed = Modules().analyze_endpoints(
                "http://127.0.0.1:8085",
                endpoints,
                auto_jwt_local_lab=True,
                scan_mode="full",
                progress_callback=cancel_after_first_endpoint,
                cancellation_event=cancellation_event,
            )

        self.assertTrue(cancellation_event.is_set())
        self.assertLess(len(requests), 6)
        self.assertTrue(analyzed[0]["test_results"])
        self.assertEqual(analyzed[1]["test_results"], [])

    def test_active_bola_does_not_send_without_authenticated_baseline(self):
        response = httpx.Response(
            200,
            json={"orders": [{"id": 3, "amount": 30}]},
            request=httpx.Request("GET", "http://127.0.0.1:8085/api/orders"),
        )
        analyzer = AuthenticationTest()
        budget = {"configured": 1, "used": 0}
        with patch.object(
            AuthenticationTest, "_run_http_request"
        ) as request:
            results = analyzer._active_bola_test_results(
                target="http://127.0.0.1:8085",
                collection_path="/api/orders",
                resource_type="order",
                route_templates=[
                    {
                        "collection_path": "/api/orders",
                        "template": "/api/orders/{id}",
                        "placeholder": "{id}",
                    }
                ],
                responses={"without_credentials": response},
                authenticated_evidence=None,
                authenticated_headers=None,
                budget_state=budget,
            )

        request.assert_not_called()
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["selected"])
        self.assertFalse(results[0]["sent"])
        self.assertFalse(results[0]["response_received"])
        self.assertEqual(results[0]["baseline_status"], "unavailable")
        self.assertIn("Authenticated session is unavailable", results[0]["reason"])

    def test_active_bola_without_owner_identity_remains_potential(self):
        response = httpx.Response(
            200,
            json={"order": {"id": 2, "amount": 20}},
            request=httpx.Request("GET", "http://127.0.0.1:8085/api/orders/2"),
        )
        analyzer = AuthenticationTest()
        with patch.object(
            AuthenticationTest, "_run_http_request", return_value=response
        ):
            results = analyzer._active_bola_test_results(
                target="http://127.0.0.1:8085",
                collection_path="/api/orders",
                resource_type="order",
                route_templates=[
                    {
                        "collection_path": "/api/orders",
                        "template": "/api/orders/{id}",
                        "placeholder": "{id}",
                        "observed_identifiers": ["2"],
                    }
                ],
                responses={},
                authenticated_evidence=captured_evidence(
                    [identifier(1, path="$.orders[0]")]
                ),
                authenticated_headers={"Authorization": "Bearer lab-token"},
                budget_state={"configured": 1, "used": 0},
            )

        self.assertEqual(results[0]["assessment"], "potential")
        self.assertEqual(
            results[0]["owner_identity_evidence"]["comparison"],
            "identity_unavailable",
        )


if __name__ == "__main__":
    unittest.main()
