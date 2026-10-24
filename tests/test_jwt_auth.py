import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from app.main import app
from module.authentication_test import AuthenticationTest
from module.endpoint_selection import EndpointSelector
from module.modules import Modules
from module.pentest_report import build_pentest_report
from module.signin import LoginConfigurationError, LoginError, Signin

Signin.ENV_FILE = Path(__file__).with_name(".test-env-absent")


def response(status_code, body, headers=None):
    return httpx.Response(
        status_code,
        json=body,
        headers=headers,
        request=httpx.Request("GET", "http://127.0.0.1:8085/api/me"),
    )


class SigninTests(unittest.TestCase):
    def test_extract_token_from_common_response_shapes(self):
        self.assertEqual(
            Signin.extract_token({"access_token": "abc"}),
            "abc",
        )
        self.assertEqual(
            Signin.extract_token({"data": {"token": "def"}}),
            "def",
        )
        self.assertIsNone(Signin.extract_token({"message": "logged in"}))
        self.assertIsNone(Signin.extract_token(["not", "an", "object"]))

    @patch.dict(os.environ, {}, clear=True)
    def test_login_requires_documented_payload_configuration(self):
        config, candidates, note = Signin.configured_auth([])
        self.assertIsNone(config)
        self.assertEqual(candidates, [])
        self.assertIn("valid-token coverage is unavailable", note)
        self.assertIn("MICROSHIELD_USERNAME", note)

    def test_dotenv_is_loaded_without_overriding_process_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            dotenv_path = Path(directory) / ".env"
            dotenv_path.write_text(
                "MICROSHIELD_USERNAME=dotenv-user\n"
                "MICROSHIELD_PASSWORD=dotenv-password\n"
                "MICROSCAN_LOGIN_ENDPOINT=/api/auth/login\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"MICROSHIELD_USERNAME": "process-user"},
                clear=True,
            ):
                Signin.load_environment(dotenv_path)

                self.assertEqual(os.environ["MICROSHIELD_USERNAME"], "process-user")
                self.assertEqual(os.environ["MICROSHIELD_PASSWORD"], "dotenv-password")
                self.assertEqual(
                    os.environ["MICROSCAN_LOGIN_ENDPOINT"],
                    "/api/auth/login",
                )

    @patch.dict(
        os.environ,
        {
            "MICROSHIELD_USERNAME": "lab-user",
            "MICROSHIELD_PASSWORD": "lab-password",
            "MICROSCAN_LOGIN_ENDPOINT": "/api/auth/login",
        },
        clear=True,
    )
    def test_username_and_password_environment_create_login_payload(self):
        discovered = [
            {"method": "POST", "path": "/api/auth/login", "responses": [{"sc": 200}]}
        ]

        config, candidates, note = Signin.configured_auth(discovered)

        self.assertEqual(
            config["payload"],
            {"username": "lab-user", "password": "lab-password"},
        )
        self.assertEqual(config["login_endpoint"], "/api/auth/login")
        self.assertEqual(candidates[0]["path"], "/api/auth/login")
        self.assertIsNone(note)

    @patch.dict(
        os.environ,
        {"MICROSHIELD_USERNAME": "lab-user"},
        clear=True,
    )
    def test_partial_credentials_report_missing_password_without_echoing_username(self):
        config, _, note = Signin.configured_auth([])

        self.assertIsNone(config)
        self.assertIn("both MICROSHIELD_USERNAME and MICROSHIELD_PASSWORD", note)
        self.assertNotIn("lab-user", note)

    @patch("module.signin.httpx.post")
    def test_login_posts_configured_body_to_lab_login_route(self, post):
        post.return_value = httpx.Response(
            200,
            json={"data": {"access_token": "test-token", "token_type": "Bearer"}},
            request=httpx.Request("POST", "http://127.0.0.1:8085/api/auth/login"),
        )

        login = Signin().signin(
            "127.0.0.1:8085",
            {
                "login_endpoint": "/api/auth/login",
                "payload": {"user": "lab-user", "passphrase": "lab-pass"},
                "auth_scheme": None,
            },
        )

        self.assertEqual(login["token"], "test-token")
        self.assertEqual(login["auth_scheme"], "Bearer")
        self.assertEqual(
            post.call_args.args[0],
            "http://127.0.0.1:8085/api/auth/login",
        )
        self.assertEqual(
            post.call_args.kwargs["json"],
            {"user": "lab-user", "passphrase": "lab-pass"},
        )
        self.assertFalse(post.call_args.kwargs["follow_redirects"])

    @patch("module.signin.httpx.post")
    def test_jwt_token_field_defaults_to_bearer_without_leaking_token(self, post):
        jwt = "header.payload.signature"
        post.return_value = httpx.Response(
            200,
            json={"message": "logged in", "token": jwt},
            request=httpx.Request("POST", "http://127.0.0.1:8085/api/auth/login"),
        )

        login = Signin().signin(
            "http://127.0.0.1:8085",
            {"login_endpoint": "/api/auth/login", "payload": {"username": "lab"}},
        )

        self.assertEqual(login["token"], jwt)
        self.assertEqual(login["auth_scheme"], "Bearer")
        self.assertEqual(login["auth_scheme_source"], "jwt_format_default")
        self.assertNotIn(jwt, str({key: value for key, value in login.items() if key != "token"}))

    @patch.dict(
        os.environ,
        {"MICROSCAN_LOGIN_PAYLOAD": '{"username":"lab-user","password":"lab-pass"}'},
        clear=True,
    )
    def test_legacy_payload_uses_discovered_login_endpoint_verbatim(self):
        discovered = [
            {"method": "POST", "path": "/api/auth/login", "responses": [{"sc": 200}]}
        ]

        config, candidates, note = Signin.configured_auth(discovered)

        self.assertEqual(config["login_endpoint"], "/api/auth/login")
        self.assertEqual(
            config["payload"],
            {"username": "lab-user", "password": "lab-pass"},
        )
        self.assertEqual(candidates[0]["path"], "/api/auth/login")
        self.assertIsNone(note)

    def test_explicit_absolute_login_url_must_match_target_origin(self):
        self.assertEqual(
            Signin._login_url(
                "http://127.0.0.1:8085",
                "http://127.0.0.1:8085/api/auth/login",
            ),
            "http://127.0.0.1:8085/api/auth/login",
        )
        with self.assertRaisesRegex(LoginConfigurationError, "target origin"):
            Signin._login_url(
                "http://127.0.0.1:8085",
                "http://outside.example/api/auth/login",
            )
        with self.assertRaisesRegex(LoginConfigurationError, "valid path or URL"):
            Signin._login_url("http://127.0.0.1:8085", "http://[invalid")

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_AUTH_CONFIG": (
                '{"payload":{"username":"lab-user"},'
                '"login_endpoint":"http://127.0.0.1:8085/api/auth/login"}'
            )
        },
        clear=True,
    )
    def test_absolute_login_url_can_be_explicitly_configured(self):
        config, _, note = Signin.configured_auth([])

        self.assertEqual(
            config["login_endpoint"],
            "http://127.0.0.1:8085/api/auth/login",
        )
        self.assertEqual(
            Signin._login_url("http://127.0.0.1:8085", config["login_endpoint"]),
            "http://127.0.0.1:8085/api/auth/login",
        )
        self.assertIsNone(note)

    def test_discovered_post_login_endpoint_is_selected_without_guessing_body(self):
        discovered = [
            {"method": "POST", "path": "/v2/session/token", "responses": [{"sc": 200}]},
            {"method": "POST", "path": "/v2/auth/register", "responses": [{"sc": 201}]},
            {"method": "GET", "path": "/v2/users/me"},
        ]
        candidates = EndpointSelector.discover_login_candidates(discovered)
        config, configured_candidates, note = Signin.configured_auth(discovered)
        self.assertIsNone(config)
        self.assertEqual(candidates[0]["path"], "/v2/session/token")
        self.assertEqual(configured_candidates, candidates)
        self.assertIn("request schema and credentials are unknown", note)

    @patch("module.signin.httpx.post")
    def test_login_rejects_http_failure_without_echoing_body(self, post):
        post.return_value = httpx.Response(
            401,
            json={"error": "invalid password", "password": "must-not-leak"},
            request=httpx.Request("POST", "http://127.0.0.1:8085/api/auth/login"),
        )

        with self.assertRaises(LoginError) as raised:
            Signin().signin(
                "http://127.0.0.1:8085",
                {
                    "login_endpoint": "/api/auth/login",
                    "payload": {"password": "secret"},
                },
            )

        self.assertEqual(raised.exception.status_code, 401)
        self.assertNotIn("secret", str(raised.exception))
        self.assertNotIn("must-not-leak", str(raised.exception))

    @patch("module.signin.httpx.post")
    def test_login_rejects_invalid_json(self, post):
        post.return_value = httpx.Response(
            200,
            content=b"not-json",
            request=httpx.Request("POST", "http://127.0.0.1:8085/api/auth/login"),
        )

        with self.assertRaisesRegex(LoginError, "invalid JSON"):
            Signin().signin(
                "http://127.0.0.1:8085",
                {"login_endpoint": "/api/auth/login", "payload": {"user": "lab-user"}},
            )

    @patch("module.signin.httpx.post")
    def test_login_rejects_success_response_without_token(self, post):
        post.return_value = httpx.Response(
            200,
            json={"message": "accepted"},
            request=httpx.Request("POST", "http://127.0.0.1:8085/api/auth/login"),
        )

        with self.assertRaisesRegex(LoginError, "did not contain"):
            Signin().signin(
                "http://127.0.0.1:8085",
                {"login_endpoint": "/api/auth/login", "payload": {"user": "lab-user"}},
            )

    @patch("module.signin.httpx.post")
    def test_login_rejects_explicit_failure_even_when_response_contains_token(self, post):
        post.return_value = httpx.Response(
            200,
            json={
                "success": False,
                "access_token": "must-not-be-used",
                "message": "invalid credentials",
            },
            request=httpx.Request("POST", "http://127.0.0.1:8085/api/auth/login"),
        )

        with self.assertRaisesRegex(LoginError, "unsuccessful authentication"):
            Signin().signin(
                "http://127.0.0.1:8085",
                {
                    "login_endpoint": "/api/auth/login",
                    "payload": {"user": "lab-user"},
                },
            )

    def test_login_endpoint_cannot_escape_target_origin(self):
        with self.assertRaises(LoginConfigurationError):
            Signin._login_url(
                "http://127.0.0.1:8085",
                "//outside.example/api/login",
            )

    @patch("module.signin.httpx.post", side_effect=httpx.TimeoutException("secret"))
    def test_login_timeout_is_sanitized(self, post):
        with self.assertRaisesRegex(LoginError, "timed out") as raised:
            Signin().signin(
                "http://127.0.0.1:8085",
                {
                    "login_endpoint": "/api/auth/login",
                    "payload": {"password": "secret"},
                },
            )
        self.assertNotIn("secret", str(raised.exception))


class AuthenticationTestTests(unittest.TestCase):
    def setUp(self):
        self.modules = Modules()
        self.authentication_test = self.modules.authentication_test
        self.endpoint_selector = self.modules.endpoint_selector
        self.environment = patch.dict(
            os.environ,
            {"MICROSCAN_PROTECTED_ENDPOINT": "/api/me"},
            clear=True,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def evaluate_missing_token_body(self, body, authentication_required=None):
        candidate_endpoint = {
            "method": "GET",
            "path": "/api/orders/check/",
        }
        if authentication_required is not None:
            candidate_endpoint["authentication_required"] = authentication_required
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(200, body), response(401, {"message": "invalid token"})],
        ):
            result = self.authentication_test.evaluate(
                "http://127.0.0.1:8085",
                {
                    "endpoint": candidate_endpoint,
                    "path": "/api/orders/check/",
                    "method": "GET",
                    "reason": "selected by test",
                },
            )
        return next(
            case for case in result["test_cases"]
            if case["test_case"] == "without_token"
        ), result

    def test_200_resource_body_with_explicit_jwt_policy_confirms_missing_jwt(self):
        case, _ = self.evaluate_missing_token_body(
            {"orders": [{"id": 17, "total": 35}]},
            authentication_required=True,
        )

        self.assertEqual(case["status"], "confirmed")
        self.assertEqual(case["evidence"]["status_code"], 200)
        self.assertTrue(case["evidence"]["protected_data_observed"])
        self.assertTrue(case["evidence"]["authentication_required"])
        self.assertNotIn("denied this request", case["reason"])

    def test_200_public_resource_body_is_not_a_missing_jwt_finding(self):
        case, _ = self.evaluate_missing_token_body(
            {"orders": [{"id": 17, "total": 35}]},
            authentication_required=False,
        )

        self.assertEqual(case["status"], "not_detected_in_this_test")
        self.assertIn("marks the resource as public", case["reason"])

    def test_200_generic_message_without_policy_is_inconclusive_not_denied(self):
        case, _ = self.evaluate_missing_token_body(
            {"message": "Request completed"}
        )

        self.assertEqual(case["status"], "inconclusive")
        self.assertIn("insufficient", case["reason"])
        self.assertNotIn("denied this request", case["reason"])
        self.assertFalse(case["evidence"]["authentication_denied"])

    def test_200_body_denial_is_only_treated_as_denial_when_body_says_so(self):
        evidence = self.authentication_test._response_evidence(
            response(200, {"message": "Unauthorized"})
        )
        case = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders/check/",
            "No Authorization header.",
            evidence,
        )

        self.assertEqual(evidence["denial_basis"], "response_body")
        self.assertEqual(case["status"], "not_detected_in_this_test")
        self.assertIn("despite the HTTP status", case["reason"])

    def test_generic_failure_envelopes_are_not_authorization_denials(self):
        for message in ("Validation failed", "Order could not be processed"):
            with self.subTest(message=message):
                evidence = self.authentication_test._response_evidence(
                    response(200, {"success": False, "message": message})
                )
                case = AuthenticationTest._case_result(
                    "without_token",
                    "GET",
                    "/api/orders",
                    "No Authorization header.",
                    evidence,
                )

                self.assertFalse(evidence["body_denial_signal"])
                self.assertFalse(evidence["authentication_denied"])
                self.assertIsNone(evidence["denial_basis"])
                self.assertEqual(case["status"], "inconclusive")

    def test_explicit_authentication_and_authorization_errors_remain_denials(self):
        for body in (
            {"error": "Invalid credentials"},
            {"error_code": "AUTHORIZATION_DENIED"},
        ):
            with self.subTest(body=body):
                evidence = self.authentication_test._response_evidence(
                    response(200, body)
                )

                self.assertTrue(evidence["body_denial_signal"])
                self.assertTrue(evidence["authentication_denied"])
                self.assertEqual(evidence["denial_basis"], "response_body")

    def test_business_record_error_or_failed_text_is_not_auth_denial(self):
        evidence = self.authentication_test._response_evidence(
            response(
                200,
                {
                    "orders": [
                        {
                            "id": 17,
                            "description": "A previous validation error was recorded.",
                            "error": "Payment processing failed.",
                        }
                    ]
                },
            )
        )
        case = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders",
            "No Authorization header.",
            evidence,
        )

        self.assertTrue(evidence["resource_records_observed"])
        self.assertFalse(evidence["body_denial_signal"])
        self.assertFalse(evidence["authentication_denied"])
        self.assertIsNone(evidence["denial_basis"])
        self.assertEqual(case["status"], "potential")

    def test_invalid_jwt_401_is_not_detected_when_no_resource_data_is_returned(self):
        evidence = self.authentication_test._response_evidence(response(401, {}))
        case = AuthenticationTest._case_result(
            "invalid_token",
            "GET",
            "/api/orders/check/",
            "Invalid signature JWT.",
            evidence,
        )

        self.assertTrue(evidence["authentication_denied"])
        self.assertEqual(evidence["denial_basis"], "http_status")
        self.assertEqual(case["status"], "not_detected_in_this_test")
        self.assertIn("HTTP 401", case["reason"])

    def test_json_authorization_error_is_not_resource_disclosure(self):
        for status_code, body in (
            (401, {"error": "Unauthorized", "code": "AUTH_DENIED"}),
            (403, {"success": False, "message": "Access denied"}),
        ):
            with self.subTest(status_code=status_code, body=body):
                evidence = self.authentication_test._response_evidence(
                    response(status_code, body)
                )
                case = AuthenticationTest._case_result(
                    "invalid_token",
                    "GET",
                    "/api/orders",
                    "Invalid signature JWT.",
                    evidence,
                )

                self.assertTrue(evidence["response_is_json"])
                self.assertTrue(evidence["error_payload_observed"])
                self.assertFalse(evidence["resource_records_observed"])
                self.assertEqual(case["status"], "not_detected_in_this_test")

    def test_empty_collection_is_not_resource_disclosure(self):
        evidence = self.authentication_test._response_evidence(
            response(200, {"orders": []})
        )
        case = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders",
            "No Authorization header.",
            evidence,
        )

        self.assertTrue(evidence["empty_collection_observed"])
        self.assertFalse(evidence["resource_records_observed"])
        self.assertEqual(case["status"], "inconclusive")

    def test_generic_json_object_with_arbitrary_keys_is_not_resource_disclosure(self):
        evidence = self.authentication_test._response_evidence(
            response(200, {"foo": "bar", "baz": "qux"})
        )
        case = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders",
            "No Authorization header.",
            evidence,
        )

        self.assertTrue(evidence["response_is_json"])
        self.assertFalse(evidence["resource_records_observed"])
        self.assertEqual(case["status"], "inconclusive")

    def test_structured_data_on_invalid_jwt_response_is_a_potential_case(self):
        evidence = self.authentication_test._response_evidence(
            response(401, {"orders": [{"id": 17, "total": 35}]})
        )
        case = AuthenticationTest._case_result(
            "invalid_token",
            "GET",
            "/api/orders/check/",
            "Structurally valid JWT with invalid signature.",
            evidence,
        )

        self.assertTrue(evidence["protected_data_observed"])
        self.assertTrue(evidence["authentication_denied"])
        self.assertEqual(case["status"], "potential")
        self.assertTrue(case["evidence"]["resource_record_samples"])
        self.assertIn("same response also indicated authorization denial", case["reason"])

    def test_denial_conflict_prevents_confirmed_classification_even_with_policy(self):
        evidence = self.authentication_test._response_evidence(
            response(401, {"orders": [{"id": 17, "total": 35}]})
        )
        evidence["authentication_required"] = True
        case = AuthenticationTest._case_result(
            "invalid_token",
            "GET",
            "/api/orders",
            "Invalid signature JWT.",
            evidence,
        )

        self.assertEqual(case["status"], "potential")
        self.assertTrue(case["evidence"]["authentication_required"])
        self.assertTrue(case["evidence"]["authorization_denial_detected"])

    def test_nested_denial_with_resource_data_prevents_confirmation(self):
        evidence = self.authentication_test._response_evidence(
            response(
                200,
                {
                    "metadata": {"message": "Access denied"},
                    "orders": [{"id": 17, "total": 35}],
                },
            )
        )
        evidence["authentication_required"] = True
        case = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders",
            "No Authorization header.",
            evidence,
        )

        self.assertTrue(case["evidence"]["body_denial_signal"])
        self.assertTrue(case["evidence"]["authorization_denial_detected"])
        self.assertEqual(case["status"], "potential")

    def test_partial_resource_evidence_prevents_confirmation(self):
        evidence = self.authentication_test._response_evidence(
            response(
                200,
                {"orders": [{"id": index, "total": index} for index in range(4)]},
            )
        )
        evidence["authentication_required"] = True
        case = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders",
            "No Authorization header.",
            evidence,
        )

        self.assertTrue(case["evidence"]["resource_records_observed"])
        self.assertTrue(case["evidence"]["body_summary_partial"])
        self.assertEqual(case["status"], "potential")

    def test_authentication_challenge_with_resource_data_prevents_confirmation(self):
        evidence = self.authentication_test._response_evidence(
            response(
                200,
                {"orders": [{"id": 17, "total": 35}]},
                headers={"www-authenticate": 'Bearer realm="api"'},
            )
        )
        evidence["authentication_required"] = True
        case = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders",
            "No Authorization header.",
            evidence,
        )

        self.assertEqual(evidence["denial_basis"], "authentication_challenge")
        self.assertTrue(case["evidence"]["authentication_denied"])
        self.assertEqual(case["status"], "potential")

    def test_partial_or_missing_body_does_not_create_disclosure_finding(self):
        evidence = self.authentication_test._response_evidence(
            httpx.Response(
                401,
                content=b"",
                request=httpx.Request("GET", "http://127.0.0.1/api/orders"),
            )
        )
        case = AuthenticationTest._case_result(
            "invalid_token",
            "GET",
            "/api/orders",
            "Invalid signature JWT.",
            evidence,
        )

        self.assertFalse(evidence["body_available"])
        self.assertFalse(evidence["resource_records_observed"])
        self.assertEqual(case["status"], "inconclusive")
        self.assertNotEqual(case["status"], "potential")

    def test_valid_token_403_is_not_a_successful_positive_control(self):
        endpoint = {"method": "GET", "path": "/api/admin/dashboard"}
        token_info = {
            "token": "mock-valid-token",
            "auth_header": "Authorization",
            "auth_scheme": "Bearer",
            "auth_scheme_source": "configured",
            "mechanism": "JWT over Bearer",
            "http_status": 200,
            "response_content_type": "application/json",
        }
        with patch.object(
            Signin,
            "configured_auth",
            return_value=({"login_endpoint": "/api/login"}, [], "configured"),
        ), patch.object(
            self.authentication_test,
            "_signin_once",
            return_value=token_info,
        ), patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(401, {"error": "Unauthorized"}),
                response(401, {"error": "Invalid token"}),
                response(403, {"error": "Forbidden"}),
            ],
        ):
            result = self.authentication_test.evaluate(
                "http://127.0.0.1:8085",
                {
                    "endpoint": endpoint,
                    "path": endpoint["path"],
                    "method": "GET",
                    "reason": "selected by test",
                },
                discovered_endpoints=[],
            )

        valid_case = next(
            case for case in result["test_cases"]
            if case["test_case"] == "valid_token"
        )
        self.assertEqual(valid_case["status"], "inconclusive")
        self.assertTrue(valid_case["evidence"]["authentication_denied"])
        self.assertFalse(valid_case["evidence"]["resource_records_observed"])

    def test_potential_finding_is_preserved_when_endpoint_assessment_is_inconclusive(self):
        evidence = self.authentication_test._response_evidence(
            response(200, {"orders": [{"id": 17, "total": 35}]})
        )
        case = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders/check/",
            "No Authorization header.",
            evidence,
        )
        endpoint = {
            "method": "GET",
            "path": "/api/orders/check/",
            "discovery_source": "discovery",
            "discovered": True,
            "jwt_selected": True,
            "test_results": [
                {
                    "status": "inconclusive",
                    "test_cases": [
                        case,
                        {
                            "test_case": "expired_token",
                            "method": "GET",
                            "path": "/api/orders/check/",
                            "status": "skipped",
                            "reason": "Expired-token probing is not implemented.",
                            "implementation_status": "not_implemented",
                            "request_attempted": False,
                            "evidence": None,
                        },
                        {
                            "test_case": "valid_token",
                            "method": "GET",
                            "path": "/api/orders/check/",
                            "status": "inconclusive",
                            "reason": "Valid token was not configured.",
                            "request_attempted": False,
                            "evidence": None,
                        },
                    ],
                }
            ],
        }
        report = build_pentest_report([endpoint])

        self.assertEqual(
            report["endpoint_assessments"][0]["assessment"],
            "Inconclusive",
        )
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["status"], "potential")
        self.assertEqual(report["findings"][0]["evidence"], evidence)
        raw_case = report["test_results"][0]["test_cases"][0]
        self.assertEqual(raw_case["test_case"], "without_token")
        self.assertEqual(raw_case["evidence"], evidence)

    def test_expired_coverage_gap_does_not_create_unsupported_finding(self):
        endpoint = {
            "method": "GET",
            "path": "/api/orders/check/",
            "discovery_source": "discovery",
            "discovered": True,
            "jwt_selected": True,
            "test_results": [
                {
                    "status": "inconclusive",
                    "test_cases": [
                        {
                            "test_case": "without_token",
                            "status": "not_detected_in_this_test",
                            "request_attempted": True,
                            "evidence": {
                                "status_code": 200,
                                "protected_data_observed": False,
                                "authentication_denied": True,
                                "denial_basis": "response_body",
                            },
                        },
                        {
                            "test_case": "invalid_token",
                            "status": "not_detected_in_this_test",
                            "request_attempted": True,
                            "evidence": {
                                "status_code": 401,
                                "protected_data_observed": False,
                                "authentication_denied": True,
                                "denial_basis": "http_status",
                            },
                        },
                        {
                            "test_case": "expired_token",
                            "status": "skipped",
                            "reason": "Expired-token probing is not implemented.",
                            "implementation_status": "not_implemented",
                            "request_attempted": False,
                            "evidence": None,
                        },
                    ],
                }
            ],
        }

        report = build_pentest_report([endpoint])

        self.assertEqual(report["findings"], [])
        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"],
            "inconclusive",
        )

    def test_denied_unauthenticated_and_invalid_requests_with_valid_control_are_not_findings(self):
        candidate_endpoint = {
            "method": "GET",
            "path": "/api/orders/check/",
        }
        with patch(
            "module.authentication_test.Signin.configured_auth",
            return_value=({"payload": {}}, [], None),
        ), patch.object(
            self.authentication_test,
            "_signin_once",
            return_value={
                "token": "test-token",
                "auth_header": "Authorization",
                "auth_scheme": "Bearer",
                "auth_scheme_source": "configured",
                "mechanism": "JWT over Bearer",
                "http_status": 200,
                "response_content_type": "application/json",
            },
        ), patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(200, {"message": "Unauthorized"}),
                response(401, {"message": "invalid token"}),
                response(200, {"orders": [{"id": 17, "total": 35}]}),
            ],
        ):
            result = self.authentication_test.evaluate(
                "http://127.0.0.1:8085",
                {
                    "endpoint": candidate_endpoint,
                    "path": candidate_endpoint["path"],
                    "method": "GET",
                    "reason": "selected by test",
                },
            )

        cases = {case["test_case"]: case for case in result["test_cases"]}
        self.assertEqual(result["status"], "not_vulnerable_in_test")
        self.assertEqual(
            cases["without_token"]["status"], "not_detected_in_this_test"
        )
        self.assertEqual(
            cases["invalid_token"]["status"], "not_detected_in_this_test"
        )
        self.assertEqual(
            cases["valid_token"]["status"], "not_detected_in_this_test"
        )
        self.assertEqual(cases["expired_token"]["status"], "skipped")
        self.assertTrue(cases["valid_token"]["evidence"]["protected_data_observed"])

        endpoint = {
            **candidate_endpoint,
            "discovery_source": "discovery",
            "discovered": True,
            "jwt_selected": True,
            "test_results": [result],
        }
        report = build_pentest_report([endpoint])
        self.assertEqual(report["findings"], [])
        self.assertEqual(
            report["endpoint_assessments"][0]["assessment"],
            "Partially tested",
        )
        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"],
            "inconclusive",
        )

    def test_expired_token_skip_does_not_remove_confirmed_missing_jwt_finding(self):
        _, result = self.evaluate_missing_token_body(
            {"orders": [{"id": 17, "total": 35}]},
            authentication_required=True,
        )
        endpoint = {
            "method": "GET",
            "path": "/api/orders/check/",
            "discovery_source": "discovery",
            "discovered": True,
            "jwt_selected": True,
            "test_results": [result],
        }
        report = build_pentest_report([endpoint])

        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["status"], "confirmed")
        self.assertEqual(report["findings"][0]["test_case"], "without_token")
        self.assertEqual(
            report["endpoint_assessments"][0]["assessment"],
            "Partially tested",
        )
        self.assertIn(
            "Expired-token probing is not implemented",
            report["endpoint_assessments"][0]["reason"],
        )

    def test_case_classification_reports_potential_from_protected_data_signal(self):
        result = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders/check/",
            "No Authorization header.",
            {
                "status_code": 200,
                "content_type": "application/json",
                "body_bytes": 44,
                "json_keys": ["orders"],
                "protected_data_observed": True,
                "resource_records_observed": True,
                "resource_record_samples": [
                    {"path": "$.orders[0]", "fields": {"id": "<redacted:number>"}}
                ],
                "authentication_denied": False,
            },
        )

        self.assertEqual(result["status"], "potential")
        self.assertIn("remain unverified", result["reason"])
        self.assertTrue(result["unverified"])
        self.assertTrue(result["request_attempted"])

    def test_case_classification_uses_not_detected_without_claiming_security(self):
        result = AuthenticationTest._case_result(
            "invalid_token",
            "GET",
            "/api/inventory",
            "Malformed token value.",
            {
                "status_code": 401,
                "protected_data_observed": False,
                "authentication_denied": True,
                "body_available": True,
                "response_is_json": True,
            },
        )

        self.assertEqual(result["status"], "not_detected_in_this_test")
        self.assertIn("authorization denial", result["reason"])
        self.assertIn("intended", result["unverified"])

    def test_case_classification_marks_request_error_inconclusive(self):
        result = AuthenticationTest._case_result(
            "without_token",
            "GET",
            "/api/orders/check/",
            "No Authorization header.",
            {"execution_status": "error", "reason": "Request timed out."},
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertTrue(result["request_attempted"])

    @patch.dict(os.environ, {}, clear=True)
    def test_shared_selector_prefers_self_route_and_excludes_debug_route(self):
        discovered = [
            {"method": "GET", "path": "/api/orders/123", "responses": [{"sc": 401}]},
            {
                "method": "GET",
                "path": "/api/orders/debug/forwarded",
                "responses": [{"sc": 401}],
            },
            {"method": "GET", "path": "/api/users/me", "responses": [{"sc": 200}]},
        ]

        selected = self.endpoint_selector.select_authentication_candidate(discovered)

        self.assertEqual(selected["path"], "/api/users/me")
        self.assertEqual(
            self.endpoint_selector.classify_endpoint(discovered[0])["classification"],
            "resource_by_id",
        )
        self.assertEqual(
            self.endpoint_selector.classify_endpoint(discovered[1])["classification"],
            "other",
        )

    def test_both_unauthenticated_requests_denied(self):
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(401, {"message": "unauthorized"}), response(403, {})],
        ) as request:
            result = self.authentication_test.evaluate(
                "http://127.0.0.1:8085",
                self.modules.select_authentication_candidate([]),
            )

        self.assertEqual(result["status"], "inconclusive")
        self.assertNotIn("Authorization", str(result["evidence"]))
        self.assertIn("expected access policy could not be established", result["reason"])
        invalid_header = request.call_args_list[1].kwargs["headers"]["Authorization"]
        self.assertTrue(invalid_header.startswith("Bearer "))
        token = invalid_header.split(" ", 1)[1]
        header, payload, signature = token.split(".")

        def decode_segment(value):
            return json.loads(
                base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            )

        self.assertEqual(
            decode_segment(header), {"alg": "HS256", "typ": "JWT"}
        )
        self.assertEqual(
            decode_segment(payload)["sub"],
            "microscan-invalid-signature-probe",
        )
        self.assertTrue(signature)
        self.assertNotIn(token, str(result))
        self.assertEqual(
            invalid_header,
            f"Bearer {AuthenticationTest.INVALID_TOKEN}",
        )

    def test_structured_data_without_credentials_is_potential(self):
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(200, {"data": {"id": 1, "name": "lab-user"}}),
                response(401, {"message": "invalid token"}),
            ],
        ):
            result = self.modules.evaluate_authentication_test("http://127.0.0.1:8085")

        self.assertEqual(result["status"], "potential")
        self.assertNotIn("lab-user", str(result["evidence"]))

    def test_unknown_statuses_are_inconclusive(self):
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(404, {}), response(405, {})],
        ):
            result = self.modules.evaluate_authentication_test("http://127.0.0.1:8085")

        self.assertEqual(result["status"], "inconclusive")

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_AUTH_CONFIG": (
                '{"payload":{"user":"lab"},"login_endpoint":"/api/auth/login",'
                '"auth_scheme":"Bearer"}'
            ),
            "MICROSCAN_PROTECTED_ENDPOINT": "/api/me",
        },
        clear=True,
    )
    def test_valid_lab_token_is_used_only_for_configured_protected_route(self):
        with patch(
            "module.authentication_test.Signin.signin",
            return_value={
                "token": "valid-secret-token",
                "auth_header": "Authorization",
                "auth_scheme": "Bearer",
                "mechanism": "JWT over Bearer",
                "http_status": 200,
                "response_content_type": "application/json",
            },
        ), patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(401, {"message": "unauthorized"}),
                response(401, {"message": "invalid token"}),
                response(200, {"user": {"id": 1}}),
            ],
        ) as request:
            result = self.modules.evaluate_authentication_test("http://127.0.0.1:8085")

        self.assertEqual(result["status"], "not_vulnerable_in_test")
        self.assertEqual(request.call_count, 3)
        self.assertTrue(
            request.call_args_list[-1].kwargs["headers"]["Authorization"].startswith(
                "Bearer "
            )
        )
        self.assertNotIn("valid-secret-token", str(result))

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_LOGIN_PAYLOAD": (
                '{"username":"lab-user","password":"lab-password"}'
            ),
        },
        clear=True,
    )
    def test_discovered_login_token_is_sent_to_authenticated_probe(self):
        token = "header.payload.signature"
        discovered = [
            {"method": "GET", "path": "/api/users/me", "responses": [{"sc": 401}]},
            {"method": "POST", "path": "/api/auth/login", "responses": [{"sc": 200}]},
        ]
        login_response = httpx.Response(
            200,
            json={"message": "logged in", "token": token},
            headers={"content-type": "application/json"},
            request=httpx.Request(
                "POST",
                "http://127.0.0.1:8085/api/auth/login",
            ),
        )
        with patch("module.signin.httpx.post", return_value=login_response) as post, patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(401, {"message": "unauthorized"}),
                response(401, {"message": "invalid token"}),
                response(200, {"user": {"id": 5}}),
            ],
        ) as request:
            selected = self.endpoint_selector.select_authentication_candidate(discovered)
            result = self.authentication_test.evaluate(
                "http://127.0.0.1:8085",
                selected,
                discovered,
            )

        self.assertEqual(
            post.call_args.kwargs["json"],
            {"username": "lab-user", "password": "lab-password"},
        )
        self.assertFalse(post.call_args.kwargs["follow_redirects"])
        self.assertEqual(result["authenticated_check"]["status"], "tested")
        self.assertEqual(
            result["authenticated_check"]["auth_scheme_source"],
            "jwt_format_default",
        )
        self.assertIn("inferred from JWT format", result["authentication_mechanism"])
        self.assertTrue(
            request.call_args_list[-1].kwargs["headers"]["Authorization"].endswith(token)
        )
        self.assertNotIn(token, str(result))
        self.assertNotIn("lab-password", str(result))

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_AUTH_CONFIG": (
                '{"payload":{"username":"lab","password":"secret"},'
                '"login_endpoint":"/api/auth/login"}'
            ),
        },
        clear=True,
    )
    def test_real_login_failure_is_reported_without_credentials(self):
        discovered = [
            {"method": "GET", "path": "/api/users/me", "responses": [{"sc": 401}]},
            {"method": "POST", "path": "/api/auth/login", "responses": [{"sc": 200}]},
        ]
        login_response = httpx.Response(
            401,
            json={"error": "invalid credentials", "password": "must-not-leak"},
            request=httpx.Request("POST", "http://127.0.0.1:8085/api/auth/login"),
        )
        with patch("module.signin.httpx.post", return_value=login_response), patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(401, {"message": "unauthorized"}),
                response(401, {"message": "invalid token"}),
            ],
        ):
            selected = self.endpoint_selector.select_authentication_candidate(discovered)
            result = self.authentication_test.evaluate(
                "http://127.0.0.1:8085",
                selected,
                discovered,
            )

        self.assertEqual(result["authenticated_check"]["status"], "error")
        self.assertEqual(result["authenticated_check"]["login_status"], 401)
        self.assertNotIn("secret", str(result))
        self.assertNotIn("must-not-leak", str(result))

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/users/me"}]'
            )
        },
        clear=True,
    )
    def test_unauthenticated_probes_run_without_login_configuration(self):
        discovered = [
            {"method": "GET", "path": "/api/users/me", "responses": [{"sc": 401}]},
            {"method": "POST", "path": "/v2/auth/token", "responses": [{"sc": 200}]},
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(401, {}), response(401, {})],
        ) as request, patch("module.authentication_test.Signin.signin") as login:
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        result = next(item for item in analyzed if item["test_results"])["test_results"][0]
        self.assertEqual(request.call_count, 2)
        login.assert_not_called()
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["authenticated_check"]["status"], "skipped")
        self.assertEqual(result["authentication_mechanism"], "unknown")
        self.assertEqual(
            result["discovery"]["discovered_login_endpoints"][0]["path"],
            "/v2/auth/token",
        )

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/orders/1"},'
                '{"method":"GET","path":"/api/users/me"}]'
            )
        },
        clear=True,
    )
    def test_allowlisted_matrix_is_independent_and_deduplicates_discovery(self):
        discovered = [
            {"method": "GET", "path": "/api/orders/1", "responses": [{"sc": 401}]},
            {"method": "GET", "path": "/api/orders/1", "responses": [{"sc": 401}]},
            {"method": "GET", "path": "/api/users/me", "responses": [{"sc": 401}]},
            {"method": "PUT", "path": "/api/orders/1", "responses": [{"sc": 200}]},
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(401, {"message": "unauthorized"}),
                response(401, {"message": "invalid token"}),
                response(401, {"message": "unauthorized"}),
                response(200, {"user": {"id": 1}}),
            ],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        by_identity = {
            (endpoint["method"], endpoint["path"]): endpoint for endpoint in analyzed
        }
        self.assertEqual(len(analyzed), 3)
        self.assertEqual(request.call_count, 4)
        self.assertEqual(
            by_identity[("GET", "/api/orders/1")]["test_results"][0]["test_cases"][1]["status"],
            "not_detected_in_this_test",
        )
        self.assertEqual(
            by_identity[("GET", "/api/users/me")]["test_results"][0]["test_cases"][1]["status"],
            "potential",
        )
        self.assertEqual(
            by_identity[("GET", "/api/users/me")]["test_results"][0]["test_cases"][-1][
                "status"
            ],
            "skipped",
        )
        self.assertIn(
            "signing key",
            by_identity[("GET", "/api/users/me")]["test_results"][0]["test_cases"][-1][
                "reason"
            ],
        )
        self.assertEqual(
            by_identity[("PUT", "/api/orders/1")]["test_results"][0]["status"],
            "skipped",
        )
        self.assertEqual(
            [call.args[0] for call in request.call_args_list],
            ["GET", "GET", "GET", "GET"],
        )

    @patch.dict(os.environ, {"MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]"}, clear=True)
    def test_auto_selection_uses_discovery_status_and_protected_paths_on_loopback(self):
        discovered = [
            {"method": "GET", "path": "/api/orders/1", "responses": [{"sc": 401}]},
            {"method": "GET", "path": "/api/orders/check/", "status": 200},
            {"method": "GET", "path": "/api/auth/login", "status": 401},
            {"method": "GET", "path": "/api/health", "status": 401},
            {"method": "POST", "path": "/api/users", "status": 401},
            {"method": "GET", "path": "/api/search", "status": 200},
            {"method": "GET", "path": "/api/unknown", "status": 403},
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(401, {}),
                response(401, {}),
                response(401, {}),
                response(401, {}),
                response(403, {}),
                response(403, {}),
            ],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://localhost:8085",
                discovered,
                auto_jwt_local_lab=True,
            )

        by_path = {endpoint["path"]: endpoint for endpoint in analyzed}
        self.assertEqual(
            {
                path
                for path, endpoint in by_path.items()
                if endpoint["jwt_selected"]
            },
            {"/api/orders/1", "/api/orders/check/"},
        )
        self.assertEqual(request.call_count, 4)
        self.assertEqual(by_path["/api/auth/login"]["test_results"][0]["status"], "skipped")
        self.assertIn("login", by_path["/api/auth/login"]["jwt_selection_reason"])
        self.assertEqual(by_path["/api/health"]["test_results"][0]["status"], "skipped")
        self.assertEqual(by_path["/api/users"]["test_results"][0]["status"], "skipped")
        self.assertEqual(by_path["/api/search"]["test_results"][0]["status"], "skipped")
        self.assertIn("HTTP 200", by_path["/api/orders/check/"]["jwt_selection_reason"])
        self.assertFalse(by_path["/api/unknown"]["jwt_selected"])

    @patch.dict(os.environ, {"MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]"}, clear=True)
    def test_auto_selection_uses_one_priority_representative_per_route_shape(self):
        discovered = [
            {"method": "GET", "path": "/api/orders/1", "status": 200},
            {"method": "GET", "path": "/api/orders/2", "status": 401},
            {"method": "GET", "path": "/api/orders/3", "status": 403},
            {"method": "GET", "path": "/api/inventory", "status": 200},
            {"method": "GET", "path": "/api/inventory/", "status": 200},
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(401, {}) for _ in range(6)],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://localhost:8085",
                discovered,
                auto_jwt_local_lab=True,
            )

        by_path = {endpoint["path"]: endpoint for endpoint in analyzed}
        selected = {
            path for path, endpoint in by_path.items() if endpoint["jwt_selected"]
        }
        self.assertEqual(
            selected,
            {"/api/orders/1", "/api/inventory", "/api/inventory/"},
        )
        self.assertEqual(request.call_count, 6)
        self.assertEqual(by_path["/api/orders/2"]["test_results"][0]["status"], "skipped")
        self.assertEqual(by_path["/api/orders/3"]["test_results"][0]["status"], "skipped")
        self.assertIn("/api/orders/1", by_path["/api/orders/2"]["jwt_selection_reason"])
        self.assertIn("/api/orders/1", by_path["/api/orders/3"]["jwt_selection_reason"])
        self.assertNotEqual(
            self.modules._automatic_route_group("/api/inventory"),
            self.modules._automatic_route_group("/api/inventory/"),
        )
        self.assertNotEqual(
            self.modules._automatic_route_group("/api/v1/orders"),
            self.modules._automatic_route_group("/api/v2/orders"),
        )

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]",
            "MICROSCAN_JWT_ENDPOINT_BUDGET": "2",
        },
        clear=True,
    )
    def test_200_sensitive_routes_are_prioritized_with_configured_budget(self):
        discovered = [
            {"method": "GET", "path": "/api/inventory", "status": 401},
            {"method": "GET", "path": "/api/users", "status": 200},
            {"method": "GET", "path": "/api/orders/check/", "status": 200},
            {"method": "GET", "path": "/api/admin/dashboard", "status": 200},
            {"method": "GET", "path": "/api/products", "status": 403},
            {"method": "POST", "path": "/api/inventory", "status": 401},
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(401, {}) for _ in range(4)],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://localhost:8085",
                discovered,
                auto_jwt_local_lab=True,
            )

        by_identity = {
            (endpoint["method"], endpoint["path"]): endpoint
            for endpoint in analyzed
        }
        self.assertTrue(by_identity[("GET", "/api/orders/check/")]["jwt_selected"])
        self.assertTrue(
            by_identity[("GET", "/api/admin/dashboard")]["jwt_selected"]
        )
        self.assertFalse(by_identity[("GET", "/api/inventory")]["jwt_selected"])
        self.assertIn(
            "limited to 2 endpoint groups",
            by_identity[("GET", "/api/inventory")]["jwt_selection_reason"],
        )
        self.assertFalse(by_identity[("POST", "/api/inventory")]["jwt_selected"])
        self.assertEqual(request.call_count, 4)
        self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    @patch.dict(os.environ, {"MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]"}, clear=True)
    def test_auto_selection_is_bounded_to_five_priority_route_groups(self):
        discovered = [
            {"method": "GET", "path": f"/api/orders/{identifier}", "status": 401}
            for identifier in range(1, 8)
        ]
        discovered.extend(
            [
                {"method": "GET", "path": f"/api/users/{identifier}", "status": 200}
                for identifier in range(1, 4)
            ]
        )
        discovered.extend(
            [
                {"method": "GET", "path": "/api/inventory", "status": 200},
                {"method": "GET", "path": "/api/products", "status": 200},
                {"method": "GET", "path": "/api/accounts", "status": 200},
                {"method": "GET", "path": "/api/admin", "status": 200},
                {"method": "GET", "path": "/api/billing", "status": 200},
                {"method": "GET", "path": "/api/projects", "status": 200},
            ]
        )
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(401, {}) for _ in range(10)],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://localhost:8085",
                discovered,
                auto_jwt_local_lab=True,
            )

        selected = [endpoint for endpoint in analyzed if endpoint["jwt_selected"]]
        skipped = [endpoint for endpoint in analyzed if not endpoint["jwt_selected"]]
        self.assertEqual(len(selected), 5)
        self.assertEqual(request.call_count, 10)
        self.assertEqual(len(skipped), 11)
        self.assertTrue(
            any(
                "same route shape" in endpoint["jwt_selection_reason"]
                for endpoint in skipped
            )
        )
        self.assertTrue(
            any(
                "limited to 5 endpoint groups" in endpoint["jwt_selection_reason"]
                for endpoint in skipped
            )
        )

    @patch.dict(os.environ, {"MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]"}, clear=True)
    def test_discovery_query_or_external_origin_is_never_probed(self):
        discovered = [
            {
                "method": "GET",
                "target": "http://localhost:8085/api/orders/1?next=/other",
                "status": 401,
            }
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://localhost:8085",
                discovered,
                auto_jwt_local_lab=True,
            )

        request.assert_not_called()
        self.assertFalse(analyzed[0]["jwt_selected"])
        self.assertIn("query or fragment", analyzed[0]["jwt_selection_reason"])

    @patch.dict(os.environ, {"MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]"}, clear=True)
    def test_auto_selection_requires_enabled_local_mode_and_loopback(self):
        with patch.object(
            self.authentication_test,
            "_run_http_request",
        ) as request:
            not_confirmed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                [{"method": "GET", "path": "/api/orders/1", "status": 401}],
            )
            non_local = self.modules.analyze_endpoints(
                "https://example.test",
                [{"method": "GET", "path": "/api/orders/1", "status": 401}],
                auto_jwt_local_lab=True,
            )

        request.assert_not_called()
        self.assertFalse(not_confirmed[0]["jwt_selected"])
        self.assertIn("disabled for this scan", not_confirmed[0]["jwt_selection_reason"])
        self.assertFalse(non_local[0]["jwt_selected"])
        self.assertIn("loopback target", non_local[0]["jwt_selection_reason"])

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/orders/1"}]'
            )
        },
        clear=True,
    )
    def test_allowlist_remains_required_boundary_when_auto_mode_is_confirmed(self):
        discovered = [
            {"method": "GET", "path": "/api/orders/1", "status": 401},
            {"method": "GET", "path": "/api/users/2", "status": 401},
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(401, {}), response(401, {})],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "https://example.test",
                discovered,
                auto_jwt_local_lab=True,
            )

        self.assertEqual(request.call_count, 2)
        self.assertTrue(analyzed[0]["jwt_selected"])
        self.assertFalse(analyzed[1]["jwt_selected"])
        self.assertEqual(analyzed[1]["test_results"][0]["status"], "skipped")
        self.assertEqual(analyzed[0]["jwt_selection_mode"], "explicit_allowlist")

    @patch.dict(os.environ, {"MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]"}, clear=True)
    def test_discovery_path_on_different_origin_is_skipped(self):
        discovered = [
            {
                "method": "GET",
                "target": "http://outside.test/api/orders/1",
                "status": 401,
            }
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://localhost:8085",
                discovered,
                auto_jwt_local_lab=True,
            )

        request.assert_not_called()
        self.assertFalse(analyzed[0]["jwt_selected"])
        self.assertIn("outside the configured target origin", analyzed[0]["jwt_selection_reason"])

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/a"},'
                '{"method":"GET","path":"/api/b"}]'
            )
        },
        clear=True,
    )
    def test_request_error_on_one_endpoint_does_not_stop_matrix(self):
        discovered = [
            {"method": "GET", "path": "/api/a"},
            {"method": "GET", "path": "/api/b"},
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                httpx.TimeoutException("timeout"),
                response(401, {}),
                response(401, {}),
                response(401, {}),
            ],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        self.assertEqual(request.call_count, 4)
        self.assertEqual(
            analyzed[0]["test_results"][0]["test_cases"][0]["status"],
            "inconclusive",
        )
        self.assertEqual(
            analyzed[1]["test_results"][0]["test_cases"][0]["status"],
            "not_detected_in_this_test",
        )

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_AUTH_CONFIG": (
                '{"payload":{"user":"lab"},"login_endpoint":"/api/auth/login",'
                '"auth_scheme":"Bearer"}'
            ),
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/a"},'
                '{"method":"GET","path":"/api/b"}]'
            ),
        },
        clear=True,
    )
    def test_configured_login_is_reused_for_all_allowlisted_endpoints(self):
        discovered = [
            {"method": "GET", "path": "/api/a"},
            {"method": "GET", "path": "/api/b"},
        ]
        with patch(
            "module.authentication_test.Signin.signin",
            return_value={
                "token": "valid-secret-token",
                "auth_header": "Authorization",
                "auth_scheme": "Bearer",
                "mechanism": "JWT over Bearer",
                "http_status": 200,
                "response_content_type": "application/json",
            },
        ) as login, patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(401, {"message": "unauthorized"}),
                response(401, {"message": "invalid token"}),
                response(200, {"user": {"id": 1}}),
                response(401, {}),
                response(401, {}),
                response(200, {"user": {"id": 2}}),
            ],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        login.assert_called_once()
        self.assertEqual(request.call_count, 6)
        self.assertEqual(len(analyzed), 2)
        self.assertNotIn("valid-secret-token", str(analyzed))

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/items/1"},'
                '{"method":"PUT","path":"/api/items/1"}]'
            )
        },
        clear=True,
    )
    def test_methods_are_independent_and_non_get_allowlist_is_skipped(self):
        discovered = [
            {"method": "GET", "path": "/api/items/1"},
            {"method": "POST", "path": "/api/items/1"},
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(401, {}), response(401, {})],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        by_method = {
            endpoint["method"]: endpoint["test_results"][0] for endpoint in analyzed
        }
        self.assertEqual(request.call_count, 2)
        self.assertEqual(by_method["GET"]["status"], "inconclusive")
        self.assertEqual(by_method["POST"]["status"], "skipped")
        self.assertEqual(by_method["PUT"]["status"], "skipped")

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_AUTH_CONFIG": (
                '{"payload":{"user":"lab"},"auth_scheme":"Bearer"}'
            ),
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/users/me"}]'
            ),
        },
        clear=True,
    )
    def test_valid_token_flow_uses_discovered_login_endpoint_and_explicit_config(self):
        discovered = [
            {"method": "GET", "path": "/api/users/me", "responses": [{"sc": 401}]},
            {"method": "POST", "path": "/v2/auth/token", "responses": [{"sc": 200}]},
        ]
        with patch(
            "module.authentication_test.Signin.signin",
            return_value={
                "token": "valid-secret-token",
                "auth_header": "Authorization",
                "auth_scheme": "Bearer",
                "mechanism": "JWT over Bearer",
                "http_status": 200,
                "response_content_type": "application/json",
            },
        ) as login, patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(401, {"message": "unauthorized"}),
                response(401, {"message": "invalid token"}),
                response(200, {"user": {"id": 1}}),
            ],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        result = next(item for item in analyzed if item["test_results"])["test_results"][0]
        login.assert_called_once()
        self.assertEqual(login.call_args.args[1]["login_endpoint"], "/v2/auth/token")
        self.assertEqual(request.call_count, 3)
        self.assertEqual(result["authenticated_check"]["status"], "tested")
        self.assertEqual(result["status"], "not_vulnerable_in_test")
        self.assertNotIn("valid-secret-token", str(result))

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/users/me"}]'
            )
        },
        clear=True,
    )
    def test_orchestrator_selects_endpoint_once_and_passes_it_to_probe_runner(self):
        discovered = [
            {"method": "GET", "path": "/api/users/me", "responses": [{"sc": 401}]},
        ]
        with patch.object(
            self.endpoint_selector,
            "select_authentication_candidate",
            wraps=self.endpoint_selector.select_authentication_candidate,
        ) as select, patch.object(
            self.authentication_test,
            "evaluate",
            return_value={"test_module": "jwt_authentication", "status": "skipped"},
        ) as evaluate:
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        self.assertEqual(select.call_count, 0)
        self.assertEqual(evaluate.call_args.args[1]["path"], "/api/users/me")
        self.assertIn("allowlist", evaluate.call_args.args[1]["reason"])
        self.assertIs(analyzed[0], discovered[0])
        self.assertEqual(analyzed[0]["test_results"][0]["status"], "skipped")

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_AUTH_CONFIG": (
                '{"payload":{"user":"lab"},"login_endpoint":"/api/auth/login"}'
            ),
            "MICROSCAN_PROTECTED_ENDPOINT": "/api/me",
        },
        clear=True,
    )
    def test_observed_auth_challenge_can_supply_the_token_scheme(self):
        with patch(
            "module.authentication_test.Signin.signin",
            return_value={
                "token": "valid-secret-token",
                "auth_header": "Authorization",
                "auth_scheme": None,
                "mechanism": "jwt (token format observed; authorization scheme unknown)",
                "http_status": 200,
                "response_content_type": "application/json",
            },
        ), patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(401, {}, {"www-authenticate": "Bearer"}),
                response(401, {}, {"www-authenticate": "Bearer"}),
                response(200, {"user": {"id": 1}}),
            ],
        ) as request:
            result = self.modules.evaluate_authentication_test("http://127.0.0.1:8085")

        self.assertEqual(result["authenticated_check"]["status"], "tested")
        self.assertEqual(result["authentication_mechanism"], "JWT over Bearer (challenge observed)")
        self.assertTrue(
            request.call_args_list[-1].kwargs["headers"]["Authorization"].startswith(
                "Bearer "
            )
        )

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_AUTH_CONFIG": '{"payload":{"user":"lab"},"auth_scheme":"Bearer"}',
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/users/me"}]'
            ),
        },
        clear=True,
    )
    def test_login_failure_does_not_interrupt_unauthenticated_testing(self):
        discovered = [
            {"method": "GET", "path": "/api/users/me", "responses": [{"sc": 401}]},
            {"method": "POST", "path": "/v2/auth/token", "responses": [{"sc": 200}]},
        ]
        with patch(
            "module.authentication_test.Signin.signin",
            side_effect=LoginError("Login endpoint returned HTTP 401.", status_code=401),
        ), patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(401, {}), response(403, {})],
        ) as request:
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        result = next(item for item in analyzed if item["test_results"])["test_results"][0]
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["unauthenticated_checks"][0]["status_code"], 401)
        self.assertEqual(result["authenticated_check"]["status"], "error")
        self.assertEqual(result["status"], "inconclusive")
        self.assertNotIn("password", str(result))

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/users/me"}]'
            )
        },
        clear=True,
    )
    def test_automatically_selects_discovered_safe_get_endpoint(self):
        discovered = [
            {
                "method": "GET",
                "path": "/api/orders/debug/forwarded",
                "responses": [{"sc": 401}],
            },
            {
                "method": "GET",
                "path": "/api/orders/123",
                "responses": [{"sc": 401}],
            },
            {
                "method": "POST",
                "path": "/api/auth/login",
                "responses": [{"sc": 200}],
            },
            {
                "method": "GET",
                "path": "/api/orders/42",
                "responses": [{"sc": 200}],
            },
            {
                "method": "GET",
                "path": "/api/users/me",
                "responses": [{"sc": 200}],
            },
        ]
        with patch.object(
            AuthenticationTest,
            "_run_http_request",
            side_effect=[response(401, {}), response(401, {})],
        ) as request, patch(
            "module.authentication_test.Signin.signin",
            side_effect=LoginConfigurationError("missing login payload"),
        ):
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        selected = next(item for item in analyzed if item["path"] == "/api/users/me")
        self.assertEqual(selected["path"], "/api/users/me")
        self.assertEqual(selected["method"], "GET")
        result = selected["test_results"][0]
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("allowlist", result["endpoint_selection_reason"])
        self.assertEqual(request.call_count, 2)

        debug_endpoint = analyzed[0]
        self.assertEqual(debug_endpoint["classification"], "other")
        self.assertEqual(debug_endpoint["test_results"][0]["status"], "skipped")

    @patch.dict(os.environ, {}, clear=True)
    def test_numeric_resource_id_is_preferred_and_debug_route_is_excluded(self):
        discovered = [
            {
                "method": "GET",
                "path": "/api/orders/debug/forwarded",
                "responses": [{"sc": 401}],
            },
            {
                "method": "GET",
                "path": "/api/orders/123",
                "responses": [{"sc": 401}],
            },
        ]
        candidate = self.modules.select_authentication_candidate(discovered)

        self.assertEqual(candidate["path"], "/api/orders/123")
        self.assertEqual(
            self.modules.classify_endpoint(discovered[0])["classification"],
            "other",
        )
        self.assertEqual(
            self.modules.classify_endpoint(discovered[1])["classification"],
            "resource_by_id",
        )
        self.assertIn("candidate signal only", candidate["reason"])

    @patch.dict(os.environ, {}, clear=True)
    def test_debug_route_alone_is_not_a_suitable_candidate(self):
        candidate = self.modules.select_authentication_candidate(
            [
                {
                    "method": "GET",
                    "path": "/api/orders/debug/forwarded",
                    "responses": [{"sc": 401}],
                }
            ]
        )
        self.assertIsNone(candidate)

    @patch.dict(os.environ, {}, clear=True)
    def test_no_safe_candidate_is_skipped_with_exact_reason(self):
        analyzed = self.modules.analyze_endpoints(
            "http://127.0.0.1:8085",
            [
                {"method": "POST", "path": "/api/auth/login"},
                {"method": "POST", "path": "/api/auth/register"},
            ],
        )

        result = analyzed[0]["test_results"][0]
        self.assertEqual(result["status"], "skipped")
        self.assertIn("only GET is supported", result["reason"])

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/users/me"}]'
            )
        },
        clear=True,
    )
    def test_unknown_responses_for_discovered_candidate_are_inconclusive(self):
        discovered = [
            {"method": "POST", "path": "/api/auth/login"},
            {
                "method": "GET",
                "path": "/api/users/me",
                "responses": [{"sc": 404}],
            },
        ]
        with patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[response(404, {}), response(405, {})],
        ):
            analyzed = self.modules.analyze_endpoints(
                "http://127.0.0.1:8085",
                discovered,
            )

        selected = next(item for item in analyzed if item["path"] == "/api/users/me")
        self.assertEqual(selected["test_results"][0]["status"], "inconclusive")
        debug_endpoint = analyzed[0]
        self.assertEqual(debug_endpoint["test_results"][0]["status"], "skipped")

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_AUTH_CONFIG": (
                '{"payload":{"user":"lab"},"login_endpoint":"/api/auth/login",'
                '"auth_scheme":"Bearer"}'
            ),
            "MICROSCAN_PROTECTED_ENDPOINT": "/api/me",
        },
        clear=True,
    )
    def test_valid_token_probe_runs_even_when_unauthenticated_data_is_returned(self):
        with patch(
            "module.authentication_test.Signin.signin",
            return_value={
                "token": "valid-secret-token",
                "auth_header": "Authorization",
                "auth_scheme": "Bearer",
                "mechanism": "JWT over Bearer",
                "http_status": 200,
                "response_content_type": "application/json",
            },
        ), patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(200, {"user": {"id": 1}}),
                response(401, {}),
                response(200, {"user": {"id": 1}}),
            ],
        ) as request:
            result = self.modules.evaluate_authentication_test("http://127.0.0.1:8085")

        self.assertEqual(request.call_count, 3)
        self.assertEqual(result["status"], "potential")
        self.assertEqual(
            result["evidence"][-1]["request"],
            "authenticated",
        )
        self.assertNotIn("valid-secret-token", str(result))

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_AUTH_CONFIG": (
                '{"payload":{"user":"lab"},"login_endpoint":"/api/auth/login",'
                '"auth_scheme":"Bearer"}'
            ),
            "MICROSCAN_PROTECTED_ENDPOINT": "/api/me",
        },
        clear=True,
    )
    def test_not_found_responses_do_not_prove_authentication_is_enforced(self):
        with patch(
            "module.authentication_test.Signin.signin",
            return_value={
                "token": "valid-secret-token",
                "auth_header": "Authorization",
                "auth_scheme": "Bearer",
                "mechanism": "JWT over Bearer",
                "http_status": 200,
                "response_content_type": "application/json",
            },
        ), patch.object(
            self.authentication_test,
            "_run_http_request",
            side_effect=[
                response(404, {}),
                response(405, {}),
                response(200, {"user": {"id": 1}}),
            ],
        ):
            result = self.modules.evaluate_authentication_test("http://127.0.0.1:8085")

        self.assertEqual(result["status"], "inconclusive")

    def test_target_origin_rejects_external_endpoint(self):
        with self.assertRaises(ValueError):
            AuthenticationTest._scope_url(
                "http://127.0.0.1:8085",
                "//outside.example/api/me",
            )

    def test_protected_endpoint_rejects_query_data(self):
        with self.assertRaises(ValueError):
            AuthenticationTest._scope_url(
                "http://127.0.0.1:8085",
                "/api/me?token=not-allowed",
            )

    def test_protected_endpoint_configuration_missing_is_skipped(self):
        os.environ.pop("MICROSCAN_PROTECTED_ENDPOINT", None)
        result = self.modules.evaluate_authentication_test("http://127.0.0.1:8085")
        self.assertEqual(result["status"], "skipped")

    def test_discovered_endpoint_is_not_probed_without_explicit_allowlist(self):
        os.environ.pop("MICROSCAN_PROTECTED_ENDPOINT", None)
        with patch.object(
            self.authentication_test,
            "_run_http_request",
        ) as request:
            result = self.modules.evaluate_authentication_test(
                "http://127.0.0.1:8085",
                [{"method": "GET", "path": "/api/users/me"}],
            )

        self.assertEqual(result["status"], "skipped")
        request.assert_not_called()

    def test_security_probe_disables_redirects_and_sets_timeout(self):
        with patch(
            "module.authentication_test.httpx.request",
            return_value=response(302, {}),
        ) as request:
            result = self.authentication_test._run_http_request(
                "GET",
                "http://127.0.0.1:8085/api/me",
            )

        self.assertEqual(result.status_code, 302)
        self.assertFalse(request.call_args.kwargs["follow_redirects"])
        self.assertEqual(
            request.call_args.kwargs["timeout"],
            AuthenticationTest.TIMEOUT_SECONDS,
        )

    def test_non_auth_modules_are_not_advertised(self):
        self.assertEqual(
            self.modules.classify_endpoint({"path": "/api/users/42"})["applicable_tests"],
            [],
        )


class PentestReportTests(unittest.TestCase):
    @staticmethod
    def endpoint_with_cases(*cases):
        return {
            "method": "GET",
            "path": "/api/orders/1",
            "discovery_source": "discovery",
            "discovered": True,
            "test_results": [
                {
                    "test_module": "jwt_authentication",
                    "status": "inconclusive",
                    "reason": "Endpoint-level test summary.",
                    "test_cases": list(cases),
                }
            ],
        }

    @staticmethod
    def case(status, *, test_case="without_token", attempted=True, reason="Evidence"):
        result = {
            "test_case": test_case,
            "method": "GET",
            "path": "/api/orders/1",
            "status": status,
            "request_attempted": attempted,
            "reason": reason,
            "evidence": {
                "status_code": 200,
                "protected_data_observed": True,
                "resource_records_observed": True,
                "resource_record_samples": [
                    {"path": "$.orders[0]", "fields": {"id": "<redacted:number>"}}
                ],
                "authentication_required": status == "confirmed",
                "authorization_denial_detected": False,
            },
        }
        if test_case == "expired_token" and status == "skipped":
            result["implementation_status"] = "not_implemented"
        return result

    def test_confirmed_finding_takes_priority_and_is_not_a_test_status(self):
        report = build_pentest_report(
            [
                self.endpoint_with_cases(
                    self.case("confirmed", test_case="invalid_token")
                )
            ]
        )

        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"],
            "vulnerabilities_confirmed",
        )
        self.assertEqual(report["summary"]["confirmed_findings"], 1)
        self.assertEqual(report["findings"][0]["status"], "confirmed")
        self.assertIn("evidence", report["findings"][0])
        self.assertTrue(report["findings"][0]["recommendation"])
        self.assertEqual(report["findings"][0]["severity"], None)

    def test_report_downgrades_confirmed_cases_with_conflict_or_incomplete_evidence(self):
        for evidence_update in (
            {"body_denial_signal": True},
            {"body_summary_partial": True},
            {"observed_challenge_scheme": "Bearer"},
        ):
            with self.subTest(evidence_update=evidence_update):
                case = self.case("confirmed", test_case="invalid_token")
                case["evidence"].update(evidence_update)
                endpoint = self.endpoint_with_cases(case)
                endpoint["test_results"][0]["status"] = "confirmed"
                report = build_pentest_report([endpoint])

                self.assertEqual(report["summary"]["confirmed_findings"], 0)
                self.assertEqual(report["findings"][0]["status"], "potential")
                self.assertEqual(report["test_results"][0]["status"], "potential")
                self.assertEqual(
                    report["endpoint_assessments"][0]["test_cases"][0]["status"],
                    "potential",
                )

        unsupported_case = self.case("confirmed", test_case="invalid_token")
        unsupported_case["evidence"].update(
            {
                "resource_records_observed": False,
                "resource_record_samples": [],
                "body_summary_partial": True,
            }
        )
        endpoint = self.endpoint_with_cases(unsupported_case)
        endpoint["test_results"][0]["status"] = "confirmed"
        report = build_pentest_report([endpoint])

        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["confirmed_findings"], 0)
        self.assertEqual(report["test_results"][0]["status"], "inconclusive")
        self.assertEqual(
            report["endpoint_assessments"][0]["test_cases"][0]["status"],
            "inconclusive",
        )

    def test_potential_findings_take_priority_over_coverage_gaps(self):
        report = build_pentest_report(
            [
                self.endpoint_with_cases(
                    self.case("potential"),
                    self.case(
                        "skipped",
                        test_case="expired_token",
                        attempted=False,
                        reason="Expired-token probing is not implemented.",
                    ),
                )
            ]
        )

        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"],
            "potential_vulnerabilities_found",
        )
        self.assertEqual(report["summary"]["potential_findings"], 1)
        self.assertEqual(report["summary"]["skipped_tests"], 0)
        self.assertEqual(report["summary"]["not_implemented_test_cases"], 1)

    def test_complete_negative_coverage_concludes_only_for_tested_scope(self):
        report = build_pentest_report(
            [
                self.endpoint_with_cases(
                    self.case("not_vulnerable_in_test", test_case="without_token"),
                    self.case("not_vulnerable_in_test", test_case="invalid_token"),
                )
            ]
        )

        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"],
            "no_vulnerabilities_detected_in_tested_scope",
        )
        self.assertTrue(report["summary"]["coverage_complete"])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["tested_endpoints"], 1)
        self.assertEqual(report["summary"]["request_count"], 2)

    def test_skipped_endpoint_prevents_clean_scope_conclusion(self):
        tested = self.endpoint_with_cases(
            self.case("not_vulnerable_in_test", test_case="without_token")
        )
        untested = {
            "method": "GET",
            "path": "/api/users/1",
            "discovery_source": "discovery",
            "discovered": True,
            "test_results": [
                {
                    "status": "skipped",
                    "test_cases": [
                        self.case(
                            "skipped",
                            attempted=False,
                            reason="Outside selected scope.",
                        )
                    ],
                }
            ],
        }
        report = build_pentest_report([tested, untested])

        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"], "inconclusive"
        )
        self.assertEqual(report["summary"]["untested_endpoints"], 1)
        self.assertEqual(report["summary"]["tested_endpoints"], 1)

    def test_unimplemented_test_case_is_counted_as_coverage_gap(self):
        report = build_pentest_report(
            [
                self.endpoint_with_cases(
                    self.case("not_vulnerable_in_test"),
                    self.case(
                        "skipped",
                        test_case="expired_token",
                        attempted=False,
                        reason="Expired-token probing is not implemented.",
                    ),
                )
            ]
        )

        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"], "inconclusive"
        )
        self.assertEqual(report["summary"]["not_implemented_test_cases"], 1)

    def test_three_completed_cases_and_unimplemented_expired_case_is_partial(self):
        endpoint = self.endpoint_with_cases(
            self.case("not_vulnerable_in_test", test_case="without_token"),
            self.case("not_vulnerable_in_test", test_case="invalid_token"),
            self.case("not_vulnerable_in_test", test_case="valid_token"),
            self.case(
                "skipped",
                test_case="expired_token",
                attempted=False,
                reason="Expired-token probing is not implemented.",
            ),
        )
        report = build_pentest_report([endpoint])

        self.assertEqual(
            report["endpoint_assessments"][0]["assessment"], "Partially tested"
        )
        self.assertIn("not implemented", report["endpoint_assessments"][0]["reason"])
        self.assertEqual(report["summary"]["tested_endpoints"], 1)
        self.assertEqual(report["summary"]["partially_tested_endpoints"], 1)
        self.assertEqual(report["summary"]["passed_test_cases"], 3)
        self.assertEqual(report["summary"]["test_cases_attempted"], 3)
        self.assertEqual(report["summary"]["not_implemented_test_cases"], 1)
        self.assertEqual(report["summary"]["skipped_tests"], 0)
        self.assertEqual(report["summary"]["inconclusive_tests"], 0)
        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"], "inconclusive"
        )

    def test_all_required_cases_can_be_not_detected_without_api_wide_claim(self):
        report = build_pentest_report(
            [
                self.endpoint_with_cases(
                    self.case(
                        "not_detected_in_this_test",
                        test_case="without_token",
                    ),
                    self.case(
                        "not_detected_in_this_test",
                        test_case="invalid_token",
                    ),
                    self.case(
                        "not_detected_in_this_test",
                        test_case="valid_token",
                    ),
                    self.case(
                        "not_detected_in_this_test",
                        test_case="expired_token",
                    ),
                )
            ]
        )

        self.assertEqual(
            report["endpoint_assessments"][0]["assessment"],
            "Not detected in tested cases",
        )
        self.assertEqual(report["summary"]["not_detected_test_cases"], 4)
        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"],
            "no_vulnerabilities_detected_in_tested_scope",
        )
        self.assertIn(
            "does not establish",
            report["summary"]["overall_conclusion"]["message"],
        )

    def test_endpoint_case_request_and_not_implemented_counters_are_separate(self):
        completed = self.endpoint_with_cases(
            self.case("not_vulnerable_in_test", test_case="without_token"),
            self.case(
                "error",
                test_case="invalid_token",
                attempted=True,
                reason="Request timed out.",
            ),
            self.case(
                "skipped",
                test_case="expired_token",
                attempted=False,
                reason="Not implemented in this scanner.",
            ),
        )
        untested = {
            "method": "GET",
            "path": "/api/users/1",
            "discovery_source": "discovery",
            "jwt_selected": False,
            "test_results": [
                {
                    "status": "skipped",
                    "test_cases": [
                        self.case(
                            "skipped",
                            attempted=False,
                            reason="Outside automatic selection scope.",
                        )
                    ],
                }
            ],
        }
        report = build_pentest_report([completed, untested])
        summary = report["summary"]

        self.assertEqual(summary["discovered_endpoints"], 2)
        self.assertEqual(summary["selected_endpoints"], 0)
        self.assertEqual(summary["tested_endpoints"], 1)
        self.assertEqual(summary["partially_tested_endpoints"], 0)
        self.assertEqual(summary["inconclusive_endpoints"], 1)
        self.assertEqual(summary["untested_endpoints"], 1)
        self.assertEqual(summary["test_cases_attempted"], 2)
        self.assertEqual(summary["passed_test_cases"], 1)
        self.assertEqual(summary["error_tests"], 1)
        self.assertEqual(summary["skipped_tests"], 1)
        self.assertEqual(summary["not_implemented_test_cases"], 1)
        self.assertEqual(summary["unattempted_test_cases"], 2)
        self.assertIn("mutually exclusive", summary["test_case_count_note"])
        self.assertEqual(
            summary["skipped_tests"] + summary["not_implemented_test_cases"],
            2,
        )

    def test_legacy_skipped_total_splits_not_implemented_cases_without_overlap(self):
        cases = [
            {
                **self.case(
                    "skipped",
                    test_case=f"expired_token_{index}",
                    attempted=False,
                    reason="Expired-token probe is not implemented.",
                ),
                "implementation_status": "not_implemented",
            }
            for index in range(5)
        ]
        cases.extend(
            self.case(
                "skipped",
                test_case=f"out_of_scope_{index}",
                attempted=False,
                reason="Not selected for testing.",
            )
            for index in range(56)
        )
        report = build_pentest_report([self.endpoint_with_cases(*cases)])

        self.assertEqual(report["summary"]["raw_test_status_counts"]["skipped"], 61)
        self.assertEqual(report["summary"]["not_implemented_test_cases"], 5)
        self.assertEqual(report["summary"]["skipped_tests"], 56)
        self.assertEqual(report["summary"]["unattempted_test_cases"], 61)

    def test_findings_and_raw_test_evidence_are_preserved(self):
        evidence = {
            "status_code": 200,
            "content_type": "application/json",
            "body_bytes": 36,
            "json_keys": ["orders"],
            "protected_data_observed": True,
            "resource_records_observed": True,
            "resource_record_samples": [
                {"path": "$.orders[0]", "fields": {"id": "<redacted:number>"}}
            ],
        }
        endpoint = self.endpoint_with_cases(
            {
                **self.case("potential", test_case="invalid_token"),
                "evidence": evidence,
            }
        )
        endpoint["test_results"][0]["evidence"] = [
            {"request": "invalid_token", **evidence}
        ]
        report = build_pentest_report([endpoint])

        self.assertEqual(report["findings"][0]["evidence"], evidence)
        self.assertEqual(
            report["test_results"][0]["evidence"],
            [{"request": "invalid_token", **evidence}],
        )
        self.assertEqual(
            report["endpoint_assessments"][0]["test_cases"][0]["evidence"],
            evidence,
        )

    def test_unsupported_potential_is_not_created_from_missing_coverage_evidence(self):
        case = self.case("potential")
        case["evidence"] = {
            "status_code": 200,
            "protected_data_observed": True,
        }
        report = build_pentest_report([self.endpoint_with_cases(case)])

        self.assertEqual(report["findings"], [])
        self.assertEqual(
            report["endpoint_assessments"][0]["test_cases"][0]["status"],
            "inconclusive",
        )
        self.assertEqual(report["summary"]["potential_findings"], 0)

    def test_confirmed_finding_requires_verified_policy_evidence(self):
        case = self.case("confirmed")
        case["evidence"].pop("authentication_required")
        report = build_pentest_report([self.endpoint_with_cases(case)])

        self.assertEqual(report["findings"][0]["status"], "potential")
        self.assertEqual(report["summary"]["confirmed_findings"], 0)
        self.assertEqual(report["summary"]["potential_findings"], 1)

    def test_trailing_slash_routes_keep_independent_findings_and_assessments(self):
        endpoints = []
        for path in ("/api/inventory", "/api/inventory/"):
            case = self.case("potential")
            case["path"] = path
            endpoint = self.endpoint_with_cases(case)
            endpoint["path"] = path
            endpoints.append(endpoint)

        report = build_pentest_report(endpoints)

        self.assertEqual(
            [finding["endpoint"] for finding in report["findings"]],
            ["/api/inventory", "/api/inventory/"],
        )
        self.assertEqual(
            [assessment["path"] for assessment in report["endpoint_assessments"]],
            ["/api/inventory", "/api/inventory/"],
        )

    def test_request_error_is_counted_and_prevents_clean_conclusion(self):
        report = build_pentest_report(
            [
                self.endpoint_with_cases(
                    self.case("error", attempted=True, reason="Request timed out.")
                )
            ]
        )

        self.assertEqual(report["summary"]["error_tests"], 1)
        self.assertEqual(report["summary"]["request_count"], 1)
        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"], "inconclusive"
        )

    def test_scan_failure_has_failure_conclusion(self):
        report = build_pentest_report(
            scan_failed=True,
            failure_reason="Discovery process failed.",
        )

        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"], "scan_failed"
        )
        self.assertEqual(report["summary"]["scan_status"], "failed")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["request_count"], 0)

    def test_mixed_statuses_separate_findings_from_test_outcomes(self):
        report = build_pentest_report(
            [
                self.endpoint_with_cases(
                    self.case("potential"),
                    self.case("not_vulnerable_in_test", test_case="invalid_token"),
                    self.case(
                        "skipped",
                        test_case="expired_token",
                        attempted=False,
                        reason="Not implemented.",
                    ),
                    self.case(
                        "error",
                        test_case="valid_token",
                        attempted=True,
                        reason="Authenticated request timed out.",
                    ),
                )
            ]
        )

        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["status"], "potential")
        self.assertEqual(len(report["test_results"]), 1)
        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"],
            "potential_vulnerabilities_found",
        )
        self.assertEqual(report["summary"]["test_cases_run"], 3)
        self.assertEqual(report["summary"]["request_count"], 3)
        self.assertEqual(report["summary"]["skipped_tests"], 0)
        self.assertEqual(report["summary"]["not_implemented_test_cases"], 1)
        self.assertEqual(report["summary"]["error_tests"], 1)


class ScanContractTests(unittest.TestCase):
    def test_discovery_failure_returns_scan_failed_pentest_summary(self):
        from fastapi.testclient import TestClient

        with patch(
            "app.main.Discovery.discover",
            side_effect=RuntimeError("Kiterunner failed."),
        ):
            result = TestClient(app).get(
                "/scan",
                params={"target": "127.0.0.1:8085", "num": 10},
            )

        self.assertEqual(result.status_code, 424)
        payload = result.json()
        self.assertEqual(payload["summary"]["scan_status"], "failed")
        self.assertEqual(
            payload["summary"]["overall_conclusion"]["code"], "scan_failed"
        )
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["summary"]["request_count"], 0)

    @patch.dict(os.environ, {"MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]"}, clear=True)
    def test_confirmed_local_scan_tests_selected_discovery_endpoints_and_reports_counts(self):
        from fastapi.testclient import TestClient

        with patch(
            "app.main.Discovery.discover",
            return_value=[
                {"method": "GET", "path": "/api/orders/1", "status": 401},
                {"method": "POST", "path": "/api/orders/1", "status": 401},
                {"method": "GET", "path": "/api/auth/login", "status": 401},
            ],
        ), patch.object(
            AuthenticationTest,
            "_run_http_request",
            side_effect=[response(401, {}), response(401, {})],
        ) as request:
            result = TestClient(app).get(
                "/scan",
                params={
                    "target": "127.0.0.1:8085",
                    "num": 10,
                    "auto_jwt_local_lab": "true",
                },
            )

        self.assertEqual(result.status_code, 200)
        payload = result.json()
        self.assertEqual(request.call_count, 2)
        self.assertEqual(payload["summary"]["discovered_endpoints"], 3)
        self.assertEqual(payload["summary"]["selected_endpoints"], 1)
        self.assertEqual(payload["summary"]["tested_endpoints"], 1)
        self.assertEqual(payload["summary"]["test_cases_run"], 2)
        self.assertEqual(payload["summary"]["skipped_endpoints"], 2)
        self.assertEqual(payload["summary"]["jwt_selection_mode"], "automatic_local_lab")
        self.assertEqual(
            {result["status"] for result in payload["test_results"]},
            {"inconclusive", "skipped"},
        )

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                '[{"method":"GET","path":"/api/a"}]'
            )
        },
        clear=True,
    )
    def test_scan_summary_separates_discovered_tested_and_skipped_cases(self):
        from fastapi.testclient import TestClient

        with patch(
            "app.main.Discovery.discover",
            return_value=[
                {"method": "GET", "path": "/api/a"},
                {"method": "GET", "path": "/api/b"},
            ],
        ), patch.object(
            AuthenticationTest,
            "_run_http_request",
            side_effect=[
                response(401, {"message": "unauthorized"}),
                response(401, {"message": "invalid token"}),
            ],
        ):
            result = TestClient(app).get(
                "/scan",
                params={"target": "127.0.0.1:8085", "num": 10},
            )

        self.assertEqual(result.status_code, 200)
        summary = result.json()["summary"]
        self.assertEqual(summary["discovered_endpoints"], 2)
        self.assertEqual(summary["tested_endpoints"], 1)
        self.assertEqual(summary["untested_endpoints"], 1)
        self.assertEqual(summary["test_cases_run"], 2)
        self.assertEqual(summary["potential_findings"], 0)
        self.assertEqual(summary["skipped_tests"], 5)
        self.assertEqual(summary["not_implemented_test_cases"], 1)
        self.assertEqual(summary["inconclusive_tests"], 0)
        self.assertTrue(summary["jwt_allowlist_configured"])
        self.assertEqual(summary["jwt_allowlist_entries"], 1)
        self.assertEqual(
            summary["jwt_allowlist_targets"],
            [{"method": "GET", "path": "/api/a"}],
        )

    @patch.dict(os.environ, {}, clear=True)
    def test_empty_allowlist_reports_configuration_gap_and_skips_discovery(self):
        from fastapi.testclient import TestClient

        with patch(
            "app.main.Discovery.discover",
            return_value=[
                {"method": "GET", "path": "/api/a"},
                {"method": "GET", "path": "/api/b"},
            ],
        ), patch.object(
            AuthenticationTest,
            "_run_http_request",
        ) as probe:
            result = TestClient(app).get(
                "/scan",
                params={"target": "127.0.0.1:8085", "num": 10},
            )

        self.assertEqual(result.status_code, 200)
        payload = result.json()
        self.assertFalse(payload["summary"]["jwt_allowlist_configured"])
        self.assertEqual(payload["summary"]["jwt_allowlist_entries"], 0)
        self.assertEqual(payload["summary"]["test_cases_run"], 0)
        self.assertEqual(payload["summary"]["skipped_tests"], 8)
        self.assertEqual(payload["summary"]["not_implemented_test_cases"], 0)
        self.assertTrue(
            all(
                endpoint["test_results"][0]["status"] == "skipped"
                for endpoint in payload["results"]
            )
        )
        probe.assert_not_called()

    def test_existing_scan_route_returns_real_test_evidence_shape(self):
        from fastapi.testclient import TestClient

        endpoint = {"method": "GET", "path": "/api/users/me"}
        test_result = {
            "test_module": "jwt_authentication",
            "status": "skipped",
            "reason": "Protected endpoint configuration is missing.",
            "tested_endpoint": None,
            "endpoint_selection_reason": None,
            "discovery": {"authentication_mechanism": "unknown"},
            "unauthenticated_checks": [],
            "authenticated_check": {
                "status": "skipped",
                "reason": "No credentials configured.",
            },
            "authentication_mechanism": "unknown",
            "evidence": [],
            "test_cases": [
                {
                    "test_case": "without_token",
                    "method": "GET",
                    "path": "/api/users/me",
                    "request_condition": "No request sent.",
                    "status": "skipped",
                    "reason": "No allowlist.",
                    "evidence": None,
                }
            ],
        }

        with patch.dict(
            os.environ,
            {
                "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": (
                    '[{"method":"GET","path":"/api/users/me"}]'
                )
            },
            clear=True,
        ), patch("app.main.Discovery.discover", return_value=[endpoint]), patch.object(
            Modules,
            "evaluate_authentication_test",
            return_value=test_result,
        ):
            response_result = TestClient(app).get(
                "/scan",
                params={"target": "127.0.0.1:8085", "num": 10},
            )

        self.assertEqual(response_result.status_code, 200)
        payload = response_result.json()
        self.assertEqual(payload["target"], "http://127.0.0.1:8085")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["test_results"][0]["status"], "skipped")
        self.assertEqual(payload["test_results"][0]["evidence"], [])
        self.assertIsNone(payload["test_results"][0]["endpoint_selection_reason"])
        self.assertEqual(
            payload["test_results"][0]["authenticated_check"]["status"],
            "skipped",
        )
        self.assertEqual(
            payload["test_results"][0]["authentication_mechanism"],
            "unknown",
        )
        self.assertEqual(payload["results"][0]["test_results"][0]["test_module"], "jwt_authentication")
        self.assertEqual(payload["summary"]["discovered_endpoints"], 1)
        self.assertEqual(payload["summary"]["tested_endpoints"], 0)
        self.assertEqual(payload["summary"]["skipped_tests"], 1)

    def test_scan_requires_an_origin_only_target(self):
        from fastapi.testclient import TestClient

        response_result = TestClient(app).get(
            "/scan",
            params={"target": "http://127.0.0.1:8085/api"},
        )
        self.assertEqual(response_result.status_code, 400)


if __name__ == "__main__":
    unittest.main()
