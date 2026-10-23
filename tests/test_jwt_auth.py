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
from module.signin import LoginConfigurationError, LoginError, Signin


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
                response(401, {}),
                response(401, {}),
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
            side_effect=[response(401, {}), response(401, {})],
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

    @patch.dict(os.environ, {}, clear=True)
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
            "MICROSCAN_AUTH_CONFIG": (
                '{"payload":{"user":"lab"},"auth_scheme":"Bearer"}'
            )
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
                response(401, {}),
                response(401, {}),
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

    @patch.dict(os.environ, {}, clear=True)
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

        self.assertEqual(select.call_count, 1)
        self.assertEqual(evaluate.call_args.args[1]["path"], "/api/users/me")
        self.assertIn("current-user", evaluate.call_args.args[1]["reason"])
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
            "MICROSCAN_AUTH_CONFIG": '{"payload":{"user":"lab"},"auth_scheme":"Bearer"}'
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

    @patch.dict(os.environ, {}, clear=True)
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

        selected = next(item for item in analyzed if item["test_results"])
        self.assertEqual(selected["path"], "/api/users/me")
        self.assertEqual(selected["method"], "GET")
        result = selected["test_results"][0]
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("current-user", result["endpoint_selection_reason"])
        self.assertEqual(request.call_count, 2)
        self.assertIn("candidate signal only", result["endpoint_selection_reason"])

        debug_endpoint = analyzed[0]
        self.assertEqual(debug_endpoint["classification"], "other")
        self.assertEqual(debug_endpoint["test_results"], [])

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
        self.assertIn("No suitable discovered GET endpoint", result["reason"])

    @patch.dict(os.environ, {}, clear=True)
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

        selected = next(item for item in analyzed if item["test_results"])
        self.assertEqual(selected["path"], "/api/users/me")
        self.assertEqual(selected["test_results"][0]["status"], "inconclusive")

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


class ScanContractTests(unittest.TestCase):
    def test_existing_scan_route_returns_real_test_evidence_shape(self):
        from fastapi.testclient import TestClient

        endpoint = {"method": "POST", "path": "/api/auth/login"}
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
        }

        with patch("app.main.Discovery.discover", return_value=[endpoint]), patch.object(
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
        self.assertEqual(payload["findings"][0]["status"], "skipped")
        self.assertEqual(payload["findings"][0]["evidence"], [])
        self.assertIsNone(payload["findings"][0]["endpoint_selection_reason"])
        self.assertEqual(
            payload["findings"][0]["authenticated_check"]["status"],
            "skipped",
        )
        self.assertEqual(
            payload["findings"][0]["authentication_mechanism"],
            "unknown",
        )
        self.assertEqual(payload["results"][0]["test_results"][0]["test_module"], "jwt_authentication")

    def test_scan_requires_an_origin_only_target(self):
        from fastapi.testclient import TestClient

        response_result = TestClient(app).get(
            "/scan",
            params={"target": "http://127.0.0.1:8085/api"},
        )
        self.assertEqual(response_result.status_code, 400)


if __name__ == "__main__":
    unittest.main()
