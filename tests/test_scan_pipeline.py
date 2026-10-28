import json
import os
import unittest
from unittest.mock import AsyncMock, call, patch
from urllib.parse import urlsplit

import httpx
from fastapi.testclient import TestClient

from app.main import (
    RecursiveDiscoveryLimits,
    _authorized_discovered_origins,
    _discovered_loopback_origins,
    app,
)
from module.authentication_test import AuthenticationTest
from module.signin import Signin


FRONTEND = "http://localhost:5000"
GATEWAY = FRONTEND
SECONDARY_ORIGIN = "http://localhost:8085"


def file_discovery_result():
    return {
        "results": [
            {
                "url": f"{FRONTEND}/api/users",
                "verification_url": f"{GATEWAY}/api/users",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "relative_to_frontend": True,
                "is_api_endpoint": True,
                "classification": "api_endpoint",
                "verification_status": "verified",
                "sources": ["javascript", "gateway_verification"],
                "evidence": [
                    {
                        "source_url": f"{FRONTEND}/assets/app.js",
                        "snippet": "fetch('/api/users')",
                    }
                ],
            }
        ],
        "page_sources": [FRONTEND],
        "summary": {"scripts_analyzed": 1, "requests_made": 4},
    }


async def scan_file_discovery(target, **kwargs):
    await kwargs["progress_callback"](
        {
            "stage": "JavaScript Analysis",
            "status": "completed",
            "detail": "Analyzed 1 JavaScript file(s).",
        }
    )
    await kwargs["progress_callback"](
        {
            "stage": "File Discovery",
            "status": "completed",
            "detail": "Collected 1 path and endpoint result(s).",
        }
    )
    return file_discovery_result()


class ScanPipelineTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    @patch.dict(
        os.environ,
        {"MICROSCAN_GATEWAY_TARGET": "http://localhost:8085"},
        clear=True,
    )
    def test_scan_target_scheme_host_and_port_reach_each_pipeline_stage(self):
        for target in (
            "http://localhost:5000",
            "http://localhost:9000",
            "https://127.0.0.1:9443",
        ):
            with self.subTest(target=target), patch(
                "app.main.Discovery.discover", return_value=[]
            ) as kiterunner, patch(
                "app.main.FileDiscovery.scan",
                new_callable=AsyncMock,
                return_value={"results": [], "page_sources": [], "summary": {}},
            ) as file_scan, patch(
                "app.main.Modules.analyze_endpoints", return_value=[]
            ) as security_modules:
                response = self.client.get("/scan", params={"target": target})

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["target"], target)
            self.assertEqual(kiterunner.call_args, call(target, 1000))
            self.assertEqual(file_scan.await_args.args[0], target)
            self.assertEqual(file_scan.await_args.kwargs["gateway_target"], target)
            self.assertEqual(security_modules.call_args.args[0], target)

    def test_invalid_target_returns_a_clear_error_without_scanning(self):
        with patch("app.main.Discovery.discover") as kiterunner:
            response = self.client.get(
                "/scan",
                params={"target": "ftp://localhost:5000"},
            )
            streamed_response = self.client.get(
                "/scan",
                params={"target": "ftp://localhost:5000", "stream": "true"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("valid HTTP(S) origin", response.json()["detail"])
        self.assertIn("valid HTTP(S) origin", streamed_response.text)
        kiterunner.assert_not_called()

    def test_loopback_api_evidence_is_added_without_manual_scope_input(self):
        file_result = {
            "results": [
                {
                    "url": f"{SECONDARY_ORIGIN}/api/orders",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                }
            ]
        }
        with patch("app.main.Discovery.discover", return_value=[]) as discovery, patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ), patch(
            "app.main.Discovery.discover_seeded",
            return_value={"results": [], "exit_code": 0, "result_count": 0},
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ) as security_modules:
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            _discovered_loopback_origins(file_result, FRONTEND),
            {SECONDARY_ORIGIN},
        )
        self.assertEqual(discovery.call_args_list[1].args[0], SECONDARY_ORIGIN)
        seeded_scan.assert_called_once_with(SECONDARY_ORIGIN, ["/api/orders"], 100)
        self.assertEqual(security_modules.call_args.args[0], SECONDARY_ORIGIN)
        self.assertEqual(
            response.json()["summary"]["authorized_scope"],
            [FRONTEND, SECONDARY_ORIGIN],
        )

    def test_loopback_api_evidence_does_not_expand_remote_target_scope(self):
        file_result = {
            "results": [
                {
                    "url": f"{SECONDARY_ORIGIN}/api/orders",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                }
            ]
        }
        self.assertEqual(
            _discovered_loopback_origins(file_result, "https://example.test"),
            set(),
        )

    def test_discovered_urls_are_reduced_to_authorized_origins(self):
        file_result = {
            "results": [
                {
                    "url": "https://api.example.test/api/orders",
                    "sources": ["html"],
                },
                {
                    "url": "https://api.example.test/asdf",
                    "sources": ["wordlist"],
                },
                {
                    "url": "https://outside.invalid/api/orders",
                    "sources": ["javascript"],
                },
                {
                    "template": "/api/orders/${id}",
                    "is_template": True,
                    "url": None,
                    "sources": ["javascript"],
                },
            ]
        }

        self.assertEqual(
            _authorized_discovered_origins(
                file_result,
                ["https://api.example.test", FRONTEND],
            ),
            {"https://api.example.test"},
        )

    def test_verified_javascript_routes_are_tested_on_their_loopback_origin(self):
        api_endpoint = {
            "url": f"{SECONDARY_ORIGIN}/api/orders",
            "resolved_url": f"{SECONDARY_ORIGIN}/api/orders",
            "verification_url": f"{SECONDARY_ORIGIN}/api/orders",
            "method": "GET",
            "is_api_endpoint": True,
            "classification": "api_endpoint",
            "verification_status": "verified",
            "status_code": 200,
            "content_type": "application/json",
            "sources": ["javascript", "gateway_verification"],
            "evidence": [
                {
                    "source_url": f"{FRONTEND}/assets/app.js",
                    "snippet": "fetch('http://localhost:8085/api/orders')",
                }
            ],
        }
        with patch("app.main.Discovery.discover", return_value=[]) as discovery, patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value={
                "results": [api_endpoint],
                "page_sources": [FRONTEND],
                "summary": {},
            },
        ), patch(
            "app.main.Discovery.discover_seeded",
            return_value={"results": [], "exit_code": 0, "result_count": 0},
        ), patch(
            "app.main.Modules.analyze_endpoints",
            side_effect=lambda target, endpoints, **kwargs: endpoints,
        ) as security_modules:
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            SECONDARY_ORIGIN,
            [call.args[0] for call in discovery.call_args_list],
        )
        self.assertEqual(security_modules.call_args.args[0], SECONDARY_ORIGIN)
        self.assertEqual(
            security_modules.call_args.args[1][0]["path"],
            "/api/orders",
        )
        self.assertEqual(response.json()["security_target"], SECONDARY_ORIGIN)

    @patch.dict(os.environ, {"MICROSCAN_GATEWAY_TARGET": GATEWAY}, clear=True)
    def test_main_scan_uses_one_target_for_kiterunner_and_file_discovery(self):
        discovered = [
            {
                "method": "GET",
                "path": "/api/users",
                "responses": [{"sc": 200}],
            }
        ]
        seeded = [
            {
                "method": "GET",
                "path": "/api/orders",
                "responses": [{"sc": 200, "content_type": "application/json"}],
                "discovery_phase": "seeded",
            }
        ]
        with patch(
            "app.main.Discovery.discover", return_value=discovered
        ) as kiterunner, patch(
            "app.main.Discovery.discover_seeded",
            return_value=seeded,
        ) as seeded_kiterunner, patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            side_effect=scan_file_discovery,
        ) as file_scan, patch(
            "app.main.Modules.analyze_endpoints",
            side_effect=lambda target, endpoints, auto_jwt_local_lab=False, **kwargs: endpoints,
        ) as security_tests:
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(kiterunner.call_args_list[0], call(FRONTEND, 1000))
        self.assertEqual(kiterunner.call_count, 1)
        self.assertEqual(seeded_kiterunner.call_count, 2)
        self.assertEqual(
            seeded_kiterunner.call_args_list[0],
            call(GATEWAY, ["/api/users"], 100),
        )
        self.assertEqual(
            seeded_kiterunner.call_args_list[1],
            call(GATEWAY, ["/api/orders"], 100),
        )
        file_scan.assert_awaited_once()
        self.assertEqual(file_scan.await_args.args[0], FRONTEND)
        self.assertEqual(file_scan.await_args.kwargs["gateway_target"], GATEWAY)
        self.assertTrue(file_scan.await_args.kwargs["verify_endpoints"])

        tested_endpoints = security_tests.call_args.args[1]
        matching = [
            item for item in tested_endpoints
            if item["method"] == "GET" and item["path"] == "/api/users"
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(
            set(matching[0]["discovery_sources"]),
            {"javascript", "kiterunner"},
        )
        self.assertEqual(matching[0]["verification_status"], "verified")

        payload = response.json()
        self.assertEqual(payload["discovery_target"], FRONTEND)
        users_record = next(
            item for item in payload["discovery_results"]
            if item.get("resolved_url") == f"{GATEWAY}/api/users"
        )
        self.assertEqual(
            users_record["sources"],
            ["kiterunner", "javascript", "gateway_verification"],
        )
        self.assertEqual(users_record["url"], f"{FRONTEND}/api/users")
        orders_record = next(
            item for item in payload["discovery_results"]
            if item["url"] == f"{GATEWAY}/api/orders"
        )
        self.assertEqual(orders_record["sources"], ["kiterunner_seeded"])
        self.assertEqual(
            users_record["evidence"][0]["source_url"],
            f"{FRONTEND}/assets/app.js",
        )
        self.assertEqual(
            {stage["stage"] for stage in payload["discovery_stages"]},
            {
                "API Discovery",
                "File Discovery",
                "Seeded API Discovery",
                "Recursive Discovery Round 2",
                "Recursive Discovery Summary",
                "Authorized Scope",
                "API Origin Candidates",
                "Seeded API Discovery Eligibility",
                "JavaScript Analysis",
                "Endpoint Correlation",
                "Security Testing",
            },
        )
        self.assertEqual(
            next(item for item in payload["discovery_results"] if item["url"].endswith("/api/users"))["security_status"],
            "skipped",
        )

    @patch.dict(os.environ, {"MICROSCAN_GATEWAY_TARGET": GATEWAY}, clear=True)
    def test_relative_api_seeds_use_the_scan_target_and_are_recorded_in_history(self):
        api_origin = SECONDARY_ORIGIN
        file_result = {
            "page_sources": [FRONTEND],
            "summary": {},
            "results": [
                {
                    "url": f"{api_origin}/",
                    "discovered_url": f"{api_origin}/",
                    "method": "GET",
                    "status_code": 404,
                    "verification_status": "inconclusive",
                    "sources": ["javascript"],
                    "is_api_endpoint": False,
                    "evidence": [{"source_url": f"{FRONTEND}/app.js", "snippet": "baseURL"}],
                },
                {
                    "url": f"{FRONTEND}/api/orders",
                    "resolved_url": f"{api_origin}/api/orders",
                    "discovered_url": "/api/orders",
                    "method": "GET",
                    "relative_to_frontend": True,
                    "is_api_endpoint": True,
                    "verification_status": "discovered",
                    "sources": ["javascript"],
                    "evidence": [{"source_url": f"{FRONTEND}/app.js", "snippet": "fetch('/api/orders')"}],
                },
                {
                    "url": f"{FRONTEND}/api/inventory",
                    "resolved_url": f"{api_origin}/api/inventory",
                    "discovered_url": "/api/inventory",
                    "method": "GET",
                    "relative_to_frontend": True,
                    "is_api_endpoint": True,
                    "verification_status": "discovered",
                    "sources": ["javascript"],
                    "evidence": [{"source_url": f"{FRONTEND}/app.js", "snippet": "fetch('/api/inventory')"}],
                },
                {
                    "url": f"{FRONTEND}/api/auth/login",
                    "resolved_url": f"{api_origin}/api/auth/login",
                    "discovered_url": "/api/auth/login",
                    "method": "POST",
                    "relative_to_frontend": True,
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                    "evidence": [{"source_url": f"{FRONTEND}/app.js", "snippet": "axios.post('/api/auth/login')"}],
                },
                {
                    "url": None,
                    "template": "/api/orders/${encodeURIComponent(id)}",
                    "is_template": True,
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                },
                {
                    "url": "https://outside.invalid/api/admin",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                },
            ],
        }
        execution = {
            "target": api_origin,
            "seed_count": 2,
            "exit_code": 0,
            "result_count": 1,
            "results": [
                {
                    "method": "GET",
                    "path": "/api/orders/1",
                    "responses": [{"sc": 200, "content_type": "application/json"}],
                    "discovery_phase": "seeded",
                }
            ],
        }
        with patch("app.main.DISCOVERY_LIMITS", RecursiveDiscoveryLimits(max_seeds_per_round=2)), patch(
            "app.main.Discovery.discover", return_value=[]
        ) as kiterunner, patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ), patch(
            "app.main.Discovery.discover_seeded",
            return_value=execution,
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(kiterunner.call_args_list[0].args[0], FRONTEND)
        self.assertEqual(kiterunner.call_args_list[1].args[0], api_origin)
        self.assertTrue(kiterunner.call_args_list[1].args[2])
        origin_scan_stage = next(
            stage
            for stage in response.json()["discovery_stages"]
            if stage["stage"] == "API Origin Discovery Round 1"
        )
        self.assertIn("base origin", origin_scan_stage["detail"])
        self.assertIn("independently of JavaScript route seeds", origin_scan_stage["detail"])
        self.assertEqual(seeded_scan.call_count, 3)
        self.assertEqual(
            seeded_scan.call_args_list[0],
            call(api_origin, ["/api/orders", "/api/inventory"], 100),
        )
        self.assertEqual(
            seeded_scan.call_args_list[1],
            call(api_origin, ["/api/auth/login"], 100),
        )
        self.assertEqual(
            seeded_scan.call_args_list[2],
            call(api_origin, ["/api/orders/1"], 100),
        )
        payload = response.json()
        stage = next(
            item for item in payload["discovery_stages"]
            if item["stage"] == "Seeded API Discovery"
        )
        self.assertEqual(stage["status"], "completed")
        self.assertEqual(stage["target"], api_origin)
        self.assertEqual(stage["seed_count"], 2)
        self.assertEqual(stage["exit_code"], 0)
        self.assertEqual(stage["result_count"], 1)
        self.assertIn("2 seed(s)", stage["detail"])
        self.assertIn("exit code 0", stage["detail"])
        self.assertEqual(payload["summary"]["seeded_discovery"]["result_count"], 1)
        self.assertEqual(len(payload["summary"]["discovery_rounds"]), 3)
        self.assertEqual(payload["summary"]["recursive_discovery_stop_reason"], "queue_empty")
        self.assertEqual(payload["summary"]["security_input_endpoints"], 1)
        api_root = next(
            item for item in payload["discovery_results"]
            if item.get("original_url") == f"{api_origin}/"
        )
        self.assertFalse(api_root.get("is_api_endpoint", False))

    @patch.dict(os.environ, {"MICROSCAN_GATEWAY_TARGET": GATEWAY}, clear=True)
    def test_unverified_javascript_endpoint_is_resolved_but_not_security_tested(self):
        js_only = {
            "results": [
                {
                    "url": f"{FRONTEND}/api/orders",
                    "method": "GET",
                    "relative_to_frontend": True,
                    "is_api_endpoint": True,
                    "verification_status": "discovered",
                    "sources": ["javascript"],
                    "evidence": [{"source_url": f"{FRONTEND}/app.js", "snippet": "fetch('/api/orders')"}],
                }
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.Discovery.discover_seeded", return_value=[]
        ), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=js_only,
        ), patch(
            "app.main.Modules.analyze_endpoints",
            side_effect=lambda target, endpoints, auto_jwt_local_lab=False, **kwargs: endpoints,
        ) as security_tests:
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        sent_endpoints = security_tests.call_args.args[1]
        self.assertEqual(sent_endpoints, [])
        inventory = response.json()["discovery_results"]
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["url"], f"{FRONTEND}/api/orders")
        self.assertEqual(inventory[0]["sources"], ["javascript"])
        self.assertEqual(inventory[0]["verification_status"], "discovered")
        self.assertEqual(inventory[0]["resolution_status"], "resolved")
        self.assertEqual(inventory[0]["resolved_url"], f"{GATEWAY}/api/orders")
        self.assertEqual(inventory[0]["security_status"], "skipped")

    @patch.dict(os.environ, {}, clear=True)
    def test_jwt_selection_consumes_resolved_unified_gateway_inventory(self):
        paths = [
            ("/api/inventory", 401),
            ("/api/orders", 401),
            ("/api/users", 401),
            ("/api/admin/dashboard", 401),
            ("/api/auth/session", 401),
            ("/api/auth/login", 405),
            ("/api/auth/register", 405),
        ]
        gateway_results = [
            {
                "method": "GET",
                "path": path,
                "responses": [{"sc": status}],
            }
            for path, status in paths
        ]
        gateway_file_records = [
            {
                "url": f"{GATEWAY}{path}",
                "resolved_url": f"{GATEWAY}{path}",
                "method": "GET",
                "status_code": status,
                "is_api_endpoint": True,
                "verification_status": "blocked",
                "sources": ["javascript"],
                "evidence": [
                    {
                        "source_url": f"{FRONTEND}/assets/app.js",
                        "snippet": f"fetch('{path}')",
                    }
                ],
            }
            for path, status in paths
        ]
        file_result = {
            "results": [
                {
                    "url": f"{GATEWAY}/",
                    "method": "GET",
                    "is_api_endpoint": False,
                    "sources": ["javascript"],
                    "evidence": [
                        {
                            "source_url": f"{FRONTEND}/assets/app.js",
                            "snippet": "const API_BASE = 'http://localhost:8085'",
                        }
                    ],
                },
                *gateway_file_records,
                {
                    "url": None,
                    "template": "/api/orders/${encodeURIComponent(id)}",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "is_template": True,
                    "resolution_status": "unresolved",
                    "sources": ["javascript"],
                    "evidence": [
                        {
                            "source_url": f"{FRONTEND}/assets/app.js",
                            "snippet": "fetch(`/api/orders/${encodeURIComponent(id)}`)",
                        }
                    ],
                },
                {
                    "url": "https://outside.invalid/api/users",
                    "resolved_url": "https://outside.invalid/api/users",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                    "evidence": [],
                },
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }

        def discover(target, *_args):
            if target == FRONTEND:
                return [{"path": "/", "responses": [{"sc": 200}]}]
            return gateway_results

        request_urls = []

        def mocked_jwt_request(method, url, headers=None):
            request_urls.append((method, url, headers))
            return httpx.Response(
                401,
                json={"message": "Unauthorized"},
                request=httpx.Request(method, url),
            )

        login_discovery_records = []

        def missing_valid_token(discovered, **_kwargs):
            login_discovery_records.extend(discovered)
            return None, [], "No configured valid-token credentials."

        with patch("app.main.Discovery.discover", side_effect=discover), patch(
            "app.main.Discovery.discover_seeded",
            return_value={
                "target": GATEWAY,
                "results": [],
                "exit_code": 0,
                "result_count": 0,
            },
        ), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ), patch.object(
            AuthenticationTest,
            "_run_http_request",
            side_effect=mocked_jwt_request,
        ), patch(
            "module.authentication_test.Signin.configured_auth",
            side_effect=missing_valid_token,
        ):
            response = self.client.get(
                "/scan",
                params={
                    "target": FRONTEND,
                    "auto_jwt_local_lab": "true",
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["security_target"], GATEWAY)
        self.assertEqual(payload["summary"]["security_input_endpoints"], 5)
        self.assertEqual(payload["summary"]["discovered_endpoints"], 5)
        self.assertEqual(payload["summary"]["selected_endpoints"], 4)
        self.assertEqual(payload["summary"]["tested_endpoints"], 4)
        self.assertEqual(payload["summary"]["request_count"], 8)
        self.assertEqual(len(request_urls), 8)
        self.assertTrue(
            all(url.startswith(GATEWAY + "/api/") for _, url, _ in request_urls)
        )
        self.assertTrue(
            all(method == "GET" for method, _, _ in request_urls)
        )
        self.assertTrue(
            any(
                item["method"] == "GET"
                and item["path"] == "/api/auth/login"
                and item["status_code"] == 405
                for item in login_discovery_records
            )
        )
        self.assertFalse(
            any(
                item["method"] == "POST" and item["path"] == "/api/auth/login"
                for item in login_discovery_records
            )
        )
        self.assertEqual(payload["findings"], [])
        invalid_tokens = [
            headers["Authorization"].split(" ", 1)[1]
            for _, _, headers in request_urls
            if headers and headers.get("Authorization", "").startswith("Bearer ")
        ]
        self.assertEqual(len(invalid_tokens), 4)
        self.assertTrue(all(token not in str(payload) for token in invalid_tokens))

        inventory = payload["discovery_results"]
        orders = next(
            item
            for item in inventory
            if item.get("resolved_url") == f"{GATEWAY}/api/orders"
        )
        self.assertEqual(orders["original_url"], f"{GATEWAY}/api/orders")
        self.assertIn("javascript", orders["sources"])
        self.assertEqual(orders["security_status"], "tested")
        self.assertEqual(
            sum(
                item.get("resolved_url") == f"{GATEWAY}/api/orders"
                for item in inventory
            ),
            1,
        )
        self.assertTrue(
            any(
                item.get("template") == "/api/orders/${encodeURIComponent(id)}"
                for item in inventory
            )
        )
        exclusions = payload["summary"]["jwt_inventory_exclusion_reasons"]
        self.assertTrue(any(item["method"] == "UNKNOWN" for item in exclusions))
        self.assertTrue(any("405" in item["reason"] for item in exclusions))
        self.assertTrue(
            any("dynamic template" in item["reason"].lower() for item in exclusions)
        )
        self.assertTrue(
            any(
                "outside the authorized scan scope" in item["reason"]
                for item in exclusions
            )
        )
        session = next(
            item for item in payload["results"] if item["path"] == "/api/auth/session"
        )
        self.assertFalse(session["jwt_selected"])
        self.assertIn("authentication", session["test_results"][0]["reason"].lower())
        orders_result = next(
            item for item in payload["results"] if item["path"] == "/api/orders"
        )["test_results"][0]
        cases = {case["test_case"]: case for case in orders_result["test_cases"]}
        self.assertEqual(cases["valid_token"]["status"], "skipped")
        self.assertIn("No configured valid-token credentials", cases["valid_token"]["reason"])
        self.assertEqual(cases["expired_token"]["status"], "skipped")
        self.assertEqual(payload["summary"]["skipped_tests"], 8)
        self.assertEqual(payload["summary"]["not_implemented_test_cases"], 4)

    @patch.dict(
        os.environ,
        {
            "MICROSCAN_GATEWAY_TARGET": GATEWAY,
            "MICROSCAN_JWT_ENDPOINT_ALLOWLIST": "[]",
            "MICROSHIELD_USERNAME": "",
            "MICROSHIELD_PASSWORD": "",
            "MICROSCAN_LOGIN_PAYLOAD": "",
            "MICROSCAN_AUTH_CONFIG": "",
            "MICROSCAN_LOGIN_ENDPOINT": "",
        },
        clear=True,
    )
    def test_verified_javascript_endpoint_is_actually_tested_when_module_selects_it(self):
        verified_js = {
            "results": [
                {
                    "url": f"{FRONTEND}/api/orders",
                    "verification_url": f"{GATEWAY}/api/orders",
                    "method": "GET",
                    "status_code": 200,
                    "relative_to_frontend": True,
                    "is_api_endpoint": True,
                    "verification_status": "verified",
                    "sources": ["javascript", "gateway_verification"],
                    "evidence": [],
                }
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        responses = [
            httpx.Response(
                401,
                json={"message": "unauthorized"},
                request=httpx.Request("GET", f"{GATEWAY}/api/orders"),
            ),
            httpx.Response(
                401,
                json={"message": "invalid token"},
                request=httpx.Request("GET", f"{GATEWAY}/api/orders"),
            ),
        ]
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.Discovery.discover_seeded", return_value=[]
        ), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=verified_js,
        ), patch.object(
            AuthenticationTest,
            "_run_http_request",
            side_effect=responses,
        ) as security_requests:
            response = self.client.get(
                "/scan",
                params={
                    "target": FRONTEND,
                    "auto_jwt_local_lab": "true",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(security_requests.call_count, 2)
        self.assertEqual(response.json()["summary"]["security_input_endpoints"], 1)
        self.assertEqual(response.json()["summary"]["selected_endpoints"], 1)
        self.assertEqual(response.json()["summary"]["tested_endpoints"], 1)
        record = next(
            item for item in response.json()["discovery_results"]
            if item.get("verification_url") == f"{GATEWAY}/api/orders"
        )
        self.assertEqual(record["security_status"], "tested")

    @patch.dict(os.environ, {"MICROSCAN_GATEWAY_TARGET": GATEWAY}, clear=True)
    def test_javascript_post_remains_post_in_inventory_and_security_input(self):
        js_post = {
            "results": [
                {
                    "url": f"{FRONTEND}/api/auth/login",
                    "resolved_url": f"{GATEWAY}/api/auth/login",
                    "method": "POST",
                    "relative_to_frontend": True,
                    "is_api_endpoint": True,
                    "verification_status": "discovered",
                    "sources": ["javascript"],
                    "evidence": [],
                }
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.Discovery.discover_seeded", return_value=[]
        ), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=js_post,
        ), patch(
            "app.main.Modules.analyze_endpoints",
            side_effect=lambda target, endpoints, auto_jwt_local_lab=False, **kwargs: endpoints,
        ) as security_tests:
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        sent_endpoints = security_tests.call_args.args[1]
        self.assertEqual(sent_endpoints, [])
        inventory = response.json()["discovery_results"]
        self.assertEqual(inventory[0]["method"], "POST")
        self.assertEqual(inventory[0]["url"], f"{FRONTEND}/api/auth/login")
        self.assertEqual(inventory[0]["resolved_url"], f"{GATEWAY}/api/auth/login")
        self.assertEqual(inventory[0]["verification_status"], "discovered")
        self.assertEqual(inventory[0]["resolution_status"], "resolved")
        self.assertEqual(inventory[0]["security_status"], "skipped")

    def test_correlator_deduplicates_by_origin_path_method_not_method_alone(self):
        from app.main import _correlate_discoveries

        initial = [
            {"method": "GET", "path": "/api/items", "responses": [{"sc": 200}]},
            {"method": "POST", "path": "/api/items", "responses": [{"sc": 405}]},
        ]
        file_results = [
            {
                "url": f"{GATEWAY}/api/items",
                "method": "GET",
                "sources": ["javascript"],
                "is_api_endpoint": True,
                "verification_status": "verified",
                "evidence": [],
            },
            {
                "url": f"{GATEWAY}/api/items",
                "method": "DELETE",
                "sources": ["javascript"],
                "is_api_endpoint": True,
                "verification_status": "verified",
                "evidence": [],
            },
        ]
        inventory, security_targets = _correlate_discoveries(
            initial,
            file_results,
            GATEWAY,
            GATEWAY,
        )

        identities = {(item["method"], item["url"]) for item in inventory}
        self.assertEqual(
            identities,
            {
                ("GET", f"{GATEWAY}/api/items"),
                ("POST", f"{GATEWAY}/api/items"),
                ("DELETE", f"{GATEWAY}/api/items"),
            },
        )
        self.assertEqual(
            len([item for item in inventory if item["url"] == f"{GATEWAY}/api/items"]),
            3,
        )
        self.assertEqual(
            {(item["method"], item["path"]) for item in security_targets},
            {
                ("GET", "/api/items"),
                ("POST", "/api/items"),
                ("DELETE", "/api/items"),
            },
        )

    def test_login_discovery_preserves_get_405_allow_and_javascript_post_contract(self):
        from app.main import _correlate_discoveries, _jwt_discovery_inventory
        from module.endpoint_selection import EndpointSelector

        inventory, _ = _correlate_discoveries(
            [
                {
                    "method": "GET",
                    "path": "/api/auth/login",
                    "status_code": 405,
                    "responses": [
                        {"sc": 405, "headers": {"Allow": "POST"}}
                    ],
                }
            ],
            [
                {
                    "url": f"{GATEWAY}/api/auth/login",
                    "method": "POST",
                    "sources": ["javascript"],
                    "is_api_endpoint": True,
                    "request_body_fields": ["username", "password"],
                    "request_content_type": "application/json",
                    "request_content_type_evidence": "shared_api_helper",
                    "evidence": [{"snippet": 'api("/api/auth/login", method:"POST")'}],
                }
            ],
            GATEWAY,
            GATEWAY,
            security_target=GATEWAY,
        )
        authentication_inventory = _jwt_discovery_inventory(
            inventory,
            GATEWAY,
            {GATEWAY.rstrip("/")},
        )
        candidates = EndpointSelector.discover_login_candidates(
            authentication_inventory
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["method"], "POST")
        self.assertEqual(candidates[0]["path"], "/api/auth/login")
        self.assertEqual(candidates[0]["allow_header_methods"], ["POST"])
        self.assertEqual(candidates[0]["request_body_fields"], ["username", "password"])
        self.assertEqual(candidates[0]["request_content_type"], "application/json")

    @patch.dict(
        os.environ,
        {
            "MICROSHIELD_USERNAME": "mock-user",
            "MICROSHIELD_PASSWORD": "mock-password",
        },
        clear=True,
    )
    def test_correlated_post_login_candidate_runs_and_report_does_not_expose_token(self):
        from app.main import _correlate_discoveries, _jwt_discovery_inventory

        inventory, _ = _correlate_discoveries(
            [
                {
                    "method": "GET",
                    "path": "/api/auth/login",
                    "status_code": 405,
                    "responses": [{"sc": 405, "headers": {"Allow": "POST"}}],
                }
            ],
            [
                {
                    "url": f"{GATEWAY}/api/auth/login",
                    "method": "POST",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                    "request_body_fields": ["username", "password"],
                    "request_content_type": "application/json",
                    "request_content_type_evidence": "shared_api_helper",
                    "evidence": [
                        {
                            "source_url": f"{FRONTEND}/assets/app.js",
                            "snippet": "api('/api/auth/login', {method:'POST', body:{username,password}})",
                        }
                    ],
                }
            ],
            FRONTEND,
            GATEWAY,
            security_target=GATEWAY,
        )
        auth_inventory = _jwt_discovery_inventory(
            inventory,
            GATEWAY,
            {FRONTEND, GATEWAY},
        )
        jwt = "header.payload.signature"
        auth_test = AuthenticationTest()
        auth_test.reset_scan_state()
        selected = {
            "endpoint": {"method": "GET", "path": "/api/orders"},
            "path": "/api/orders",
            "method": "GET",
            "reason": "selected test route",
        }
        protected_response = lambda status, payload: httpx.Response(
            status,
            json=payload,
            request=httpx.Request("GET", f"{GATEWAY}/api/orders"),
        )
        login_response = httpx.Response(
            200,
            json={"access_token": jwt, "token_type": "Bearer"},
            request=httpx.Request("POST", f"{GATEWAY}/api/auth/login"),
        )

        with patch.object(Signin, "load_environment"), patch(
            "module.signin.httpx.post",
            return_value=login_response,
        ) as login_request, patch.object(
            auth_test,
            "_run_http_request",
            side_effect=[
                protected_response(401, {"error": "Unauthorized"}),
                protected_response(401, {"error": "Invalid token"}),
                protected_response(200, {"orders": [{"id": 1}]}),
            ],
        ) as endpoint_request, self.assertLogs(level="INFO") as captured:
            result = auth_test.evaluate(
                GATEWAY,
                selected,
                discovered_endpoints=auth_inventory,
            )

        login_request.assert_called_once()
        self.assertEqual(
            login_request.call_args.args[0],
            f"{GATEWAY}/api/auth/login",
        )
        self.assertEqual(
            login_request.call_args.kwargs["json"],
            {"username": "mock-user", "password": "mock-password"},
        )
        self.assertEqual(
            login_request.call_args.kwargs["headers"]["Content-Type"],
            "application/json",
        )
        self.assertEqual(endpoint_request.call_count, 3)
        self.assertEqual(result["discovery"]["login_discovery_status"], "found")
        self.assertEqual(result["discovery"]["selected_login_route"], "/api/auth/login")
        self.assertEqual(result["discovery"]["selected_login_method"], "POST")
        self.assertEqual(result["discovery"]["login_attempt_status"], "succeeded")
        self.assertEqual(result["discovery"]["authentication_result"], "success")
        self.assertTrue(result["discovery"]["token_or_session_detected"])
        report_data = json.dumps(result)
        log_data = "\n".join(captured.output)
        self.assertNotIn(jwt, report_data)
        self.assertNotIn("mock-password", report_data)
        self.assertNotIn(jwt, log_data)
        self.assertNotIn("mock-password", log_data)
        self.assertIn("Login executor invoked", log_data)
        self.assertIn("token_detected=True", log_data)

    def test_discovery_normalizes_not_found_without_dropping_observations_or_other_states(self):
        from app.main import _correlate_discoveries, _jwt_inventory_candidates

        inventory, _ = _correlate_discoveries(
            [
                {
                    "method": "GET",
                    "path": "/api/missing",
                    "responses": [{"sc": 404, "content_type": "application/json"}],
                },
                {
                    "method": "GET",
                    "path": "/api/inventory",
                    "responses": [{"sc": 401, "content_type": "application/json"}],
                },
                {
                    "method": "GET",
                    "path": "/api/orders",
                    "responses": [{"sc": 401, "content_type": "application/json"}],
                },
                {
                    "method": "GET",
                    "path": "/api/users",
                    "responses": [{"sc": 401, "content_type": "application/json"}],
                },
                {
                    "method": "GET",
                    "path": "/api/admin",
                    "responses": [{"sc": 403, "content_type": "application/json"}],
                },
                {
                    "method": "GET",
                    "path": "/api/auth/login",
                    "responses": [
                        {
                            "sc": 405,
                            "content_type": "application/json",
                            "headers": {"Allow": "POST"},
                        }
                    ],
                },
                {
                    "method": "GET",
                    "path": "/api/known-but-unavailable",
                    "responses": [{"sc": 404, "content_type": "application/json"}],
                },
            ],
            [
                {
                    "url": f"{GATEWAY}/api/fallback",
                    "method": "GET",
                    "status_code": 200,
                    "content_type": "text/html",
                    "verification_status": "not_found",
                    "sources": ["wordlist"],
                    "evidence": [],
                },
                {
                    "url": f"{GATEWAY}/api/known-but-unavailable",
                    "method": "GET",
                    "sources": ["javascript"],
                    "evidence": [{"snippet": "fetch('/api/known-but-unavailable')"}],
                },
            ],
            GATEWAY,
            GATEWAY,
            security_target=GATEWAY,
        )
        by_path = {urlsplit(item["url"]).path: item for item in inventory}
        candidates, exclusions = _jwt_inventory_candidates(
            inventory,
            GATEWAY,
            {GATEWAY},
        )
        candidate_paths = {item["path"] for item in candidates}
        exclusion_paths = {
            urlsplit(item["url"]).path: item["reason"]
            for item in exclusions
            if item.get("url")
        }

        self.assertEqual(by_path["/api/missing"]["status_code"], 404)
        self.assertEqual(by_path["/api/missing"]["verification_status"], "not_found")
        self.assertEqual(
            by_path["/api/missing"]["discovery_observations"][0]["status_code"],
            404,
        )
        self.assertEqual(by_path["/api/fallback"]["status_code"], 200)
        self.assertEqual(by_path["/api/fallback"]["verification_status"], "not_found")
        self.assertEqual(by_path["/api/known-but-unavailable"]["status_code"], 404)
        self.assertEqual(
            by_path["/api/known-but-unavailable"]["verification_status"],
            "inconclusive",
        )
        self.assertEqual(by_path["/api/auth/login"]["allow"], "POST")
        self.assertEqual(by_path["/api/auth/login"]["verification_status"], "inconclusive")
        self.assertTrue(
            {"/api/inventory", "/api/orders", "/api/users", "/api/admin"}
            <= candidate_paths
        )
        self.assertNotIn("/api/missing", candidate_paths)
        self.assertIn("/api/missing", exclusion_paths)
        self.assertIn("/api/fallback", exclusion_paths)

    @patch.dict(os.environ, {}, clear=True)
    def test_scan_summary_separates_discovery_inventory_and_security_testing_counts(self):
        discovered = [
            {
                "method": "GET",
                "path": "/api/no-route",
                "responses": [{"sc": 404, "content_type": "application/json"}],
            },
            {
                "method": "GET",
                "path": "/api/inventory",
                "responses": [{"sc": 401, "content_type": "application/json"}],
            },
        ]
        with patch("app.main.Discovery.discover", return_value=discovered), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value={"results": [], "page_sources": [], "summary": {}},
        ), patch(
            "app.main.Modules.analyze_endpoints",
            side_effect=lambda target, endpoints, auto_jwt_local_lab=False, **kwargs: endpoints,
        ) as security_tests:
            response = self.client.get("/scan", params={"target": GATEWAY})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        summary = payload["summary"]
        self.assertEqual(summary["discovery_inventory_records"], 2)
        self.assertEqual(summary["unique_discovery_endpoints"], 2)
        self.assertEqual(summary["excluded_not_found_discovery_endpoints"], 1)
        self.assertEqual(summary["actionable_discovery_endpoints"], 1)
        self.assertEqual(summary["security_input_endpoints"], 1)
        self.assertEqual(summary["selected_for_testing_endpoints"], 0)
        self.assertEqual(summary["actually_tested_endpoints"], 0)
        self.assertEqual(summary["selected_endpoints"], 0)
        self.assertEqual(summary["attempted_endpoints"], 0)
        self.assertEqual(len(security_tests.call_args.args[1]), 1)
        self.assertEqual(security_tests.call_args.args[1][0]["path"], "/api/inventory")

    @patch.dict(os.environ, {}, clear=True)
    def test_file_discovery_failure_does_not_skip_kiterunner_or_security_testing(self):
        discovered = [{"method": "GET", "path": "/api/items", "responses": [{"sc": 200}]}]
        with patch("app.main.Discovery.discover", return_value=discovered), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("connection refused"),
        ), patch(
            "app.main.Modules.analyze_endpoints",
            side_effect=lambda target, endpoints, auto_jwt_local_lab=False, **kwargs: endpoints,
        ) as security_tests:
            response = self.client.get("/scan", params={"target": GATEWAY})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(security_tests.call_args.args[1]), 1)
        self.assertIn("file_discovery", response.json()["discovery_errors"])
        self.assertEqual(
            next(
                stage for stage in response.json()["discovery_stages"]
                if stage["stage"] == "File Discovery"
            )["status"],
            "error",
        )

    @patch.dict(os.environ, {"MICROSCAN_GATEWAY_TARGET": GATEWAY}, clear=True)
    def test_kiterunner_failure_does_not_skip_file_discovery(self):
        with patch(
            "app.main.Discovery.discover",
            side_effect=RuntimeError("Kiterunner unavailable."),
        ), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            side_effect=scan_file_discovery,
        ), patch(
            "app.main.Discovery.discover_seeded", return_value=[]
        ), patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ) as security_tests:
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        endpoints = security_tests.call_args.args[1]
        self.assertEqual([endpoint["path"] for endpoint in endpoints], ["/api/users"])
        self.assertIn("api_discovery", response.json()["discovery_errors"])
        self.assertTrue(response.json()["discovery_results"])

    @patch.dict(os.environ, {"MICROSCAN_GATEWAY_TARGET": GATEWAY}, clear=True)
    def test_scan_stream_reports_live_stages_and_final_scan_payload(self):
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            side_effect=scan_file_discovery,
        ), patch(
            "app.main.Discovery.discover_seeded", return_value=[]
        ), patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get(
                "/scan",
                params={
                    "target": FRONTEND,
                    "stream": "true",
                    "scan_mode": "full",
                },
            )

        self.assertEqual(response.status_code, 200)
        events = [
            json.loads(line.removeprefix("data: "))
            for line in response.text.splitlines()
            if line.startswith("data: ")
        ]
        stage_names = [
            event["stage"]
            for event in events
            if event["type"] == "progress"
        ]
        self.assertIn("API Discovery", stage_names)
        self.assertIn("JavaScript Analysis", stage_names)
        self.assertIn("Security Testing", stage_names)
        self.assertEqual(events[-1]["type"], "complete")
        self.assertEqual(events[-1]["payload"]["target"], FRONTEND)
        self.assertEqual(events[-1]["payload"]["summary"]["scan_mode"], "full")

    @patch.dict(os.environ, {}, clear=True)
    def test_target_origin_is_used_without_gateway_configuration(self):
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value={
                "results": [
                    {
                        "url": f"{FRONTEND}/api/orders",
                        "method": "GET",
                        "relative_to_frontend": True,
                        "sources": ["javascript"],
                    }
                ],
                "page_sources": [FRONTEND],
                "summary": {},
            },
        ) as file_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ), patch("app.main.Discovery.discover_seeded") as seeded_scan:
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(file_scan.await_args.kwargs["verify_endpoints"])
        self.assertEqual(file_scan.await_args.kwargs["gateway_target"], FRONTEND)
        seeded_scan.assert_not_called()
        stage = next(
            item for item in response.json()["discovery_stages"]
            if item["stage"] == "Seeded API Discovery"
        )
        self.assertEqual(stage["status"], "skipped")
        self.assertIn("not classified as an API endpoint", stage["detail"])

    @patch.dict(
        os.environ,
        {"MICROSCAN_GATEWAY_TARGET": "https://outside.invalid"},
        clear=True,
    )
    def test_legacy_gateway_environment_does_not_expand_scan_scope(self):
        with patch("app.main.Discovery.discover", return_value=[]) as discovery, patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value={"results": [], "page_sources": [], "summary": {}},
        ) as file_scan, patch(
            "app.main.Discovery.discover_seeded"
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        discovery.assert_called_once_with(FRONTEND, 1000)
        file_scan.assert_awaited_once()
        seeded_scan.assert_not_called()
        stage = next(
            item for item in response.json()["discovery_stages"]
            if item["stage"] == "Seeded API Discovery"
        )
        self.assertEqual(stage["status"], "skipped")
        self.assertIn("no JavaScript/HTML API candidates", stage["detail"])
        self.assertEqual(
            response.json()["summary"]["authorized_scope"],
            [FRONTEND],
        )

    @patch.dict(os.environ, {"MICROSCAN_GATEWAY_TARGET": GATEWAY}, clear=True)
    def test_dynamic_templates_are_not_forwarded_as_seed_urls(self):
        dynamic_result = {
            "results": [
                {
                    "url": None,
                    "template": "${API_BASE}${path}",
                    "is_template": True,
                    "method": "GET",
                    "sources": ["javascript"],
                },
                {
                    "url": f"{FRONTEND}/api/orders/${{encodeURIComponent(id)}}",
                    "method": "GET",
                    "relative_to_frontend": True,
                    "sources": ["javascript"],
                },
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=dynamic_result,
        ), patch(
            "app.main.Discovery.discover_seeded", return_value=[]
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        seeded_scan.assert_not_called()
        results = response.json()["discovery_results"]
        self.assertTrue(any(item.get("template") == "${API_BASE}${path}" for item in results))

    @patch.dict(os.environ, {"MICROSCAN_GATEWAY_TARGET": GATEWAY}, clear=True)
    def test_seeded_kiterunner_failure_preserves_file_discovery_results(self):
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.Discovery.discover_seeded",
            side_effect=RuntimeError(
                "Kiterunner seeded API scan failed "
                "(exit_code=2, command=['kr', 'scan']): gateway connection failed"
            ),
        ), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            side_effect=scan_file_discovery,
        ), patch("app.main.Modules.analyze_endpoints", return_value=[]):
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["discovery_results"])
        self.assertIn("kiterunner_seed_discovery", payload["discovery_errors"])
        stage = next(
            item for item in payload["discovery_stages"]
            if item["stage"] == "Seeded API Discovery"
        )
        self.assertEqual(stage["status"], "failed")
        self.assertEqual(stage["status"], "failed")
        self.assertEqual(stage["exit_code"], 2)
        self.assertIn("gateway connection failed", stage["detail"])

    @patch.dict(os.environ, {}, clear=True)
    def test_unverified_javascript_paths_are_not_sent_to_security_testing(self):
        unverified_file = {
            "results": [
                {
                    "url": f"{FRONTEND}/api/private",
                    "method": "GET",
                    "status_code": None,
                    "is_api_endpoint": True,
                    "verification_status": "discovered",
                    "sources": ["javascript"],
                    "evidence": [],
                }
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=unverified_file,
        ), patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ) as security_tests:
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(security_tests.call_args.args[1], [])
        self.assertEqual(
            response.json()["discovery_results"][0]["verification_status"],
            "discovered",
        )

    @patch.dict(os.environ, {}, clear=True)
    def test_explicit_per_scan_scope_runs_recursive_discovery(self):
        file_result = {
            "results": [
                {
                    "url": f"{FRONTEND}/api/orders",
                    "discovered_url": "/api/orders",
                    "method": "GET",
                    "relative_to_frontend": True,
                    "is_api_endpoint": True,
                    "verification_status": "discovered",
                    "sources": ["javascript"],
                    "evidence": [
                        {"source_url": f"{FRONTEND}/app.js", "snippet": "fetch('/api/orders')"}
                    ],
                },
                {
                    "url": f"{SECONDARY_ORIGIN}/",
                    "discovered_url": SECONDARY_ORIGIN,
                    "method": "GET",
                    "is_api_endpoint": False,
                    "sources": ["javascript"],
                    "evidence": [
                        {"source_url": f"{FRONTEND}/app.js", "snippet": "baseURL"}
                    ],
                },
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }

        def seeded_execution(target, paths, num):
            path = "/api/orders/42"
            return {
                "target": target,
                "seed_count": len(paths),
                "exit_code": 0,
                "result_count": 1,
                "results": [
                    {
                        "method": "GET",
                        "path": path,
                        "content_type": "application/json",
                    }
                ],
            }

        with patch("app.main.Discovery.discover", return_value=[]) as initial_scan, patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ) as file_scan, patch(
            "app.main.Discovery.discover_seeded",
            side_effect=seeded_execution,
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get(
                "/scan",
                params={
                    "target": FRONTEND,
                    "scope_origins": [SECONDARY_ORIGIN],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(initial_scan.call_args_list[0], call(FRONTEND, 1000))
        self.assertEqual(
            initial_scan.call_args_list[1],
            call(SECONDARY_ORIGIN, 1000, True, 45),
        )
        self.assertEqual(file_scan.await_args.kwargs["gateway_target"], FRONTEND)
        self.assertEqual(seeded_scan.call_count, 2)
        self.assertEqual(
            seeded_scan.call_args_list[0],
            call(SECONDARY_ORIGIN, ["/api/orders"], 100),
        )
        self.assertEqual(
            seeded_scan.call_args_list[1],
            call(SECONDARY_ORIGIN, ["/api/orders/42"], 100),
        )
        payload = response.json()
        self.assertEqual(
            payload["summary"]["authorized_scope"],
            [FRONTEND, SECONDARY_ORIGIN],
        )
        self.assertEqual(payload["summary"]["recursive_discovery_stop_reason"], "queue_empty")
        self.assertEqual(len(payload["summary"]["discovery_rounds"]), 2)
        self.assertEqual(
            payload["summary"]["discovery_rounds"][1]["duplicate_results"],
            1,
        )
        self.assertEqual(
            next(
                stage for stage in payload["discovery_stages"]
                if stage["stage"] == "Recursive Discovery Summary"
            )["rounds"],
            2,
        )

    @patch.dict(os.environ, {}, clear=True)
    def test_external_javascript_origin_is_not_scanned_without_scope_authorization(self):
        external = {
            "results": [
                {
                    "url": "https://outside.invalid/api/orders",
                    "discovered_url": "https://outside.invalid/api/orders",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                }
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=external,
        ), patch("app.main.Discovery.discover_seeded") as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        seeded_scan.assert_not_called()
        candidates = next(
            stage for stage in response.json()["discovery_stages"]
            if stage["stage"] == "API Origin Candidates"
        )
        self.assertIn("https://outside.invalid", candidates["ignored_candidates"])

    @patch.dict(os.environ, {}, clear=True)
    def test_user_authorized_external_api_origin_can_be_scanned(self):
        external = "https://api.example.test"
        file_result = {
            "results": [
                {
                    "url": f"{external}/api/orders",
                    "discovered_url": f"{external}/api/orders",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                },
                {
                    "url": f"{external}/asdf",
                    "discovered_url": f"{external}/asdf",
                    "method": "GET",
                    "is_api_endpoint": False,
                    "sources": ["html"],
                },
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch("app.main.Discovery.discover", return_value=[]) as initial_scan, patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ), patch(
            "app.main.Discovery.discover_seeded",
            return_value={"results": [], "exit_code": 0, "result_count": 0},
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get(
                "/scan",
                params={"target": FRONTEND, "scope_origins": [external]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(initial_scan.call_args_list[0], call(FRONTEND, 1000))
        self.assertEqual(
            initial_scan.call_args_list[1],
            call(external, 1000, True, 45),
        )
        seeded_scan.assert_called_once_with(external, ["/api/orders"], 100)
        self.assertEqual(
            response.json()["summary"]["authorized_scope"],
            [FRONTEND, external],
        )

    @patch.dict(os.environ, {}, clear=True)
    def test_relative_paths_use_the_entered_target_without_profile_mapping(self):
        file_result = {
            "results": [
                {
                    "url": f"{GATEWAY}/",
                    "discovered_url": f"{GATEWAY}/",
                    "method": "GET",
                    "is_api_endpoint": False,
                    "sources": ["javascript"],
                    "evidence": [
                        {"source_url": f"{FRONTEND}/app.js", "snippet": "'http://localhost:8085/'"}
                    ],
                },
                *[
                    {
                        "url": f"{FRONTEND}{path}",
                        "discovered_url": path,
                        "method": "GET",
                        "relative_to_frontend": True,
                        "is_api_endpoint": True,
                        "sources": ["javascript"],
                        "evidence": [
                            {"source_url": f"{FRONTEND}/app.js", "snippet": f"fetch('{path}')"}
                        ],
                    }
                    for path in ("/api/orders", "/api/inventory")
                ],
                {
                    "url": None,
                    "template": "/api/orders/${encodeURIComponent(id)}",
                    "is_template": True,
                    "is_api_endpoint": True,
                    "method": "GET",
                    "sources": ["javascript"],
                },
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ) as file_scan, patch(
            "app.main.Discovery.discover_seeded",
            return_value={"target": GATEWAY, "results": [], "exit_code": 0, "result_count": 0},
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(file_scan.await_args.kwargs["gateway_target"], GATEWAY)
        seeded_scan.assert_called_once_with(
            GATEWAY, ["/api/orders", "/api/inventory"], 100
        )
        self.assertEqual(
            response.json()["summary"]["authorized_scope"],
            [FRONTEND],
        )
        candidates = next(
            stage for stage in response.json()["discovery_stages"]
            if stage["stage"] == "API Origin Candidates"
        )
        self.assertNotIn(SECONDARY_ORIGIN, candidates["authorized_candidates"])
        self.assertTrue(
            any(
                record.get("template") == "/api/orders/${encodeURIComponent(id)}"
                for record in response.json()["discovery_results"]
            )
        )

    @patch.dict(os.environ, {}, clear=True)
    def test_reported_javascript_inventory_queues_static_routes_with_observed_methods(self):
        api_paths = [
            ("/api/inventory", "GET"),
            ("/api/orders", "GET"),
            ("/api/orders", "POST"),
            ("/api/users", "GET"),
            ("/api/auth/login", "POST"),
            ("/api/auth/register", "POST"),
            ("/api/admin/dashboard", "GET"),
        ]
        file_result = {
            "page_sources": [FRONTEND],
            "summary": {},
            "results": [
                {
                    "url": f"{GATEWAY}/",
                    "method": "GET",
                    "is_api_endpoint": False,
                    "sources": ["javascript"],
                    "evidence": [
                        {
                            "source_url": f"{FRONTEND}/assets/app.js",
                            "snippet": "const API = 'http://localhost:8085/'",
                        }
                    ],
                },
                *[
                    {
                        "url": path,
                        "method": method,
                        "is_api_endpoint": False,
                        "classification": "unresolved",
                        "sources": ["javascript"],
                        "evidence": [
                            {
                                "source_url": f"{FRONTEND}/assets/app.js",
                                "snippet": f"request({method}, '{path}')",
                            }
                        ],
                    }
                    for path, method in api_paths
                ],
                {
                    "url": None,
                    "template": "/api/orders/${encodeURIComponent(id)}",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "is_template": True,
                    "sources": ["javascript"],
                    "evidence": [
                        {
                            "source_url": f"{FRONTEND}/assets/app.js",
                            "snippet": "fetch(`/api/orders/${encodeURIComponent(id)}`)",
                        }
                    ],
                },
                {
                    "url": "http://outside.invalid/api/external",
                    "discovered_url": "/api/external",
                    "method": "GET",
                    "relative_to_frontend": True,
                    "is_api_endpoint": False,
                    "classification": "unresolved",
                    "sources": ["javascript"],
                    "evidence": [
                        {
                            "source_url": f"{FRONTEND}/assets/app.js",
                            "snippet": "fetch('http://outside.invalid/api/external')",
                        }
                    ],
                },
                {
                    "url": "/api/catalog",
                    "method": "GET",
                    "is_api_endpoint": False,
                    "classification": "unresolved",
                    "sources": ["html"],
                    "evidence": [
                        {
                            "source_url": f"{FRONTEND}/",
                            "snippet": '<form action="/api/catalog" method="get">',
                        }
                    ],
                },
                {
                    "url": "/api/fallback",
                    "method": "GET",
                    "is_api_endpoint": False,
                    "classification": "unresolved",
                    "verification_status": "inconclusive",
                    "status_code": 200,
                    "content_type": "text/html",
                    "sources": ["javascript"],
                    "evidence": [
                        {
                            "source_url": f"{FRONTEND}/assets/app.js",
                            "snippet": "fetch('/api/fallback')",
                        }
                    ],
                },
                {
                    "url": "/api/frontend-route",
                    "method": "GET",
                    "is_api_endpoint": False,
                    "classification": "frontend_route",
                    "sources": ["html"],
                    "evidence": [
                        {
                            "source_url": f"{FRONTEND}/",
                            "snippet": '<a href="/api/frontend-route">',
                        }
                    ],
                },
            ],
        }
        seeded_outcome = {
            "target": GATEWAY,
            "seed_count": 7,
            "exit_code": 0,
            "result_count": 0,
            "results": [],
            "command": ["kr", "scan", "localhost:8085", "-w", "seed.kite"],
        }
        with patch(
            "app.main.Discovery.discover",
            return_value=[
                {"method": "GET", "path": "/"},
                {
                    "method": "GET",
                    "path": "/api/auth/login",
                    "responses": [{"sc": 405}],
                },
                {
                    "method": "GET",
                    "path": "/api/orders",
                    "responses": [{"sc": 401}],
                },
            ],
        ), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ), patch(
            "app.main.Discovery.discover_seeded",
            return_value=seeded_outcome,
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get("/scan", params={"target": FRONTEND})

        self.assertEqual(response.status_code, 200)
        expected_seeds = [
            "/api/inventory",
            "/api/orders",
            "/api/users",
            "/api/auth/login",
            "/api/auth/register",
            "/api/admin/dashboard",
            "/api/catalog",
        ]
        seeded_scan.assert_called_once_with(GATEWAY, expected_seeds, 100)
        payload = response.json()
        eligibility = next(
            stage
            for stage in payload["discovery_stages"]
            if stage["stage"] == "Seeded API Discovery Eligibility"
        )
        candidates = eligibility["candidates"]
        eligible = [
            candidate for candidate in candidates if candidate["seed_eligible"]
        ]
        self.assertEqual(
            {candidate["seed_path"] for candidate in eligible},
            set(expected_seeds),
            candidates,
        )
        login_post = next(
            candidate
            for candidate in eligible
            if candidate["original_path"] == "/api/auth/login"
            and candidate["observed_method"] == "POST"
        )
        self.assertEqual(login_post["runner_method"], "GET")
        register_post = next(
            candidate
            for candidate in eligible
            if candidate["original_path"] == "/api/auth/register"
        )
        self.assertEqual(register_post["observed_method"], "POST")
        self.assertEqual(register_post["source"], ["javascript"])
        self.assertEqual(
            seeded_scan.call_args.args[1].count("/api/orders"),
            1,
        )
        self.assertEqual(eligibility["eligible_count"], 8)
        self.assertEqual(eligibility["excluded_count"], 5)
        self.assertEqual(
            {seed["path"] for seed in eligibility["accepted_seeds"]},
            set(expected_seeds),
        )
        outside_candidate = next(
            candidate
            for candidate in candidates
            if candidate["original_url"] == "http://outside.invalid/api/external"
        )
        self.assertFalse(outside_candidate["seed_eligible"])
        self.assertIn("outside the authorized scan scope", outside_candidate["exclusion_reason"])
        self.assertIn("outside.invalid", outside_candidate["resolved_origin"])
        fallback_candidate = next(
            candidate
            for candidate in candidates
            if candidate["original_path"] == "/api/fallback"
        )
        self.assertFalse(fallback_candidate["seed_eligible"])
        self.assertIn("HTML fallback", fallback_candidate["exclusion_reason"])
        frontend_route = next(
            candidate
            for candidate in candidates
            if candidate["original_path"] == "/api/frontend-route"
        )
        self.assertFalse(frontend_route["seed_eligible"])
        self.assertIn("frontend route", frontend_route["exclusion_reason"])
        seeded_stage = next(
            stage
            for stage in payload["discovery_stages"]
            if stage["stage"] == "Seeded API Discovery"
        )
        self.assertEqual(seeded_stage["status"], "completed")
        self.assertEqual(seeded_stage["target"], GATEWAY)
        self.assertEqual(seeded_stage["command"], seeded_outcome["command"])
        self.assertEqual(seeded_stage["exit_code"], 0)
        self.assertEqual(seeded_stage["result_count"], 0)
        self.assertTrue(any(
            seed["path"] == "/api/auth/login"
            and seed["observed_method"] == "POST"
            and seed["runner_method"] == "GET"
            for seed in seeded_stage["seeds"]
        ))
        login_methods = {
            record.get("method")
            for record in payload["discovery_results"]
            if urlsplit(record.get("url") or "").path == "/api/auth/login"
        }
        self.assertEqual(login_methods, {"GET", "POST"})
        login_get = next(
            record
            for record in payload["discovery_results"]
            if record.get("method") == "GET"
            and urlsplit(record.get("url") or "").path == "/api/auth/login"
        )
        login_post = next(
            record
            for record in payload["discovery_results"]
            if record.get("method") == "POST"
            and urlsplit(record.get("url") or "").path == "/api/auth/login"
        )
        self.assertEqual(login_get["status_code"], 405)
        self.assertNotEqual(login_post.get("status_code"), 405)
        register_record = next(
            record
            for record in payload["discovery_results"]
            if record.get("method") == "POST"
            and urlsplit(record.get("url") or "").path == "/api/auth/register"
        )
        self.assertEqual(register_record.get("classification"), "unresolved")
        self.assertFalse(register_record.get("is_api_endpoint"))
        duplicate_orders = next(
            record
            for record in payload["discovery_results"]
            if record.get("method") == "GET"
            and urlsplit(record.get("url") or "").path == "/api/orders"
            and set(record.get("sources", [])) >= {"javascript", "kiterunner"}
        )
        self.assertEqual(
            duplicate_orders["sources"],
            ["kiterunner", "javascript"],
        )
        self.assertTrue(duplicate_orders["evidence"])
        template = next(
            candidate
            for candidate in candidates
            if candidate["classification"] == "dynamic"
        )
        self.assertFalse(template["seed_eligible"])
        self.assertIn("Dynamic URL template", template["exclusion_reason"])
        root = next(
            candidate
            for candidate in candidates
            if candidate["original_path"] == f"{GATEWAY}/"
        )
        self.assertFalse(root["seed_eligible"])
        self.assertIn("Origin evidence only", root["exclusion_reason"])
        self.assertNotIn(
            "/api/orders/${encodeURIComponent(id)}",
            seeded_scan.call_args.args[1],
        )
        self.assertTrue(
            any(
                record.get("template") == "/api/orders/${encodeURIComponent(id)}"
                for record in payload["discovery_results"]
            )
        )
        root_record = next(
            record
            for record in payload["discovery_results"]
            if record.get("url") == f"{GATEWAY}/"
        )
        self.assertFalse(root_record.get("is_api_endpoint", False))
        inventory_get = next(
            record
            for record in payload["discovery_results"]
            if record.get("method") == "GET"
            and record.get("discovered_path") == "/api/inventory"
        )
        self.assertEqual(inventory_get["original_url"], "/api/inventory")
        self.assertEqual(
            inventory_get["evidence"][0]["source_url"],
            f"{FRONTEND}/assets/app.js",
        )
        self.assertEqual(
            inventory_get["resolved_url"],
            f"{GATEWAY}/api/inventory",
        )
        stage = next(
            stage
            for stage in payload["discovery_stages"]
            if stage["stage"] == "Seeded API Discovery"
        )
        self.assertEqual(stage["target"], GATEWAY)
        self.assertEqual(stage["command"], seeded_outcome["command"])
        self.assertEqual(stage["exit_code"], 0)
        self.assertEqual(stage["result_count"], 0)

    @patch.dict(os.environ, {}, clear=True)
    def test_recursive_discovery_request_budget_is_reported(self):
        file_result = {
            "results": [
                {
                    "url": f"{GATEWAY}/api/orders",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                },
                {
                    "url": f"{GATEWAY}/api/inventory",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                },
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch(
            "app.main.DISCOVERY_LIMITS",
            RecursiveDiscoveryLimits(max_seeds_per_round=1, max_rounds=1),
        ), patch("app.main.Discovery.discover", return_value=[]), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ), patch(
            "app.main.Discovery.discover_seeded",
            return_value={"results": [], "exit_code": 0, "result_count": 0},
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get(
                "/scan",
                params={
                    "target": FRONTEND,
                },
            )

        self.assertEqual(response.status_code, 200)
        seeded_scan.assert_called_once_with(GATEWAY, ["/api/orders"], 100)
        self.assertEqual(
            response.json()["summary"]["recursive_discovery_stop_reason"],
            "request_budget",
        )

    @patch.dict(os.environ, {}, clear=True)
    def test_target_limit_is_reported_without_executing_kiterunner(self):
        file_result = {
            "results": [
                {
                    "url": f"{SECONDARY_ORIGIN}/api/orders",
                    "resolved_url": f"{SECONDARY_ORIGIN}/api/orders",
                    "discovered_url": f"{SECONDARY_ORIGIN}/api/orders",
                    "method": "GET",
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                }
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch("app.main.DISCOVERY_LIMITS", RecursiveDiscoveryLimits(max_origins=1)), patch(
            "app.main.Discovery.discover", return_value=[]
        ), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ), patch("app.main.Discovery.discover_seeded") as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get(
                "/scan",
                params={
                    "target": FRONTEND,
                    "scope_origins": [SECONDARY_ORIGIN],
                },
            )

        self.assertEqual(response.status_code, 200)
        seeded_scan.assert_not_called()
        summary = next(
            stage for stage in response.json()["discovery_stages"]
            if stage["stage"] == "Recursive Discovery Summary"
        )
        self.assertEqual(summary["stop_reason"], "target_limit")
        self.assertEqual(summary["rounds"], 0)
        skipped = next(
            stage for stage in response.json()["discovery_stages"]
            if stage["stage"] == "Seeded API Discovery"
        )
        self.assertEqual(skipped["status"], "skipped")
        self.assertIn("target_limit", skipped["detail"])

    @patch.dict(os.environ, {}, clear=True)
    def test_recursion_depth_limit_stops_after_reported_round(self):
        file_result = {
            "results": [
                {
                    "url": f"{FRONTEND}/api/orders",
                    "discovered_url": "/api/orders",
                    "method": "GET",
                    "relative_to_frontend": True,
                    "is_api_endpoint": True,
                    "sources": ["javascript"],
                }
            ],
            "page_sources": [FRONTEND],
            "summary": {},
        }
        with patch("app.main.DISCOVERY_LIMITS", RecursiveDiscoveryLimits(max_depth=1)), patch(
            "app.main.Discovery.discover", return_value=[]
        ), patch(
            "app.main.FileDiscovery.scan",
            new_callable=AsyncMock,
            return_value=file_result,
        ), patch(
            "app.main.Discovery.discover_seeded",
            return_value={
                "target": FRONTEND,
                "seed_count": 1,
                "exit_code": 0,
                "result_count": 1,
                "results": [
                    {
                        "method": "GET",
                        "path": "/api/orders/42",
                        "content_type": "application/json",
                    }
                ],
            },
        ) as seeded_scan, patch(
            "app.main.Modules.analyze_endpoints", return_value=[]
        ):
            response = self.client.get(
                "/scan",
                params={
                    "target": FRONTEND,
                },
            )

        self.assertEqual(response.status_code, 200)
        seeded_scan.assert_called_once_with(GATEWAY, ["/api/orders"], 100)
        self.assertEqual(
            response.json()["summary"]["recursive_discovery_stop_reason"],
            "recursion_limit",
        )


if __name__ == "__main__":
    unittest.main()
