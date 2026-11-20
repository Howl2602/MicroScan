import unittest

import httpx

from module.rate_limit_test import RateLimitTest
from module.modules import Modules
from module.pentest_report import build_pentest_report


class StubAuthenticationTest:
    def reset_scan_state(self):
        pass

    def get_cached_authenticated_headers(self, target):
        return None

    def skipped_result(self, endpoint, reason):
        return {
            "test_module": "jwt_authentication",
            "status": "skipped",
            "reason": reason,
            "test_cases": [],
        }

    def evaluate(self, target, selected_candidate, discovered_endpoints):
        return {
            "test_module": "jwt_authentication",
            "status": "skipped",
            "reason": "stubbed for selection test",
            "test_cases": [],
        }


class StubRateLimitTest:
    def __init__(self):
        self.calls = []

    def analyze(self, target, endpoint, **kwargs):
        self.calls.append(
            (
                endpoint["method"],
                endpoint["path"],
                kwargs["scan_mode"],
                kwargs["request_budget"],
            )
        )
        request_count = min(kwargs["request_budget"], 11)
        return {
            "test_module": "rate_limit",
            "status": "inconclusive",
            "reason": "stubbed",
            "request_count": request_count,
            "test_cases": [],
        }


class RateLimitTestTests(unittest.TestCase):
    def test_detects_throttling_and_retry_after(self):
        requests = []

        def handler(request):
            requests.append(request)
            if len(requests) == 3:
                return httpx.Response(
                    429,
                    headers={
                        "Retry-After": "5",
                        "X-RateLimit-Limit": "2",
                    },
                )
            return httpx.Response(200, json={"ok": True})

        result = RateLimitTest(httpx.MockTransport(handler)).analyze(
            "http://127.0.0.1:8085",
            {"method": "GET", "path": "/api/users"},
        )

        self.assertEqual(result["status"], "not_vulnerable_in_test")
        self.assertEqual(result["request_count"], 3)
        test_case = result["test_cases"][0]
        self.assertEqual(test_case["status_codes"], [200, 200, 429])
        self.assertEqual(test_case["retry_after"], ["5"])
        self.assertEqual(test_case["rate_limit_headers"]["x-ratelimit-limit"], "2")

    def test_reports_confirmed_absence_when_full_burst_is_unthrottled(self):
        result = RateLimitTest(
            httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
        ).analyze(
            "http://127.0.0.1:8085",
            {"method": "GET", "path": "/api/users"},
            scan_mode="standard",
        )

        self.assertEqual(result["status"], "potential")
        self.assertEqual(result["request_count"], 11)
        self.assertEqual(result["test_cases"][0]["status_codes"], [200] * 11)

    def test_treats_authentication_denial_as_inconclusive(self):
        result = RateLimitTest(
            httpx.MockTransport(lambda request: httpx.Response(403, json={"error": "denied"}))
        ).analyze(
            "http://127.0.0.1:8085",
            {"method": "GET", "path": "/api/private"},
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["test_cases"][0]["request_count"], 1)

    def test_completes_bounded_burst_on_401_and_reports_authentication_limitation(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(401, json={"error": "unauthorized"})

        result = RateLimitTest(httpx.MockTransport(handler)).analyze(
            "http://127.0.0.1:8085",
            {"method": "GET", "path": "/api/orders"},
        )

        self.assertEqual(len(requests), 11)
        self.assertEqual(result["request_count"], 11)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["test_cases"][0]["status_codes"], [401] * 11)
        self.assertIn("authenticated rate-limit behavior remains untested", result["reason"])
        self.assertEqual(
            result["test_cases"][0]["authentication_context"],
            "unauthenticated",
        )

    def test_sends_cached_authentication_headers_without_including_them_in_results(self):
        observed_authorization = []

        def handler(request):
            observed_authorization.append(request.headers.get("authorization"))
            return httpx.Response(200, json={"ok": True})

        result = RateLimitTest(httpx.MockTransport(handler)).analyze(
            "http://127.0.0.1:8085",
            {"method": "GET", "path": "/api/orders"},
            headers={"Authorization": "Bearer private-test-token"},
        )

        self.assertEqual(len(observed_authorization), 11)
        self.assertEqual(
            observed_authorization,
            ["Bearer private-test-token"] * 11,
        )
        self.assertEqual(result["test_cases"][0]["authentication_context"], "authenticated")
        self.assertNotIn("private-test-token", repr(result))

    def test_detects_429_after_unauthorized_responses(self):
        requests = []

        def handler(request):
            requests.append(request)
            if len(requests) == 5:
                return httpx.Response(429, headers={"Retry-After": "10"})
            return httpx.Response(401)

        result = RateLimitTest(httpx.MockTransport(handler)).analyze(
            "http://127.0.0.1:8085",
            {"method": "GET", "path": "/api/orders"},
        )

        self.assertEqual(len(requests), 5)
        self.assertEqual(result["status"], "not_vulnerable_in_test")
        self.assertEqual(result["test_cases"][0]["status_codes"], [401] * 4 + [429])
        self.assertEqual(result["test_cases"][0]["retry_after"], ["10"])

    def test_rate_limit_headers_without_throttling_are_inconclusive(self):
        result = RateLimitTest(
            httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    headers={"X-RateLimit-Limit": "100"},
                )
            )
        ).analyze(
            "http://127.0.0.1:8085",
            {"method": "GET", "path": "/api/users"},
        )

        self.assertEqual(result["status"], "inconclusive")

    def test_request_budget_stops_burst_and_keeps_result_inconclusive(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"ok": True})

        result = RateLimitTest(
            httpx.MockTransport(handler)
        ).analyze(
            "http://127.0.0.1:8085",
            {"method": "GET", "path": "/api/users"},
            request_budget=5,
        )

        self.assertEqual(len(requests), 5)
        self.assertEqual(result["request_count"], 5)
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("request budget", result["reason"])

    def test_full_mode_selects_all_discovered_safe_get_auth_and_resource_endpoints_on_remote_target(self):
        rate_limit = StubRateLimitTest()
        modules = Modules(
            authentication_test=StubAuthenticationTest(),
            rate_limit_test=rate_limit,
        )
        endpoints = [
            {"method": "GET", "path": "/api/auth/login"},
            {"method": "GET", "path": "/api/users"},
            {"method": "GET", "path": "/api/users/1"},
            {"method": "GET", "path": "/api/orders"},
            {"method": "GET", "path": "/api/register"},
            {"method": "POST", "path": "/api/auth/login"},
            {"method": "GET", "path": "/api/search"},
            {"method": "GET", "path": "/api/users/{id}"},
        ]

        analyzed = modules.analyze_endpoints(
            "https://api.example.test",
            endpoints,
            scan_mode="full",
            rate_limit_testing=True,
        )

        selected = [(method, path) for method, path, _, _ in rate_limit.calls]
        self.assertEqual(
            selected,
            [
                ("GET", "/api/auth/login"),
                ("GET", "/api/users"),
                ("GET", "/api/users/1"),
                ("GET", "/api/orders"),
            ],
        )
        self.assertTrue(
            all(
                endpoint["discovery_source"] == "discovery"
                for endpoint in analyzed
                if endpoint.get("rate_limit_selected")
            )
        )

    def test_standard_mode_caps_selected_route_groups_without_loopback_restriction(self):
        rate_limit = StubRateLimitTest()
        modules = Modules(
            authentication_test=StubAuthenticationTest(),
            rate_limit_test=rate_limit,
        )
        endpoints = [
            {"method": "GET", "path": f"/api/users/{index}"}
            for index in range(1, 8)
        ]
        endpoints += [
            {"method": "GET", "path": f"/api/orders/{index}"}
            for index in range(1, 4)
        ]

        modules.analyze_endpoints(
            "https://api.example.test",
            endpoints,
            scan_mode="standard",
            rate_limit_testing=True,
        )

        self.assertLessEqual(len(rate_limit.calls), 5)
        self.assertEqual(len(rate_limit.calls), 2)

    def test_rate_limit_checks_are_disabled_only_when_explicitly_overridden(self):
        rate_limit = StubRateLimitTest()
        modules = Modules(
            authentication_test=StubAuthenticationTest(),
            rate_limit_test=rate_limit,
        )

        analyzed = modules.analyze_endpoints(
            "https://api.example.test",
            [{"method": "GET", "path": "/api/users"}],
            rate_limit_testing=False,
        )

        self.assertEqual(rate_limit.calls, [])
        self.assertFalse(analyzed[0]["rate_limit_selected"])
        self.assertEqual(analyzed[0]["rate_limit_selection_mode"], "not_enabled")

    def test_full_mode_enforces_scan_wide_request_budget(self):
        rate_limit = StubRateLimitTest()
        modules = Modules(
            authentication_test=StubAuthenticationTest(),
            rate_limit_test=rate_limit,
        )
        endpoints = [
            {"method": "GET", "path": f"/api/users/{index}"}
            for index in range(1, 21)
        ]

        analyzed = modules.analyze_endpoints(
            "https://api.example.test",
            endpoints,
            scan_mode="full",
            rate_limit_testing=True,
        )

        self.assertLessEqual(
            sum(min(call[3], 11) for call in rate_limit.calls),
            RateLimitTest.SCAN_REQUEST_BUDGET,
        )
        self.assertTrue(
            any(
                endpoint["rate_limit_selected"]
                and "budget was exhausted" in endpoint["rate_limit_selection_reason"]
                for endpoint in analyzed
            )
        )

    def test_report_preserves_rate_limit_evidence_as_a_potential_finding(self):
        report = build_pentest_report(
            [
                {
                    "method": "GET",
                    "path": "/api/users",
                    "discovery_source": "discovery",
                    "discovered": True,
                    "test_results": [
                        {
                            "test_module": "rate_limit",
                            "status": "potential",
                            "reason": "No limit observed in the test window.",
                            "request_count": 11,
                            "evidence": [{"status_codes": [200] * 11}],
                            "test_cases": [
                                {
                                    "test_case": "controlled_burst",
                                    "status": "potential",
                                    "reason": "No limit observed in the test window.",
                                    "request_attempted": True,
                                    "request_count": 11,
                                    "status_codes": [200] * 11,
                                    "retry_after": [],
                                    "rate_limit_headers": {},
                                }
                            ],
                        }
                    ],
                }
            ]
        )

        self.assertEqual(report["findings"][0]["status"], "potential")
        self.assertEqual(report["summary"]["potential_findings"], 1)
        self.assertEqual(report["summary"]["request_count"], 0)
        self.assertEqual(report["summary"]["rate_limit_request_count"], 11)
        self.assertEqual(
            report["endpoint_assessments"][0]["rate_limit_assessment"]["status"],
            "potential",
        )
