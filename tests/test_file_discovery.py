import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from app.main import app
from discovery.file_discovery import (
    FileDiscovery,
    extract_javascript_endpoints,
    extract_script_urls,
    normalize_origin,
)


FRONTEND = "http://localhost:3000/"
GATEWAY = "http://localhost:8085/"


class FileDiscoveryTests(unittest.TestCase):
    def test_script_urls_support_absolute_root_relative_and_relative_paths(self):
        html = """
        <script src="/assets/root.js"></script>
        <script src="scripts/app.js"></script>
        <script src="http://localhost:3000/absolute.js"></script>
        <script src="https://outside.invalid/ignored.js"></script>
        """
        self.assertEqual(
            extract_script_urls(FRONTEND, html),
            [
                "http://localhost:3000/assets/root.js",
                "http://localhost:3000/scripts/app.js",
                "http://localhost:3000/absolute.js",
            ],
        )

    def test_javascript_endpoints_include_fetch_axios_and_base_url(self):
        endpoints = extract_javascript_endpoints(
            "http://localhost:3000/app.js",
            """
            fetch('/api/items');
            axios.get("https://localhost:8085/api/users");
            const client = { baseURL: '/api/v2' };
            """,
        )
        self.assertEqual(
            {item["url"] for item in endpoints},
            {
                "http://localhost:3000/api/items",
                "https://localhost:8085/api/users",
                "http://localhost:3000/api/v2",
            },
        )

    def test_relative_javascript_request_resolves_against_frontend_page_not_script_path(self):
        endpoint = extract_javascript_endpoints(
            "http://localhost:3000/assets/app.js",
            "fetch('api/orders')",
            base_url=FRONTEND,
        )[0]

        self.assertEqual(endpoint["url"], "http://localhost:3000/api/orders")
        self.assertEqual(endpoint["discovered_url"], "api/orders")
        self.assertTrue(endpoint["relative_to_frontend"])
        self.assertTrue(endpoint["is_api_endpoint"])

    def test_absolute_api_url_and_base_constant_routes_keep_resolution_provenance(self):
        endpoints = extract_javascript_endpoints(
            "http://localhost:3000/assets/app.js",
            """
            const API_BASE = "http://localhost:8085/v1/";
            fetch('http://localhost:8085/api/orders');
            fetch(`${API_BASE}orders`);
            fetch(`${API_BASE}api/inventory`);
            """,
            base_url="http://localhost:3000/",
        )
        by_observed = {item["original_observed_url"]: item for item in endpoints}
        absolute = by_observed["http://localhost:8085/api/orders"]
        self.assertEqual(absolute["resolved_url"], "http://localhost:8085/api/orders")
        self.assertEqual(absolute["resolved_origin"], "http://localhost:8085")
        self.assertEqual(absolute["resolution_rule"], "urljoin")
        relative = by_observed["${API_BASE}orders"]
        self.assertEqual(relative["resolved_url"], "http://localhost:8085/v1/orders")
        self.assertEqual(relative["resolution_base"], "http://localhost:8085/v1/")
        static_template = by_observed["${API_BASE}api/inventory"]
        self.assertEqual(
            static_template["resolved_url"],
            "http://localhost:8085/v1/api/inventory",
        )
        self.assertFalse(static_template["is_template"])
        self.assertEqual(static_template["resolution_rule"], "static_constant_template")

    def test_static_route_relative_reference_and_unresolved_template_are_preserved(self):
        endpoints = extract_javascript_endpoints(
            "http://localhost:3000/assets/app.js",
            """
            fetch('api/orders');
            fetch(`/api/orders/${encodeURIComponent(id)}`);
            fetch(`${API_BASE}/api/users`);
            """,
        )
        by_observed = {item["original_observed_url"]: item for item in endpoints}
        relative = by_observed["api/orders"]
        self.assertEqual(
            relative["resolved_url"],
            "http://localhost:3000/assets/api/orders",
        )
        self.assertEqual(relative["resolution_base"], "http://localhost:3000/assets/app.js")
        unresolved = by_observed["/api/orders/${encodeURIComponent(id)}"]
        self.assertTrue(unresolved["is_template"])
        self.assertNotIn("resolved_url", unresolved)
        unknown_constant = by_observed["${API_BASE}/api/users"]
        self.assertTrue(unknown_constant["is_template"])

    def test_html_links_and_forms_are_discovered_without_sending_unsafe_methods(self):
        requests = []

        def handler(request):
            requests.append((request.method, str(request.url)))
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    content=(
                        '<a href="/api/items">Items</a>'
                        '<form action="/api/login" method="POST"></form>'
                    ),
                    headers={"content-type": "text/html"},
                )
            return httpx.Response(404, content="missing")

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="",
                requests_per_second=5,
            )
        )

        records = {(item["method"], httpx.URL(item["url"]).path): item for item in result["results"]}
        self.assertEqual(records[("GET", "/api/items")]["sources"], ["html"])
        self.assertEqual(records[("POST", "/api/login")]["verification_status"], "discovered")
        self.assertTrue(records[("POST", "/api/login")]["is_api_endpoint"])
        self.assertEqual(records[("POST", "/api/login")]["method"], "POST")
        self.assertTrue(all(method == "GET" for method, _ in requests))

    def test_javascript_non_get_methods_are_discovered_but_not_verified(self):
        endpoints = extract_javascript_endpoints(
            "http://localhost:3000/app.js",
            """axios.post('/api/login', data); fetch('/api/read'); fetch('/api/write', {method:'DELETE'});""",
        )
        by_url = {httpx.URL(item["url"]).path: item for item in endpoints}
        self.assertEqual(by_url["/api/login"]["method"], "POST")
        self.assertEqual(by_url["/api/read"]["method"], "GET")
        self.assertEqual(by_url["/api/write"]["method"], "DELETE")

    def test_dynamic_javascript_templates_are_evidence_not_scan_urls(self):
        endpoints = extract_javascript_endpoints(
            "http://localhost:3000/app.js",
            """
            fetch(`/api/orders/${encodeURIComponent(id)}`);
            fetch(`${API_BASE}${path}`);
            axios.get('/api/users/:userId');
            fetch('/api/items/' + encodeURIComponent(itemId));
            fetch(apiBase + '/api/inventory');
            """,
        )

        self.assertEqual(len(endpoints), 5)
        self.assertTrue(all(item["is_template"] for item in endpoints))
        self.assertTrue(all(item["url"] is None for item in endpoints))
        self.assertTrue(
            any(item["template"] == "${API_BASE}${path}" for item in endpoints)
        )
        self.assertTrue(
            any("/api/items/" in item["template"] for item in endpoints)
        )

    def test_dynamic_javascript_templates_are_not_requested(self):
        requests = []

        def handler(request):
            requests.append(request.url.path)
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    content=(
                        '<script src="/app.js"></script>'
                    ),
                    headers={"content-type": "text/html"},
                )
            if request.url.path == "/app.js":
                return httpx.Response(
                    200,
                    content=b"fetch(`/api/orders/${encodeURIComponent(id)}`)",
                    headers={"content-type": "application/javascript"},
                )
            return httpx.Response(404, content="missing")

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="",
                requests_per_second=5,
            )
        )

        self.assertNotIn("/api/orders/${encodeURIComponent(id)}", requests)
        template = next(
            item for item in result["results"]
            if item.get("template")
        )
        self.assertIsNone(template["url"])
        self.assertTrue(template["is_template"])
        self.assertEqual(template["resolution_status"], "unresolved")

    def test_only_javascript_request_evidence_is_verified_on_configured_gateway(self):
        requests = []

        def handler(request):
            requests.append(str(request.url))
            if request.url.port == 3000 and request.url.path == "/":
                return httpx.Response(
                    200,
                    content='<a href="/api/users">Users</a><script src="/app.js"></script>',
                    headers={"content-type": "text/html"},
                )
            if request.url.port == 3000 and request.url.path == "/app.js":
                return httpx.Response(
                    200,
                    content="fetch('/api/orders'); axios.post('/api/login', data); fetch('/dashboard'); const route = '/api/inventory';",
                    headers={"content-type": "application/javascript"},
                )
            if request.url.port == 8085 and request.url.path.startswith("/.microscan-missing-"):
                return httpx.Response(404, content="missing")
            if request.url.port == 8085 and request.url.path == "/api/orders":
                return httpx.Response(
                    200,
                    content='{"orders":[]}',
                    headers={"content-type": "application/json"},
                )
            return httpx.Response(404, content="missing")

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="",
                requests_per_second=5,
                verify_endpoints=True,
                gateway_target=GATEWAY,
            )
        )

        html_route = next(item for item in result["results"] if "html" in item["sources"])
        api_call = next(
            item for item in result["results"]
            if item.get("discovered_url") == "/api/orders"
        )
        literal_path = next(
            item for item in result["results"]
            if item.get("discovered_url") == "/api/inventory"
        )
        post_endpoint = next(
            item for item in result["results"]
            if item.get("discovered_url") == "/api/login"
        )
        unresolved_route = next(
            item for item in result["results"]
            if item.get("discovered_url") == "/dashboard"
        )
        self.assertEqual(html_route["classification"], "frontend_route")
        self.assertEqual(html_route["verification_status"], "discovered")
        self.assertFalse(html_route.get("verification_url"))
        self.assertEqual(api_call["url"], f"{FRONTEND.rstrip('/')}/api/orders")
        self.assertEqual(api_call["verification_url"], f"{GATEWAY.rstrip('/')}/api/orders")
        self.assertEqual(api_call["verification_status"], "verified")
        self.assertEqual(api_call["method"], "GET")
        self.assertIn("fetch('/api/orders')", api_call["evidence"][0]["snippet"])
        self.assertFalse(literal_path["is_api_endpoint"])
        self.assertFalse(literal_path.get("verification_url"))
        self.assertEqual(post_endpoint["method"], "POST")
        self.assertEqual(post_endpoint["resolved_url"], f"{GATEWAY.rstrip('/')}/api/login")
        self.assertEqual(post_endpoint["verification_status"], "discovered")
        self.assertNotIn("verification_url", post_endpoint)
        self.assertFalse(any(url.endswith("/api/login") for url in requests))
        self.assertEqual(unresolved_route["classification"], "unresolved")
        self.assertFalse(unresolved_route["is_api_endpoint"])
        self.assertFalse(unresolved_route.get("verification_url"))
        self.assertNotIn(f"{FRONTEND.rstrip('/')}/api/orders", requests)
        self.assertIn(f"{GATEWAY.rstrip('/')}/api/orders", requests)

    def test_scan_preserves_login_contract_and_allow_header_for_405(self):
        script = """
        async function api(path, options = {}) {
          const headers = {
            Accept: "application/json",
            ...(options.body ? { "Content-Type": "application/json" } : {}),
          };
          return fetch(path, { ...options, headers });
        }
        async function login() {
          return api("/api/auth/login", {
            method: "POST",
            anonymous: true,
            body: JSON.stringify({
              username: $("#loginUsername").value.trim(),
              password: $("#loginPassword").value
            })
          });
        }
        fetch("/api/auth/login");
        """

        def handler(request):
            if request.url.port == 3000 and request.url.path == "/":
                return httpx.Response(
                    200,
                    content='<script src="/app.js"></script>',
                    headers={"content-type": "text/html"},
                )
            if request.url.port == 3000 and request.url.path == "/app.js":
                return httpx.Response(
                    200,
                    content=script,
                    headers={"content-type": "application/javascript"},
                )
            if request.url.port == 8085 and request.url.path.startswith("/.microscan-missing-"):
                return httpx.Response(404, content="missing")
            if request.url.port == 8085 and request.url.path == "/api/auth/login":
                return httpx.Response(405, headers={"Allow": "POST"})
            return httpx.Response(404, content="missing")

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="",
                requests_per_second=5,
                verify_endpoints=True,
                gateway_target=GATEWAY,
            )
        )

        login_post = next(
            item
            for item in result["results"]
            if item.get("method") == "POST"
            and item.get("discovered_url") == "/api/auth/login"
        )
        login_get = next(
            item
            for item in result["results"]
            if item.get("method") == "GET"
            and item.get("discovered_url") == "/api/auth/login"
        )
        self.assertEqual(login_post["request_body_fields"], ["username", "password"])
        self.assertEqual(login_post["request_content_type"], "application/json")
        self.assertEqual(
            login_post["request_content_type_evidence"],
            "shared_api_helper",
        )
        self.assertEqual(login_get["status_code"], 405)
        self.assertEqual(login_get["allow"], "POST")

    def test_gateway_html_fallback_is_not_verified_as_an_api_response(self):
        def handler(request):
            if request.url.port == 3000 and request.url.path == "/":
                return httpx.Response(
                    200,
                    content='<script src="/app.js"></script>',
                    headers={"content-type": "text/html"},
                )
            if request.url.port == 3000 and request.url.path == "/app.js":
                return httpx.Response(
                    200,
                    content="fetch('/api/items')",
                    headers={"content-type": "application/javascript"},
                )
            if request.url.port == 8085:
                return httpx.Response(
                    200,
                    content="<html><div id='app'></div></html>",
                    headers={"content-type": "text/html"},
                )
            return httpx.Response(404)

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="",
                requests_per_second=5,
                verify_endpoints=True,
                gateway_target=GATEWAY,
            )
        )

        endpoint = next(item for item in result["results"] if item.get("is_api_endpoint"))
        self.assertEqual(endpoint["status_code"], 200)
        self.assertEqual(endpoint["verification_status"], "not_found")

    def test_out_of_scope_targets_are_rejected(self):
        for target in (
            "https://example.invalid",
            "http://localhost:9999",
            "http://192.0.2.1:3000",
            "http://127.0.0.2:3000",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_origin(target)

    def test_scan_detects_existing_and_missing_paths_and_generic_200(self):
        fallback = b"<html><title>Single page app</title></html>"

        def handler(request):
            if request.url.path == "/":
                return httpx.Response(200, content=fallback, headers={"content-type": "text/html"})
            if request.url.path == "/robots.txt":
                return httpx.Response(200, content="User-agent: *", headers={"content-type": "text/plain"})
            if request.url.path == "/missing":
                return httpx.Response(404, content="not found")
            return httpx.Response(
                200,
                content=f"<html><title>Page not found</title><p>{request.url.path}</p></html>",
                headers={"content-type": "text/html"},
            )

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="robots.txt\nmissing\nfake-route",
                requests_per_second=5,
                analyze_javascript=False,
            )
        )
        by_path = {httpx.URL(item["url"]).path: item for item in result["results"]}
        self.assertEqual(by_path["/robots.txt"]["verification_status"], "verified")
        self.assertEqual(by_path["/missing"]["verification_status"], "not_found")
        self.assertEqual(by_path["/fake-route"]["verification_status"], "not_found")

    def test_gateway_verification_never_requests_external_script_origin(self):
        requests = []
        document = b'<script src="/app.js"></script>'
        script = b"""
        fetch('/api/relative');
        fetch('https://outside.invalid/private');
        fetch('//outside.invalid/protocol-relative');
        """

        def handler(request):
            requests.append(str(request.url))
            if request.url.path == "/":
                return httpx.Response(200, content=document, headers={"content-type": "text/html"})
            if request.url.path == "/app.js":
                return httpx.Response(200, content=script, headers={"content-type": "application/javascript"})
            if request.url.host == "localhost" and request.url.port == 8085:
                body = "{}" if request.url.path.startswith("/.microscan-missing-") else '{"items":[]}'
                return httpx.Response(200, content=body, headers={"content-type": "application/json"})
            return httpx.Response(404, content="missing")

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="api/relative",
                requests_per_second=5,
                verify_endpoints=True,
                gateway_target=GATEWAY,
            )
        )
        self.assertFalse(any("outside.invalid" in url for url in requests))
        relative = next(item for item in result["results"] if item["url"].endswith("/api/relative"))
        external_results = [item for item in result["results"] if "outside.invalid" in item["url"]]
        self.assertEqual(relative["verification_status"], "verified")
        self.assertEqual(relative["verification_url"], "http://localhost:8085/api/relative")
        self.assertEqual(
            set(relative["sources"]),
            {"javascript", "wordlist", "gateway_verification"},
        )
        self.assertTrue(
            all(item["verification_status"] == "discovered" for item in external_results)
        )
        self.assertTrue(all(item["classification"] == "unresolved" for item in external_results))

    def test_network_failure_is_reported_without_crashing(self):
        def handler(request):
            raise httpx.ConnectError("not connected", request=request)

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="robots.txt",
                requests_per_second=5,
                analyze_javascript=False,
            )
        )
        self.assertEqual(result["results"][0]["verification_status"], "inconclusive")

    def test_request_timeout_is_reported_without_crashing(self):
        def handler(request):
            raise httpx.ReadTimeout("slow response", request=request)

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="robots.txt",
                requests_per_second=5,
                analyze_javascript=False,
            )
        )
        self.assertEqual(result["results"][0]["verification_status"], "inconclusive")

    def test_redirect_is_not_followed(self):
        requests = []

        def handler(request):
            requests.append(str(request.url))
            if request.url.path == "/robots.txt":
                return httpx.Response(302, headers={"location": "https://outside.invalid/"})
            return httpx.Response(404, content="missing")

        result = asyncio.run(
            FileDiscovery(httpx.MockTransport(handler)).scan(
                FRONTEND,
                wordlist="robots.txt",
                requests_per_second=5,
                analyze_javascript=False,
            )
        )
        self.assertFalse(any("outside.invalid" in url for url in requests))
        self.assertEqual(result["results"][0]["verification_status"], "blocked")

    def test_execution_deadline_returns_inconclusive_results(self):
        def handler(request):
            return httpx.Response(200, content="ok")

        with patch("discovery.file_discovery.MAX_EXECUTION_SECONDS", 0.01):
            result = asyncio.run(
                FileDiscovery(httpx.MockTransport(handler)).scan(
                    FRONTEND,
                    wordlist="robots.txt",
                    requests_per_second=5,
                    analyze_javascript=False,
                )
            )

        self.assertTrue(result["summary"]["execution_time_limited"])
        self.assertEqual(result["results"][0]["verification_status"], "inconclusive")

    def test_evidence_redacts_credentials(self):
        endpoint = extract_javascript_endpoints(
            "http://localhost:3000/app.js",
            "fetch('/api/items', { headers: { Authorization: 'Bearer supersecret' } });",
        )[0]
        self.assertNotIn("supersecret", endpoint["evidence"])

    def test_login_request_contract_uses_javascript_body_and_shared_content_type(self):
        script = """
        async function api(path, options = {}) {
          const headers = { ...(options.body ? { "Content-Type": "application/json" } : {}) };
          return fetch(path, { ...options, headers });
        }
        async function login() {
          return api("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({
              username: $("#loginUsername").value.trim(),
              password: $("#loginPassword").value
            })
          });
        }
        """

        endpoint = next(
            item
            for item in extract_javascript_endpoints(
                "http://localhost:3000/assets/app.js",
                script,
                base_url=FRONTEND,
            )
            if item["discovered_url"] == "/api/auth/login"
        )

        self.assertEqual(endpoint["method"], "POST")
        self.assertEqual(endpoint["request_body_fields"], ["username", "password"])
        self.assertEqual(endpoint["request_content_type"], "application/json")
        self.assertEqual(endpoint["request_content_type_evidence"], "shared_api_helper")

    def test_login_payload_without_content_type_evidence_remains_unresolved(self):
        endpoint = next(
            item
            for item in extract_javascript_endpoints(
                "http://localhost:3000/app.js",
                """api("/api/auth/login", {
                  method: "POST",
                  body: JSON.stringify({ username, password })
                });""",
                base_url=FRONTEND,
            )
            if item["discovered_url"] == "/api/auth/login"
        )

        self.assertEqual(endpoint["request_body_fields"], ["username", "password"])
        self.assertIsNone(endpoint["request_content_type"])

    def test_api_does_not_require_jwt_for_file_discovery(self):
        with patch("app.main.FileDiscovery.scan", new_callable=AsyncMock) as scan:
            scan.return_value = {"results": [], "summary": {"results": 0}}
            from fastapi.testclient import TestClient

            response = TestClient(app).post(
                "/file-discovery",
                json={"target": FRONTEND, "wordlist": ""},
            )

        self.assertEqual(response.status_code, 200)
        scan.assert_awaited_once()
        self.assertFalse(scan.await_args.kwargs["verify_endpoints"])


if __name__ == "__main__":
    unittest.main()
