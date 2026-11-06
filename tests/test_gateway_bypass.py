import asyncio
import unittest
from urllib.parse import urlsplit

import httpx

from module.gateway_bypass import GatewayBypass
from module.pentest_report import build_pentest_report


class GatewayBypassTests(unittest.IsolatedAsyncioTestCase):
    def test_service_probe_plan_derives_all_shared_route_prefixes(self):
        endpoints = [
            {
                "method": "GET",
                "path": f"/api/orders/{identifier}",
                "query": "",
                "query_parameters": [],
            }
            for identifier in ("1", "2", "3")
        ]

        probe_paths, identifier_endpoints = GatewayBypass._service_probe_plan(
            endpoints
        )

        self.assertEqual(
            [endpoint["path"] for endpoint in probe_paths],
            ["/api/", "/api/orders/", "/orders/"],
        )
        self.assertEqual(len(identifier_endpoints), 3)

        nested_endpoints = [
            {
                "method": "GET",
                "path": "/api/orders/1/items/3",
                "query": "",
                "query_parameters": [],
            },
            {
                "method": "GET",
                "path": "/api/orders/2/items/4",
                "query": "",
                "query_parameters": [],
            },
        ]
        nested_probe_paths, nested_identifier_endpoints = (
            GatewayBypass._service_probe_plan(nested_endpoints)
        )
        self.assertEqual(
            [endpoint["path"] for endpoint in nested_probe_paths],
            ["/api/", "/api/orders/", "/orders/"],
        )
        self.assertEqual(len(nested_identifier_endpoints), 2)

        version_paths, version_identifier_endpoints = GatewayBypass._service_probe_plan(
            [
                {
                    "method": "GET",
                    "path": "/api/v1/orders",
                    "query": "",
                    "query_parameters": [],
                },
                {
                    "method": "GET",
                    "path": "/api/v2/orders",
                    "query": "",
                    "query_parameters": [],
                },
            ]
        )
        self.assertEqual(version_identifier_endpoints, set())
        self.assertEqual(
            [endpoint["path"] for endpoint in version_paths],
            ["/api/v1/orders", "/api/v2/orders"],
        )

    async def test_standard_omits_repeated_id_variants_but_uses_common_prefixes(self):
        requests = []

        async def handler(request):
            requests.append(request)
            if request.url.port == 8085:
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json={"items": []})

        async def port_probe(hostname, port):
            return port == 8081

        discoveries = [
            *(
                {
                    "url": f"http://localhost:8085/api/orders/{identifier}",
                    "method": "GET",
                }
                for identifier in ("1", "2", "3")
            ),
            *(
                {
                    "url": f"http://localhost:8085/api/{route}",
                    "method": "GET",
                }
                for route in ("health", "status", "version", "info", "ping", "docs")
            ),
        ]

        result = await GatewayBypass(
            transport=httpx.MockTransport(handler),
            port_probe=port_probe,
        ).analyze(
            "http://localhost:8085",
            discoveries,
            scan_mode="standard",
            port_start=8081,
            port_end=8081,
        )

        service = result["services"][0]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(service["verification_evidence"]["path"], "/api/")
        self.assertEqual(
            [endpoint["path"] for endpoint in service["endpoints"]],
            [
                "/api/health",
                "/api/status",
                "/api/version",
                "/api/info",
                "/api/ping",
                "/api/docs",
            ],
        )
        self.assertEqual(len(result["skipped_endpoints"]), 3)
        self.assertEqual(len(requests), 13)

    async def test_full_scan_compares_all_discovered_routes_without_old_caps(self):
        requests = []

        class ImmediateGatewayBypass(GatewayBypass):
            async def _open_ports(self, hostname, ports, progress_callback=None):
                return [8081]

            async def _request(self, client, semaphore, url):
                requests.append(url)
                gateway_response = urlsplit(url).port == 8085
                return {
                    "status_code": 403 if gateway_response else 200,
                    "headers": {"content_type": "application/json"},
                    "body": {
                        "bytes_captured": 15,
                        "truncated": False,
                        "sha256": "gateway" if gateway_response else "direct",
                        "format": "json",
                        "nonempty_structured_data": True,
                        "shape": [{"field": "items", "type": "list"}],
                    },
                    "api_response": True,
                    "access_denied": gateway_response,
                    "error": None,
                }

        async def port_probe(hostname, port):
            return port == 8081

        discoveries = [
            {
                "url": f"http://localhost:8085/api/orders/{identifier}",
                "method": "GET",
            }
            for identifier in range(1, 121)
        ]

        result = await ImmediateGatewayBypass(
            port_probe=port_probe,
        ).analyze(
            "http://localhost:8085",
            discoveries,
            scan_mode="full",
            port_start=8081,
            port_end=8081,
        )

        service = result["services"][0]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(service["endpoints"]), 120)
        self.assertEqual(len(requests), 241)

    async def test_standard_is_inconclusive_when_only_repeated_id_routes_exist(self):
        async def handler(request):
            return httpx.Response(200, json={"items": []})

        async def port_probe(hostname, port):
            return port == 8081

        result = await GatewayBypass(
            transport=httpx.MockTransport(handler),
            port_probe=port_probe,
        ).analyze(
            "http://localhost:8085",
            [
                {"url": "http://localhost:8085/api/orders/1", "method": "GET"},
                {"url": "http://localhost:8085/api/orders/2", "method": "GET"},
            ],
            scan_mode="standard",
            port_start=8081,
            port_end=8081,
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("no eligible discovered endpoints", result["reason"])
        self.assertEqual(result["services"][0]["endpoints"], [])

    def test_gateway_bypass_evidence_is_included_in_pentest_report(self):
        gateway_bypass = {
            "status": "completed",
            "services": [
                {
                    "origin": "http://localhost:8081",
                    "port": 8081,
                    "endpoints": [
                        {
                            "method": "GET",
                            "path": "/api/orders/1",
                            "status": "confirmed",
                            "reason": "Gateway denied; direct service returned structured data.",
                            "gateway": {"response": {"status_code": 403}},
                            "direct": {"response": {"status_code": 200}},
                        }
                    ],
                }
            ],
        }

        report = build_pentest_report([], gateway_bypass=gateway_bypass)

        self.assertEqual(report["gateway_bypass"], gateway_bypass)
        self.assertEqual(report["summary"]["gateway_bypass_service_count"], 1)
        self.assertEqual(report["summary"]["gateway_bypass_status_counts"]["confirmed"], 1)
        self.assertEqual(report["findings"][0]["test_case"], "gateway_bypass")

    def test_incomplete_gateway_bypass_coverage_prevents_clean_conclusion(self):
        test_cases = [
            {
                "test_case": name,
                "status": "not_detected_in_this_test",
                "request_attempted": True,
            }
            for name in (
                "without_token",
                "invalid_token",
                "valid_token",
                "expired_token",
            )
        ]
        report = build_pentest_report(
            [
                {
                    "method": "GET",
                    "path": "/api/orders/1",
                    "discovery_source": "discovery",
                    "jwt_eligible": True,
                    "jwt_selected": True,
                    "test_results": [{"status": "completed", "test_cases": test_cases}],
                }
            ],
            gateway_bypass={
                "status": "skipped",
                "reason": "Loopback only.",
                "services": [],
                "skipped_endpoints": [],
            },
        )

        self.assertEqual(
            report["summary"]["overall_conclusion"]["code"],
            "inconclusive",
        )
        self.assertFalse(report["summary"]["coverage_complete"])
        self.assertIn(
            "Gateway Bypass did not complete with comparable service evidence.",
            report["summary"]["coverage_limitations"],
        )

    async def test_configured_candidate_port_uses_discovered_get_route(self):
        requests = []
        probed_ports = []

        async def handler(request):
            requests.append(request)
            if request.url.port == 8085:
                return httpx.Response(
                    403,
                    headers={"content-type": "application/json"},
                    json={"error": "forbidden"},
                )
            if request.url.port == 8081:
                return httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    json={"id": 1, "total": 42, "access_token": "do-not-report"},
                )

        async def port_probe(hostname, port):
            probed_ports.append(port)
            return port == 8081

        discoveries = [
            {
                "url": "http://localhost:8085/api/orders/1?page=1",
                "method": "GET",
            },
            {
                "url": "http://localhost:8085/api/orders/1",
                "method": "POST",
            },
            {
                "url": "http://localhost:8085/api/{order_id}",
                "method": "GET",
            },
            {
                "url": "http://localhost:8085/api/old",
                "method": "GET",
                "verification_status": "not_found",
            },
            {"url": "http://other.local/api/orders/1", "method": "GET"},
        ]

        result = await GatewayBypass(
            transport=httpx.MockTransport(handler),
            port_probe=port_probe,
        ).analyze(
            "http://localhost:8085",
            discoveries,
            port_start=8081,
            port_end=8085,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual([service["port"] for service in result["services"]], [8081])
        self.assertEqual(
            result["services"][0]["verification_evidence"],
            {
                "method": "GET",
                "path": "/api/orders/1",
                "source": "discovered_endpoint",
                "status_code": 200,
                "content_type": "application/json",
            },
        )
        self.assertIn(
            {
                "origin": "http://localhost:8085",
                "port": 8085,
                "host": "localhost",
            },
            result["gateway_origins"],
        )
        self.assertIn(
            {
                "origin": "http://other.local:80",
                "port": 80,
                "host": "other.local",
            },
            result["gateway_origins"],
        )
        endpoint = result["services"][0]["endpoints"][0]
        self.assertEqual(endpoint["status"], "confirmed")
        self.assertEqual(endpoint["method"], "GET")
        self.assertEqual(endpoint["gateway"]["response"]["status_code"], 403)
        self.assertEqual(endpoint["direct"]["response"]["status_code"], 200)
        self.assertTrue(endpoint["comparison"]["available"])
        self.assertTrue(endpoint["comparison"]["status_changed"])
        self.assertTrue(endpoint["comparison"]["body_changed"])
        self.assertTrue(endpoint["gateway"]["request"]["query_values_redacted"])
        self.assertNotIn("do-not-report", str(endpoint["direct"]["response"]))
        self.assertTrue(all(request.method == "GET" for request in requests))
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(request.url.params.get("page") == "1" for request in requests))
        self.assertEqual(len(result["skipped_endpoints"]), 4)
        self.assertEqual(probed_ports, [8081, 8082, 8083, 8084])

    async def test_standard_scan_probes_range_without_manual_port_entries(self):
        requests = []
        probed_ports = []
        progress_events = []

        async def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"ok": True})

        async def port_probe(hostname, port):
            probed_ports.append(port)
            return False

        async def report_progress(event):
            progress_events.append(event)

        result = await GatewayBypass(
            transport=httpx.MockTransport(handler),
            port_probe=port_probe,
        ).analyze(
            "http://localhost:8085",
            [{"url": "http://localhost:8085/api/items", "method": "GET"}],
            port_start=8081,
            port_end=8082,
            progress_callback=report_progress,
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["ports_scanned"], 2)
        self.assertIn("No HTTP-listening ports", result["reason"])
        self.assertEqual(probed_ports, [8081, 8082])
        self.assertIn("Scanned 2 of 2", progress_events[0]["detail"])
        self.assertEqual(requests, [])

    async def test_tcp_probe_finds_an_open_loopback_port(self):
        async def close_connection(reader, writer):
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(
            close_connection,
            "127.0.0.1",
            0,
        )
        port = server.sockets[0].getsockname()[1]
        try:
            open_ports = await GatewayBypass()._open_ports(
                "127.0.0.1",
                [port, 1 if port != 1 else 2],
            )
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(open_ports, [port])

    async def test_successful_status_without_gateway_access_control_is_inconclusive(self):
        async def handler(request):
            return httpx.Response(200, json={"ok": True})

        async def port_probe(hostname, port):
            return port == 8081

        result = await GatewayBypass(
            transport=httpx.MockTransport(handler),
            port_probe=port_probe,
        ).analyze(
            "http://localhost:8085",
            [{"url": "http://localhost:8085/api/items", "method": "GET"}],
            port_start=8081,
            port_end=8081,
        )

        endpoint = result["services"][0]["endpoints"][0]
        self.assertEqual(endpoint["status"], "inconclusive")
        self.assertIn("did not establish a Gateway-only", endpoint["reason"])

    async def test_standard_range_is_configurable_and_full_range_is_automatic(self):
        default = GatewayBypass._candidate_port_range("standard", 8085, None, None)
        standard = GatewayBypass._candidate_port_range("standard", 8085, 8080, 8090)
        full = GatewayBypass._candidate_port_range("full", 8085, 8080, 8090)

        self.assertEqual((default.start, default.stop - 1), (8053, 8117))
        self.assertEqual((standard.start, standard.stop - 1), (8080, 8090))
        self.assertEqual((full.start, full.stop - 1), (1, 65535))
        with self.assertRaisesRegex(ValueError, "must not exceed"):
            GatewayBypass._candidate_port_range("standard", 8085, 8090, 8080)
        with self.assertRaisesRegex(ValueError, "limited to 10000"):
            GatewayBypass._candidate_port_range("standard", 8085, 1, 10001)

    async def test_discovered_origins_are_gateway_and_no_ports_are_inferred(self):
        requests = []

        async def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"ok": True})

        async def port_probe(hostname, port):
            return False

        result = await GatewayBypass(
            transport=httpx.MockTransport(handler),
            port_probe=port_probe,
        ).analyze(
            "http://localhost:8085",
            [
                {"url": "http://localhost:8085/api/items", "method": "GET"},
                {"url": "http://127.0.0.1:8081/api/items", "method": "GET"},
            ],
            port_start=8081,
            port_end=8085,
        )

        self.assertEqual(result["services"], [])
        self.assertEqual(result["status"], "inconclusive")
        self.assertIn("No HTTP-listening ports", result["reason"])
        self.assertEqual(
            {origin["port"] for origin in result["gateway_origins"]},
            {8081, 8085},
        )
        self.assertEqual(requests, [])

    async def test_discovered_gateway_ports_are_excluded_from_candidates(self):
        requests = []

        async def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"ok": True})

        async def port_probe(hostname, port):
            return True

        result = await GatewayBypass(
            transport=httpx.MockTransport(handler),
            port_probe=port_probe,
        ).analyze(
            "http://localhost:8085",
            [
                {
                    "url": "http://localhost:8085/api/items",
                    "method": "GET",
                },
                {"url": "http://localhost:8081/api/items", "method": "GET"},
            ],
            port_start=8081,
            port_end=8081,
        )

        self.assertEqual(result["services"], [])
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(requests, [])
        self.assertEqual(
            result["excluded_service_origins"][0]["port"],
            8081,
        )

    async def test_non_loopback_gateway_endpoint_is_not_requested(self):
        requests = []

        async def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"ok": True})

        result = await GatewayBypass(
            transport=httpx.MockTransport(handler)
        ).analyze(
            "http://localhost:8085",
            [
                {
                    "url": "https://api.example.test/api/items",
                    "method": "GET",
                }
            ],
            port_start=8081,
            port_end=8081,
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["services"], [])
        self.assertEqual(requests, [])
        self.assertIn("loopback", result["skipped_endpoints"][0]["reason"])

    async def test_active_checks_are_skipped_for_non_loopback_gateway(self):
        result = await GatewayBypass().analyze(
            "https://example.test",
            [{"url": "https://api.example.test/api/items", "method": "GET"}],
        )

        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["services"], [])
        self.assertIn("loopback", result["reason"])

    async def test_input_origin_is_recorded_as_a_gateway(self):
        async def port_probe(hostname, port):
            return False

        result = await GatewayBypass(
            port_probe=port_probe,
        ).analyze(
            "http://localhost:3000",
            [{"url": "http://localhost:3000/api/items", "method": "GET"}],
            port_start=2968,
            port_end=3032,
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertIn(
            {
                "origin": "http://localhost:3000",
                "port": 3000,
                "host": "localhost",
            },
            result["gateway_origins"],
        )

if __name__ == "__main__":
    unittest.main()
