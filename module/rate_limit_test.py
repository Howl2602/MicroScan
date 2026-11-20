import time

import httpx

from module.signin import LoginConfigurationError, Signin


class RateLimitTest:
    TEST_MODULE = "rate_limit"
    TIMEOUT_SECONDS = 8
    SCAN_REQUEST_BUDGET = 100
    STANDARD_BASELINE_REQUESTS = 3
    STANDARD_BURST_REQUESTS = 8
    FULL_BURST_REQUESTS = 8

    def __init__(self, transport=None):
        self.transport = transport

    def analyze(
        self,
        target,
        endpoint,
        scan_mode="standard",
        cancellation_event=None,
        request_budget=None,
        headers=None,
    ):
        method = str(endpoint.get("method") or "GET").upper()
        path = str(endpoint.get("path") or "/")
        burst_limit = (
            self.FULL_BURST_REQUESTS
            if scan_mode == "full"
            else self.STANDARD_BURST_REQUESTS
        )
        baseline_requests = self.STANDARD_BASELINE_REQUESTS
        configured_request_count = baseline_requests + burst_limit
        request_limit = (
            configured_request_count
            if request_budget is None
            else max(min(int(request_budget), configured_request_count), 0)
        )

        try:
            normalized_target = Signin.normalize_target(target)
        except LoginConfigurationError as exc:
            return self._error_result(method, path, str(exc))

        url = f"{normalized_target}{path}"
        observations = []
        status_codes = []
        retry_after_values = []
        rate_limit_headers = {}

        try:
            client_options = {
                "timeout": self.TIMEOUT_SECONDS,
                "follow_redirects": False,
                "trust_env": False,
            }
            if self.transport is not None:
                client_options["transport"] = self.transport
            with httpx.Client(**client_options) as client:
                for index in range(request_limit):
                    if cancellation_event and cancellation_event.is_set():
                        break
                    phase = "baseline" if index < baseline_requests else "burst"
                    started_at = time.perf_counter()
                    try:
                        response = client.request(method, url, headers=headers)
                        elapsed_ms = round(
                            (time.perf_counter() - started_at) * 1000,
                            2,
                        )
                    except httpx.TimeoutException:
                        observations.append(
                            {
                                "phase": phase,
                                "request_attempted": True,
                                "status": "error",
                                "reason": "Request timed out.",
                                "latency_ms": round(
                                    (time.perf_counter() - started_at) * 1000,
                                    2,
                                ),
                            }
                        )
                        break
                    except httpx.HTTPError:
                        observations.append(
                            {
                                "phase": phase,
                                "request_attempted": True,
                                "status": "error",
                                "reason": "HTTP request failed.",
                                "latency_ms": round(
                                    (time.perf_counter() - started_at) * 1000,
                                    2,
                                ),
                            }
                        )
                        break

                    status_code = response.status_code
                    status_codes.append(status_code)
                    response_headers = {}
                    for name, value in response.headers.items():
                        lower_name = name.lower()
                        if (
                            lower_name == "retry-after"
                            or lower_name.startswith("x-ratelimit")
                            or lower_name.startswith("ratelimit")
                        ):
                            response_headers[lower_name] = str(value)[:128]
                    for name, value in response_headers.items():
                        if name.startswith("x-ratelimit") or name.startswith("ratelimit"):
                            rate_limit_headers[name] = value
                        elif name == "retry-after" and status_code == 429:
                            retry_after_values.append(value)
                    observations.append(
                        {
                            "phase": phase,
                            "request_attempted": True,
                            "status_code": status_code,
                            "latency_ms": elapsed_ms,
                            "headers": response_headers,
                        }
                    )
                    if status_code == 429:
                        break
                    if status_code == 403:
                        break
        except httpx.HTTPError:
            observations.append(
                {
                    "phase": "baseline",
                    "request_attempted": False,
                    "status": "error",
                    "reason": "HTTP client could not complete the test.",
                }
            )

        requests_sent = sum(
            1
            for observation in observations
            if observation.get("request_attempted")
        )
        has_429 = 429 in status_codes
        has_denial = any(code in {401, 403} for code in status_codes)
        has_error = any(observation.get("status") == "error" for observation in observations)
        has_rate_limit_headers = bool(rate_limit_headers)

        if has_429:
            status = "not_vulnerable_in_test"
            reason = "The endpoint returned HTTP 429, indicating throttling in the tested burst."
        elif has_denial:
            status = "inconclusive"
            reason = (
                "The complete bounded burst returned HTTP 401 to every probe. "
                "No throttling response was observed for unauthenticated requests; "
                "authenticated rate-limit behavior remains untested."
                if len(status_codes) == configured_request_count
                and all(code == 401 for code in status_codes)
                and not headers
                else (
                    "The complete authenticated burst returned HTTP 401 to every probe; "
                    "the supplied session was not accepted, so rate limiting could not "
                    "be assessed for this endpoint."
                    if len(status_codes) == configured_request_count
                    and all(code == 401 for code in status_codes)
                    else (
                        "The endpoint denied the probe with HTTP 401/403 before the "
                        "complete burst; no rate-limit conclusion is supported."
                    )
                )
            )
        elif has_error:
            status = "error"
            reason = "One or more probes failed or timed out."
        elif has_rate_limit_headers:
            status = "inconclusive"
            reason = (
                "Rate-limit headers were observed, but the tested burst did not "
                "trigger a throttling response."
            )
        elif len(status_codes) == configured_request_count and all(
            code not in {429, 503} for code in status_codes
        ):
            status = "potential"
            reason = (
                "No HTTP 429 or Retry-After response was observed across the complete "
                "baseline and burst in the tested scope; this does not prove that no "
                "rate limit exists outside this test window."
            )
        else:
            status = "inconclusive"
            reason = (
                "The response pattern was not sufficient to classify rate-limit behavior."
                if requests_sent >= configured_request_count
                else (
                    "The per-scan rate-limit request budget or cancellation stopped "
                    "the endpoint test before the complete baseline and burst."
                )
            )

        test_case = {
            "test_case": "controlled_burst",
            "method": method,
            "path": path,
            "status": status,
            "reason": reason,
            "request_attempted": requests_sent > 0,
            "request_count": requests_sent,
            "baseline_request_count": min(baseline_requests, requests_sent),
            "burst_request_count": max(requests_sent - baseline_requests, 0),
            "status_codes": status_codes,
            "latencies_ms": [
                observation["latency_ms"]
                for observation in observations
                if "latency_ms" in observation
            ],
            "retry_after": retry_after_values,
            "rate_limit_headers": rate_limit_headers,
            "authentication_context": (
                "authenticated" if headers else "unauthenticated"
            ),
        }
        return {
            "test_module": self.TEST_MODULE,
            "status": status,
            "reason": reason,
            "tested_endpoint": True,
            "request_count": requests_sent,
            "observations": observations,
            "test_cases": [test_case],
            "evidence": [
                {
                    "baseline_request_count": baseline_requests,
                    "burst_request_count": burst_limit,
                    "configured_request_count": configured_request_count,
                    "requests_sent": requests_sent,
                    "status_codes": status_codes,
                    "retry_after": retry_after_values,
                    "rate_limit_headers": rate_limit_headers,
                }
            ],
        }

    @staticmethod
    def _error_result(method, path, reason):
        test_case = {
            "test_case": "controlled_burst",
            "method": method,
            "path": path,
            "status": "error",
            "reason": reason,
            "request_attempted": False,
            "request_count": 0,
        }
        return {
            "test_module": RateLimitTest.TEST_MODULE,
            "status": "error",
            "reason": reason,
            "tested_endpoint": False,
            "request_count": 0,
            "observations": [],
            "test_cases": [test_case],
            "evidence": [],
        }
