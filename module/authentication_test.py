import json
import re
from urllib.parse import urljoin, urlsplit

import httpx

from module.endpoint_selection import EndpointSelector
from module.signin import LoginConfigurationError, LoginError, Signin


class AuthenticationTest:
    INVALID_TOKEN = "******"
    TIMEOUT_SECONDS = 8

    def __init__(self, endpoint_selector=None):
        self.endpoint_selector = endpoint_selector or EndpointSelector()

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

    @staticmethod
    def _has_data(response):
        if not 200 <= response.status_code < 300:
            return False
        try:
            body = response.json()
        except (ValueError, json.JSONDecodeError):
            return False

        if isinstance(body, list):
            return bool(body)
        if not isinstance(body, dict):
            return False

        message = body.get("message")
        if isinstance(message, str) and any(
            term in message.lower()
            for term in (
                "unauthorized",
                "not authorized",
                "forbidden",
                "invalid token",
                "login required",
            )
        ):
            return False
        if body.get("success") is False or body.get("authenticated") is False:
            return False
        if body.get("error") or body.get("errors"):
            return False

        metadata = {
            "message",
            "error",
            "errors",
            "status",
            "success",
            "authenticated",
            "code",
        }
        return any(
            key.lower() not in metadata and value not in (None, "", [], {})
            for key, value in body.items()
        )

    @classmethod
    def _is_denied(cls, response):
        if response.status_code in {401, 403}:
            return True
        if not 200 <= response.status_code < 300:
            return False
        try:
            body = response.json()
        except (ValueError, json.JSONDecodeError):
            return False
        if not isinstance(body, dict):
            return False
        if body.get("success") is False or body.get("authenticated") is False:
            return True
        message = body.get("message")
        return isinstance(message, str) and any(
            term in message.lower()
            for term in (
                "unauthorized",
                "not authorized",
                "forbidden",
                "invalid token",
                "login required",
            )
        )

    @classmethod
    def _response_evidence(cls, response):
        try:
            body = response.json()
        except (ValueError, json.JSONDecodeError):
            body = None

        safe_keys = []
        if isinstance(body, dict):
            sensitive = (
                "token",
                "password",
                "secret",
                "authorization",
                "cookie",
                "credential",
            )
            safe_keys = [
                key
                for key in body
                if isinstance(key, str)
                and not any(word in key.lower() for word in sensitive)
            ][:20]
        challenge = response.headers.get("www-authenticate", "")
        challenge_scheme = challenge.split(None, 1)[0] if challenge else None
        if challenge_scheme and not re.fullmatch(
            r"[A-Za-z0-9._-]+", challenge_scheme
        ):
            challenge_scheme = None

        return {
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", "").split(";", 1)[0],
            "body_bytes": len(response.content),
            "json_keys": safe_keys,
            "protected_data_observed": cls._has_data(response),
            "authentication_denied": cls._is_denied(response),
            "observed_challenge_scheme": challenge_scheme,
        }

    @staticmethod
    def _test_result(status, reason, evidence, tested_endpoint=None):
        return {
            "test_module": EndpointSelector.TEST_MODULE,
            "status": status,
            "reason": reason,
            "tested_endpoint": tested_endpoint,
            "evidence": evidence,
        }

    def evaluate(self, target, selected_endpoint, discovered_endpoints=None):
        if selected_endpoint is None:
            return self._test_result(
                "skipped",
                "No suitable discovered GET endpoint was available; MicroScan will not invent a probe path.",
                [],
            )

        protected_path = selected_endpoint["path"]
        selection_reason = selected_endpoint["reason"]
        candidate_endpoint = selected_endpoint.get("endpoint")
        try:
            url = self._scope_url(target, protected_path)
        except (LoginConfigurationError, ValueError) as exc:
            result = self._test_result("skipped", str(exc), [], protected_path)
            result["endpoint_selection_reason"] = selection_reason
            return result

        unauthenticated_checks = []
        responses = {}
        for label, headers in (
            ("without_credentials", None),
            ("invalid_bearer_token", {"Authorization": f"Bearer {self.INVALID_TOKEN}"}),
        ):
            try:
                response = self._run_http_request("GET", url, headers=headers)
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
        discovery = {
            "tested_endpoint": {
                "method": "GET",
                "path": protected_path,
                "discovery_status": (
                    self.endpoint_selector.discovery_status(candidate_endpoint)
                    if candidate_endpoint
                    else None
                ),
            },
            "endpoint_selection_reason": selection_reason,
            "discovered_login_endpoints": login_candidates,
            "authentication_mechanism": "unknown",
            "note": (
                "Login endpoints are reported only when discovered. No login schema or "
                "credentials are inferred."
            ),
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
            "reason": (
                "No user-provided login configuration is available; unauthenticated checks ran, "
                "but authenticated coverage is unavailable."
            ),
            "evidence": None,
        }
        try:
            auth_config, discovered_login_candidates, configuration_note = (
                Signin.configured_auth(discovered_endpoints)
            )
            discovery["discovered_login_endpoints"] = discovered_login_candidates
            if auth_config is None:
                authenticated_check["reason"] = configuration_note
            else:
                token_info = Signin().signin(target, auth_config)
                token = token_info.pop("token")
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
                if not scheme:
                    authenticated_check["reason"] = (
                        "Login succeeded and a token was obtained, but the API did not provide "
                        "an authorization scheme. Configure auth_scheme in MICROSCAN_AUTH_CONFIG."
                    )
                elif not re.fullmatch(r"[A-Za-z0-9-]+", token_info["auth_header"]):
                    authenticated_check["reason"] = (
                        "Login succeeded, but configured auth_header is invalid."
                    )
                else:
                    try:
                        response = self._run_http_request(
                            "GET",
                            url,
                            headers={
                                token_info["auth_header"]: f"{scheme} {token}"
                            },
                        )
                        responses["authenticated"] = response
                        authenticated_check = {
                            "status": "tested",
                            "reason": self._authenticated_probe_reason(scheme_source),
                            "login_status": token_info["http_status"],
                            "auth_scheme_source": scheme_source,
                            "login_response_content_type": token_info[
                                "response_content_type"
                            ],
                            "evidence": self._response_evidence(response),
                        }
                    except httpx.TimeoutException:
                        authenticated_check = {
                            "status": "error",
                            "reason": "Authenticated endpoint request timed out.",
                            "login_status": token_info["http_status"],
                            "evidence": None,
                        }
                    except httpx.RequestError:
                        authenticated_check = {
                            "status": "error",
                            "reason": (
                                "Authenticated endpoint request failed to reach the "
                                "configured target."
                            ),
                            "login_status": token_info["http_status"],
                            "evidence": None,
                        }
                token = None
        except LoginConfigurationError as exc:
            authenticated_check = {
                "status": "error",
                "reason": str(exc),
                "evidence": None,
            }
        except LoginError as exc:
            authenticated_check = {
                "status": "error",
                "reason": str(exc),
                "login_status": exc.status_code,
                "evidence": None,
            }
        finally:
            token = None

        unauth_data = (
            self._has_data(responses["without_credentials"])
            if "without_credentials" in responses
            else False
        )
        invalid_data = (
            self._has_data(responses["invalid_bearer_token"])
            if "invalid_bearer_token" in responses
            else False
        )
        if unauth_data or invalid_data:
            status = "potential"
            reason = (
                "The selected endpoint returned structured data without valid credentials. "
                "Confirm that the data is intended to be protected; this is a potential exposure, "
                "not proof that the route requires authentication."
            )
        elif (
            authenticated_check["status"] == "tested"
            and "authenticated" in responses
            and self._has_data(responses["authenticated"])
            and "without_credentials" in responses
            and "invalid_bearer_token" in responses
            and self._is_denied(responses["without_credentials"])
            and self._is_denied(responses["invalid_bearer_token"])
        ):
            status = "not_vulnerable_in_test"
            reason = (
                "This endpoint denied requests without credentials and with the invalid bearer "
                "probe, then returned structured data with the configured token. This is limited "
                "to this endpoint and test; it does not certify the API's overall authentication."
            )
        elif not responses:
            status = "error"
            reason = "Neither unauthenticated probe completed successfully."
        else:
            status = "inconclusive"
            reason = (
                "The endpoint's expected access policy could not be established from the available "
                "unauthenticated, invalid-token, and optional authenticated evidence."
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

        result = self._test_result(status, reason, evidence, protected_path)
        result.update(
            {
                "endpoint_selection_reason": selection_reason,
                "discovery": discovery,
                "unauthenticated_checks": unauthenticated_checks,
                "authenticated_check": authenticated_check,
                "authentication_mechanism": discovery["authentication_mechanism"],
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
