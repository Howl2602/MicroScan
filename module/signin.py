import json
import logging
import os
import re
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from dotenv import load_dotenv

from module.endpoint_selection import EndpointSelector


logger = logging.getLogger(__name__)


class LoginError(Exception):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class LoginConfigurationError(LoginError):
    pass


class Signin:
    TIMEOUT_SECONDS = 8
    MAX_LOGIN_CANDIDATES = 3
    TOKEN_FIELDS = ("access_token", "accessToken", "token", "jwt")
    USERNAME_FIELDS = {"email", "login", "user", "username"}
    PASSWORD_FIELDS = {"pass", "passwd", "password"}
    ENV_FILE = Path(__file__).resolve().parent.parent / ".env"

    @staticmethod
    def normalize_target(target):
        candidate = (target or "").strip()
        if not candidate or any(character.isspace() for character in candidate):
            raise LoginConfigurationError("Target must be a valid HTTP(S) origin.")
        if "://" not in candidate:
            candidate = f"http://{candidate}"

        try:
            parsed = urlsplit(candidate)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
            ):
                raise ValueError
            parsed.port
        except ValueError as exc:
            raise LoginConfigurationError("Target must be a valid HTTP(S) origin.") from exc

        return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))

    @classmethod
    def discover_login_candidates(cls, discovered_endpoints):
        return EndpointSelector.discover_login_candidates(discovered_endpoints)

    @staticmethod
    def _parse_json_env(variable):
        raw = os.environ.get(variable)
        if not raw:
            return None
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LoginConfigurationError(f"{variable} must contain valid JSON.") from exc
        if not isinstance(value, dict) or not value:
            raise LoginConfigurationError(f"{variable} must be a non-empty JSON object.")
        return value

    @classmethod
    def load_environment(cls, dotenv_path=None):
        load_dotenv(
            dotenv_path=dotenv_path or cls.ENV_FILE,
            override=False,
        )

    @staticmethod
    def _login_response_failed(data):
        containers = [data]
        if isinstance(data, dict):
            containers.extend((data.get("data"), data.get("result")))
        for container in containers:
            if not isinstance(container, dict):
                continue
            if container.get("success") is False or container.get("authenticated") is False:
                return True
            if container.get("error") or container.get("errors"):
                return True
        return False

    @classmethod
    def _credential_payloads(cls, username, password, candidates):
        payloads = {}
        for candidate in candidates:
            fields = candidate.get("request_body_fields")
            content_type = candidate.get("request_content_type")
            if (
                not candidate.get("request_format_evidence")
                or not isinstance(fields, list)
                or content_type
                not in {
                    "application/json",
                    "application/x-www-form-urlencoded",
                    "multipart/form-data",
                }
            ):
                continue
            username_key = next(
                (
                    field
                    for field in fields
                    if isinstance(field, str) and field.lower() in cls.USERNAME_FIELDS
                ),
                None,
            )
            password_key = next(
                (
                    field
                    for field in fields
                    if isinstance(field, str) and field.lower() in cls.PASSWORD_FIELDS
                ),
                None,
            )
            if (
                not username_key
                or not password_key
                or any(
                    field not in {username_key, password_key}
                    for field in fields
                )
            ):
                continue
            payloads[candidate["path"]] = {
                "payload": {username_key: username, password_key: password},
                "content_type": content_type,
            }
        return payloads

    @classmethod
    def configured_auth(cls, discovered_endpoints):
        cls.load_environment()
        config = cls._parse_json_env("MICROSCAN_AUTH_CONFIG")
        legacy_payload = cls._parse_json_env("MICROSCAN_LOGIN_PAYLOAD")
        candidates = cls.discover_login_candidates(discovered_endpoints)
        username = os.environ.get("MICROSHIELD_USERNAME", "").strip()
        password = os.environ.get("MICROSHIELD_PASSWORD", "")
        candidate_configurations = (
            cls._credential_payloads(username, password, candidates)
            if config is None
            and legacy_payload is None
            and username
            and password.strip()
            else {}
        )
        logger.info(
            "Login configuration evaluated | candidates=%d | "
            "evidence_supported_contracts=%d | credentials_configured=%s",
            len(candidates),
            len(candidate_configurations),
            bool(username and password.strip()),
        )
        credential_payload = (
            next(iter(candidate_configurations.values()))["payload"]
            if candidate_configurations
            else None
        )

        if config is None and legacy_payload is None and credential_payload is None:
            if username and password.strip():
                note = (
                    "Credentials are configured, but no discovered login candidate has a "
                    "complete evidence-supported request format. No credentials were sent."
                )
            elif username or password:
                note = (
                    "Authenticated coverage is unavailable because both "
                    "MICROSHIELD_USERNAME and MICROSHIELD_PASSWORD must be configured."
                )
            elif candidates:
                note = (
                    "A login route was discovered, but no evidence-supported request format and "
                    "complete credential pair are available. No login request was sent."
                )
            else:
                note = (
                    "No login endpoint was found in authorized Discovery evidence; no login request "
                    "was sent and valid-token coverage is unavailable. Configure "
                    "MICROSHIELD_USERNAME and MICROSHIELD_PASSWORD after login request evidence "
                    "is discovered."
                )
            return None, candidates, note
        if config is None:
            config = {"payload": legacy_payload or credential_payload}

        payload = config.get("payload", legacy_payload or credential_payload)
        if not isinstance(payload, dict) or not payload:
            raise LoginConfigurationError(
                "MICROSCAN_AUTH_CONFIG must provide a non-empty payload object."
            )

        login_endpoint = config.get("login_endpoint") or os.environ.get(
            "MICROSCAN_LOGIN_ENDPOINT"
        )
        automatic_credentials = (
            legacy_payload is None
            and credential_payload is not None
            and config.get("login_endpoint") is None
        )
        if not login_endpoint and candidate_configurations:
            login_endpoint = next(iter(candidate_configurations))
        try:
            login_route_path = (
                urlsplit(login_endpoint).path
                if isinstance(login_endpoint, str)
                and (urlsplit(login_endpoint).scheme or urlsplit(login_endpoint).netloc)
                else login_endpoint
            )
        except ValueError:
            login_route_path = None
        if (
            automatic_credentials
            and login_endpoint
            and login_route_path not in candidate_configurations
        ):
            return None, candidates, (
                "Configured login route has no matching authorized Discovery request "
                "evidence; credentials were not sent."
            )
        if not login_endpoint and candidates:
            login_endpoint = candidates[0]["path"]
        if not login_endpoint:
            return None, candidates, (
                "Login configuration is present, but no eligible POST login endpoint was "
                "found in authorized Discovery evidence."
            )
        if not isinstance(login_endpoint, str):
            raise LoginConfigurationError(
                "Configured login_endpoint must be a path or target-origin URL."
            )

        inferred_content_type = (
            candidate_configurations.get(login_route_path, {}).get("content_type")
            or next(
                (
                    candidate.get("request_content_type")
                    for candidate in candidates
                    if candidate["path"] == login_route_path
                    and candidate.get("request_format_evidence")
                ),
                None,
            )
        )
        content_type = str(
            config.get("content_type")
            or inferred_content_type
            or ("application/json" if legacy_payload or config is not None else "")
        ).split(";", 1)[0].strip().lower()
        if content_type not in {
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        }:
            raise LoginConfigurationError(
                "Configured login content_type must be JSON, URL-encoded, or multipart form data."
            )
        auth_header = config.get("auth_header", "Authorization")
        if not isinstance(auth_header, str) or not re.fullmatch(
            r"[A-Za-z0-9-]+", auth_header
        ):
            raise LoginConfigurationError("Configured auth_header is invalid.")
        auth_scheme = config.get("auth_scheme")
        if auth_scheme is not None and (
            not isinstance(auth_scheme, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]+", auth_scheme.strip())
        ):
            raise LoginConfigurationError("Configured auth_scheme is invalid.")

        return {
            "login_endpoint": login_endpoint,
            "method": str(config.get("method", "POST")).upper(),
            "payload": payload,
            "content_type": content_type,
            "token_field": config.get("token_field"),
            "auth_header": auth_header,
            "auth_scheme": auth_scheme,
            "explicit_login_endpoint": bool(
                config.get("login_endpoint")
                or os.environ.get("MICROSCAN_LOGIN_ENDPOINT")
            ),
            "_candidate_configurations": candidate_configurations,
        }, candidates, None

    @classmethod
    def extract_token(cls, data, token_field=None):
        containers = [data]
        if isinstance(data, dict):
            containers.extend((data.get("data"), data.get("result")))

        if token_field:
            keys = str(token_field).split(".")
            for container in containers:
                value = container
                for key in keys:
                    if not isinstance(value, dict):
                        value = None
                        break
                    value = value.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

        pending = list(containers)
        visited = set()
        while pending:
            container = pending.pop(0)
            if not isinstance(container, dict):
                continue
            identity = id(container)
            if identity in visited:
                continue
            visited.add(identity)
            for key in cls.TOKEN_FIELDS:
                value = container.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            pending.extend(
                [
                    value
                    for value in container.values()
                    if isinstance(value, dict)
                ][: max(0, 32 - len(visited) - len(pending))]
            )
        return None

    @staticmethod
    def token_type(data):
        containers = [data]
        if isinstance(data, dict):
            containers.extend((data.get("data"), data.get("result")))
        pending = list(containers)
        visited = set()
        while pending:
            container = pending.pop(0)
            if not isinstance(container, dict):
                continue
            identity = id(container)
            if identity in visited:
                continue
            visited.add(identity)
            value = container.get("token_type") or container.get("tokenType")
            if isinstance(value, str) and value.strip():
                return value.strip()
            pending.extend(
                [
                    nested
                    for nested in container.values()
                    if isinstance(nested, dict)
                ][: max(0, 32 - len(visited) - len(pending))]
            )
        return None

    @staticmethod
    def token_mechanism(token, token_type):
        if token_type:
            if len(token.split(".")) == 3:
                return f"JWT over {token_type}"
            return token_type.lower()
        parts = token.split(".")
        if len(parts) == 3 and all(parts):
            return "jwt (token format observed; authorization scheme unknown)"
        return "unknown (token returned; authorization scheme unknown)"

    @classmethod
    def _login_url(cls, target, path):
        origin = cls.normalize_target(target)
        candidate = (path or "").strip()
        if not candidate:
            raise LoginConfigurationError("A login endpoint path or URL is required.")
        try:
            parsed_path = urlsplit(candidate)
        except ValueError as exc:
            raise LoginConfigurationError(
                "Configured login endpoint is not a valid path or URL."
            ) from exc
        base = urlsplit(origin)
        if parsed_path.scheme or parsed_path.netloc:
            if (
                parsed_path.scheme not in {"http", "https"}
                or parsed_path.scheme != base.scheme
                or parsed_path.netloc.lower() != base.netloc.lower()
                or parsed_path.username
                or parsed_path.password
            ):
                raise LoginConfigurationError(
                    "Configured login URL must use the configured target origin."
                )
        elif not candidate.startswith("/"):
            raise LoginConfigurationError(
                "Login endpoint must be an absolute path on the target origin."
            )
        if parsed_path.query or parsed_path.fragment or not parsed_path.path.startswith("/"):
            raise LoginConfigurationError(
                "Login endpoint must not contain query or fragment data."
            )
        if any(
            segment.lower() in EndpointSelector.REGISTRATION_PATH_SEGMENTS
            for segment in parsed_path.path.split("/")
        ):
            raise LoginConfigurationError(
                "Registration endpoints cannot be used for login."
            )
        return urlunsplit((base.scheme, base.netloc, parsed_path.path, "", ""))

    def signin(self, target, configuration):
        if not isinstance(configuration, dict):
            raise LoginConfigurationError("Login configuration is required.")
        login_url = self._login_url(target, configuration.get("login_endpoint"))
        method = str(configuration.get("method", "POST")).upper()
        if method != "POST":
            raise LoginConfigurationError("Only POST login requests are supported.")
        route = urlsplit(login_url).path
        logger.info("Login executor invoked | method=%s | route=%s", method, route)

        payload = configuration.get("payload")
        if not isinstance(payload, dict) or not payload:
            raise LoginConfigurationError("Login payload must be a non-empty JSON object.")

        content_type = configuration.get("content_type", "application/json")
        headers = {"Content-Type": content_type}
        request_kwargs = {"headers": headers}
        if content_type == "application/json":
            request_kwargs["headers"] = headers
            request_kwargs["json"] = payload
        elif content_type == "application/x-www-form-urlencoded":
            request_kwargs["headers"] = headers
            request_kwargs["content"] = urlencode(payload)
        elif content_type == "multipart/form-data":
            request_kwargs["files"] = {
                key: (None, str(value)) for key, value in payload.items()
            }
        else:
            raise LoginConfigurationError("Unsupported login content type.")

        try:
            response = httpx.post(
                login_url,
                timeout=self.TIMEOUT_SECONDS,
                follow_redirects=False,
                **request_kwargs,
            )
        except httpx.TimeoutException as exc:
            raise LoginError("Login request timed out.") from exc
        except httpx.RequestError as exc:
            raise LoginError("Login request could not reach the configured target.") from exc

        if not 200 <= response.status_code < 300:
            logger.info(
                "Login executor response | method=%s | route=%s | http_status=%d | "
                "token_detected=false | session_detected=false",
                method,
                route,
                response.status_code,
            )
            raise LoginError(
                f"Login endpoint returned HTTP {response.status_code}.",
                status_code=response.status_code,
            )
        try:
            data = response.json()
        except ValueError:
            data = None

        if self._login_response_failed(data):
            logger.info(
                "Login executor response | method=%s | route=%s | http_status=%d | "
                "token_detected=false | session_detected=false",
                method,
                route,
                response.status_code,
            )
            raise LoginError(
                "Login endpoint reported an unsuccessful authentication response.",
                status_code=response.status_code,
            )

        token = self.extract_token(data, configuration.get("token_field"))
        cookies = [
            f"{cookie.name}={cookie.value}"
            for cookie in response.cookies.jar
            if cookie.name and cookie.value
        ]
        if data is None and not cookies:
            logger.info(
                "Login executor response | method=%s | route=%s | http_status=%d | "
                "token_detected=false | session_detected=false",
                method,
                route,
                response.status_code,
            )
            raise LoginError(
                "Login response contained invalid JSON and did not contain a session cookie.",
                status_code=response.status_code,
            )
        if not token and not cookies:
            logger.info(
                "Login executor response | method=%s | route=%s | http_status=%d | "
                "token_detected=false | session_detected=false",
                method,
                route,
                response.status_code,
            )
            raise LoginError(
                "Login response did not contain a supported access token or session cookie.",
                status_code=response.status_code,
            )

        token_type = self.token_type(data) if token else None
        configured_scheme = configuration.get("auth_scheme")
        scheme = str(configured_scheme or token_type or "").strip()
        jwt_format = bool(token and len(token.split(".")) == 3 and all(token.split(".")))
        defaulted_bearer_scheme = not scheme and jwt_format
        if defaulted_bearer_scheme:
            scheme = "Bearer"
        if scheme and not re.fullmatch(r"[A-Za-z0-9._-]+", scheme):
            raise LoginConfigurationError("Configured or observed auth scheme is invalid.")
        mechanism = (
            self.token_mechanism(token, token_type)
            if token
            else "cookie-based session"
        )
        if defaulted_bearer_scheme:
            mechanism = "JWT over Bearer (inferred from JWT format)"
        logger.info(
            "Login executor response | method=%s | route=%s | http_status=%d | "
            "token_detected=%s | session_detected=%s",
            method,
            route,
            response.status_code,
            bool(token),
            bool(cookies),
        )
        return {
            "token": token,
            "cookie": "; ".join(cookies) if cookies else None,
            "credential_type": "token" if token else "cookie",
            "auth_header": str(configuration.get("auth_header", "Authorization")),
            "auth_scheme": scheme or None,
            "auth_scheme_source": (
                "configured"
                if configured_scheme
                else "login_response"
                if token_type
                else "jwt_format_default"
                if defaulted_bearer_scheme
                else None
            ),
            "mechanism": mechanism,
            "http_status": response.status_code,
            "response_content_type": response.headers.get("content-type", "").split(";", 1)[0],
        }
