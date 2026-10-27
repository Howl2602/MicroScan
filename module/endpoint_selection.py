import logging
import re
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)


class EndpointSelector:
    TEST_MODULE = "jwt_authentication"
    BOLA_MODULE = "bola_passive_correlation"
    AUTH_PATH_KEYWORDS = (
        "login",
        "log-in",
        "signin",
        "sign-in",
        "sign_in",
        "auth",
        "token",
        "jwt",
        "session",
        "refresh",
        "oauth",
        "signup",
        "sign-up",
        "register",
    )
    USER_KEYWORDS = ("user", "account", "profile", "me", "member")
    ADMIN_KEYWORDS = ("admin", "manager", "settings", "internal", "system")
    RESOURCE_PATTERN = re.compile(
        r"/(users|accounts|posts|orders|products|items|projects)/?$"
    )
    RESOURCE_COLLECTIONS = {
        "users",
        "accounts",
        "posts",
        "orders",
        "products",
        "items",
        "projects",
    }
    RESOURCE_ID_PATTERN = re.compile(
        r"/(users|accounts|posts|orders|products|items|projects)/"
        r"(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,}|[a-z0-9_-]*[0-9][a-z0-9_-]*)/?$",
        re.IGNORECASE,
    )
    SELF_PATH_SEGMENTS = {"me", "self", "current", "profile"}
    SENSITIVE_PATH_SEGMENTS = {"admin", "internal", "system", "settings"}
    UNSUITABLE_PATH_SEGMENTS = {"debug", "internal", "health", "metrics"}
    REGISTRATION_PATH_SEGMENTS = {"register", "registration", "signup", "sign-up"}
    NON_LOGIN_AUTH_PATH_SEGMENTS = {
        "logout",
        "signout",
        "refresh",
        "reset",
        "forgot",
        "recover",
        "verify",
        "verification",
        "callback",
        "authorize",
    }

    @classmethod
    def _path_segments(cls, path):
        return [segment.lower() for segment in path.strip("/").split("/") if segment]

    @classmethod
    def _has_user_context(cls, segments):
        return any(
            segment in cls.USER_KEYWORDS or segment in cls.RESOURCE_COLLECTIONS
            for segment in segments
        )

    @classmethod
    def _is_self_resource(cls, segments):
        return cls._has_user_context(segments) and any(
            segment in cls.SELF_PATH_SEGMENTS for segment in segments
        )

    @classmethod
    def _is_resource_by_id(cls, path):
        return bool(cls.RESOURCE_ID_PATTERN.search(path))

    @classmethod
    def is_authentication_path(cls, path):
        lower_path = path.lower()
        return any(keyword in lower_path for keyword in cls.AUTH_PATH_KEYWORDS)

    def classify_endpoint(self, endpoint):
        path = str(endpoint.get("path") or endpoint.get("target") or "/")
        lower_path = path.lower()
        segments = self._path_segments(path)
        reason_parts = []

        if self.is_authentication_path(path):
            classification = "authentication"
            reason_parts.append("path matches authentication-related keywords")
        elif self._is_self_resource(segments):
            classification = "user_or_account"
            reason_parts.append("path identifies a current-user/self resource")
        elif self._is_resource_by_id(path):
            classification = "resource_by_id"
            reason_parts.append("path matches a resource collection and ID pattern")
        elif any(keyword in lower_path for keyword in self.USER_KEYWORDS):
            classification = "user_or_account"
            reason_parts.append("path matches user/account keywords")
        elif any(keyword in lower_path for keyword in self.ADMIN_KEYWORDS):
            classification = "administrative"
            reason_parts.append("path matches administrative keywords")
        elif self.RESOURCE_PATTERN.search(lower_path):
            classification = "resource_collection"
            reason_parts.append("path resembles a CRUD resource collection")
        else:
            classification = "other"
            reason_parts.append("path did not match a common resource or auth pattern")

        method = endpoint.get("method")
        if method:
            reason_parts.append(f"method={str(method).upper()}")

        applicable_tests = []
        if classification == "authentication":
            applicable_tests.append(self.TEST_MODULE)
        if classification in {
            "resource_collection",
            "resource_by_id",
            "user_or_account",
        }:
            applicable_tests.append(self.BOLA_MODULE)
        return {
            "classification": classification,
            "reason": "; ".join(reason_parts),
            "applicable_tests": applicable_tests,
        }

    @staticmethod
    def discovery_status(endpoint):
        for key in ("status", "status_code", "sc"):
            status = endpoint.get(key)
            if isinstance(status, int):
                return status
            if isinstance(status, str) and status.isdigit():
                return int(status)

        responses = endpoint.get("responses")
        if not isinstance(responses, list):
            return None
        for response in responses:
            if isinstance(response, dict):
                status = (
                    response.get("sc")
                    or response.get("status_code")
                    or response.get("status")
                )
                if isinstance(status, int):
                    return status
                if isinstance(status, str) and status.isdigit():
                    return int(status)
        return None

    @classmethod
    def _candidate_reason(cls, path):
        segments = cls._path_segments(path)
        if cls._is_self_resource(segments):
            return "discovered GET path identifies a current-user/self/profile resource"
        if cls._is_resource_by_id(path):
            return "discovered GET path identifies an individual resource"
        return "discovered GET path identifies a user/account/resource collection"

    def select_authentication_candidate(self, discovered_endpoints, override_path=None):
        if override_path:
            return {
                "endpoint": None,
                "path": override_path,
                "reason": "endpoint was explicitly configured",
            }

        candidates = []
        for index, endpoint in enumerate(discovered_endpoints or []):
            if not isinstance(endpoint, dict):
                continue
            if str(endpoint.get("method") or "").upper() != "GET":
                continue

            path = endpoint.get("path")
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            path_parts = urlsplit(path)
            if (
                path_parts.query
                or path_parts.fragment
                or path_parts.scheme
                or path_parts.netloc
            ):
                continue

            segments = self._path_segments(path)
            if not segments or any("{" in segment or "}" in segment for segment in segments):
                continue
            if self.is_authentication_path(path):
                continue
            if any(segment in self.SENSITIVE_PATH_SEGMENTS for segment in segments):
                continue
            if any(
                token in self.UNSUITABLE_PATH_SEGMENTS
                for segment in segments
                for token in re.split(r"[-_]", segment)
            ):
                continue

            classification = self.classify_endpoint(endpoint)["classification"]
            if classification not in {
                "user_or_account",
                "resource_collection",
                "resource_by_id",
            }:
                continue

            status = self.discovery_status(endpoint)
            if self._is_self_resource(segments):
                priority = 3
            elif self._is_resource_by_id(path):
                priority = 2
            else:
                priority = 1
            candidates.append((priority, index, endpoint, path, status))

        if not candidates:
            return None

        _, _, endpoint, path, status = max(
            candidates,
            key=lambda candidate: (candidate[0], -candidate[1]),
        )
        reason = self._candidate_reason(path)
        if status is not None:
            reason += (
                f"; Kiterunner observed HTTP {status} (candidate signal only, not proof "
                "of endpoint type or authentication enforcement)"
            )
        return {"endpoint": endpoint, "path": path, "reason": reason}

    @classmethod
    def discover_login_candidates(cls, discovered_endpoints):
        allow_methods_by_path = {}
        method_evidence_count = 0
        for endpoint in discovered_endpoints or []:
            if not isinstance(endpoint, dict):
                continue
            path = endpoint.get("path") or endpoint.get("discovered_path")
            if not isinstance(path, str):
                continue
            responses = endpoint.get("responses")
            response_records = [
                endpoint,
                *(
                    response
                    for response in responses
                    if isinstance(response, dict)
                )
            ] if isinstance(responses, list) else [endpoint]
            for response in response_records:
                if not isinstance(response, dict):
                    continue
                status = response.get("sc") or response.get("status_code")
                if status != 405:
                    continue
                headers = response.get("headers") or endpoint.get("headers") or {}
                allow = (
                    response.get("allow")
                    or response.get("allow_header")
                    or endpoint.get("allow")
                    or endpoint.get("allow_header")
                )
                if not allow and isinstance(headers, dict):
                    allow = headers.get("allow") or headers.get("Allow")
                if not isinstance(allow, str):
                    continue
                allow_methods_by_path.setdefault(path.rstrip("/") or "/", set()).update(
                    method.strip().upper()
                    for method in allow.split(",")
                    if re.fullmatch(r"\s*[A-Za-z]+\s*", method)
                )
                method_evidence_count += 1

        candidates = []
        exclusions = []
        for index, endpoint in enumerate(discovered_endpoints or []):
            if not isinstance(endpoint, dict):
                continue
            method = str(endpoint.get("method") or "").upper()
            path = endpoint.get("path") or endpoint.get("discovered_path")
            path_text = (
                re.sub(r"[\r\n\t]", " ", path.split("?", 1)[0].split("#", 1)[0])[:200]
                if isinstance(path, str)
                else "[missing path]"
            )
            segments = (
                cls._path_segments(path)
                if isinstance(path, str) and path.startswith("/")
                else []
            )
            route_looks_auth_related = bool(
                set(segments)
                & {
                    "login", "signin", "sign-in", "sign_in", "authenticate",
                    "token", "register", "registration", "signup", "sign-up",
                    "session", "logout", "refresh",
                }
            )
            if method != "POST" or not isinstance(path, str) or not path.startswith("/"):
                if route_looks_auth_related:
                    exclusions.append(
                        (method or "UNKNOWN", path_text, "Only an observed POST can be a login candidate.")
                    )
                continue
            parsed = urlsplit(path)
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
                exclusions.append(
                    (method, path_text, "Login candidate path must be a relative route without query data.")
                )
                continue
            if not segments or any(
                segment in cls.REGISTRATION_PATH_SEGMENTS
                | cls.NON_LOGIN_AUTH_PATH_SEGMENTS
                for segment in segments
            ):
                if route_looks_auth_related:
                    exclusions.append(
                        (method, path_text, "Registration or non-login authentication route.")
                    )
                continue
            login_terms = {"login", "signin", "sign-in", "sign_in", "authenticate"}
            token_login = "token" in segments and bool(
                {"auth", "session"} & set(segments)
            )
            if not (set(segments) & login_terms or token_login):
                if route_looks_auth_related:
                    exclusions.append(
                        (method, path_text, "Route lacks login/token endpoint evidence.")
                    )
                continue

            status = None
            response_content_type = None
            responses = endpoint.get("responses")
            if isinstance(responses, list):
                for response in responses:
                    if not isinstance(response, dict):
                        continue
                    status = response.get("sc") or response.get("status_code")
                    response_content_type = (
                        response.get("content_type")
                        or response.get("content-type")
                    )
                    if status is not None or response_content_type:
                        break
            sources = endpoint.get("discovery_sources") or endpoint.get("sources") or []
            evidence = endpoint.get("discovery_evidence") or endpoint.get("evidence") or []
            source_names = [
                source for source in sources if isinstance(source, str)
            ] if isinstance(sources, list) else []
            evidence_snippets = [
                entry["snippet"][:500]
                for entry in evidence
                if isinstance(entry, dict) and isinstance(entry.get("snippet"), str)
            ] if isinstance(evidence, list) else []
            raw_body_fields = endpoint.get("request_body_fields")
            request_body_fields = (
                [
                    field
                    for field in raw_body_fields
                    if isinstance(field, str)
                    and re.fullmatch(r"[A-Za-z_$][\w$]*", field)
                ]
                if isinstance(raw_body_fields, list)
                else []
            )
            request_content_type = endpoint.get("request_content_type")
            request_format_evidence = bool(
                request_body_fields
                and request_content_type in {
                    "application/json",
                    "application/x-www-form-urlencoded",
                    "multipart/form-data",
                }
            )
            path_allow_methods = allow_methods_by_path.get(path.rstrip("/") or "/", set())
            rank = (
                0 if set(segments) & {"login", "signin", "sign-in", "sign_in"} else 1,
                0 if request_format_evidence else 1,
                0 if status in {200, 201, 202, 400, 401, 403} else 1,
            )
            candidates.append(
                {
                    "method": method,
                    "path": path,
                    "discovery_status": status,
                    "response_content_type": response_content_type,
                    "evidence_source": source_names or ["discovery"],
                    "evidence": evidence_snippets,
                    "request_body_fields": request_body_fields,
                    "request_content_type": request_content_type,
                    "request_content_type_evidence": endpoint.get(
                        "request_content_type_evidence"
                    ),
                    "request_format_evidence": request_format_evidence,
                    "allow_header_methods": sorted(path_allow_methods),
                    "_rank": rank,
                    "_index": index,
                }
            )

        candidates.sort(
            key=lambda candidate: (*candidate["_rank"], candidate["_index"])
        )
        for candidate in candidates:
            candidate.pop("_rank", None)
            candidate.pop("_index", None)
        logger.info(
            "Login candidate selection | inventory_records=%d | candidates=%d | "
            "excluded_auth_routes=%d | allow_method_observations=%d",
            len(discovered_endpoints or []),
            len(candidates),
            len(exclusions),
            method_evidence_count,
        )
        for method, path, reason in exclusions:
            logger.info(
                "Login candidate excluded | method=%s | route=%s | reason=%s",
                method,
                path,
                reason,
            )
        for candidate in candidates:
            logger.info(
                "Login candidate retained | method=%s | route=%s | source=%s | "
                "request_contract=%s",
                candidate["method"],
                candidate["path"],
                ",".join(candidate.get("evidence_source", [])),
                candidate.get("request_format_evidence", False),
            )
        return candidates
