import re
from urllib.parse import urlsplit


class EndpointSelector:
    TEST_MODULE = "jwt_authentication"
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

        applicable_tests = (
            [self.TEST_MODULE] if classification == "authentication" else []
        )
        return {
            "classification": classification,
            "reason": "; ".join(reason_parts),
            "applicable_tests": applicable_tests,
        }

    @staticmethod
    def discovery_status(endpoint):
        responses = endpoint.get("responses")
        if not isinstance(responses, list):
            return None
        for response in responses:
            if isinstance(response, dict):
                status = response.get("sc") or response.get("status_code")
                if isinstance(status, int):
                    return status
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
        candidates = []
        for index, endpoint in enumerate(discovered_endpoints or []):
            if not isinstance(endpoint, dict):
                continue
            method = str(endpoint.get("method") or "").upper()
            path = endpoint.get("path")
            if method != "POST" or not isinstance(path, str) or not path.startswith("/"):
                continue
            parsed = urlsplit(path)
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
                continue
            if not cls.is_authentication_path(path):
                continue
            if any(
                segment in cls.REGISTRATION_PATH_SEGMENTS
                for segment in cls._path_segments(path)
            ):
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
            candidates.append(
                {
                    "method": method,
                    "path": path,
                    "discovery_status": status,
                    "response_content_type": response_content_type,
                    "_index": index,
                }
            )

        candidates.sort(
            key=lambda candidate: (
                0 if candidate["discovery_status"] in {200, 201, 202} else 1,
                candidate["_index"],
            )
        )
        for candidate in candidates:
            candidate.pop("_index", None)
        return candidates
