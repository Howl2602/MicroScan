# MicroScan
A tool which I'm developing for my Thesis

## Authentication checks

The existing `GET /scan?target=...` API and Kiterunner discovery flow are retained. MicroScan selects only a discovered, safe-looking `GET` route for unauthenticated probes; it prefers current-user/self-profile routes and resource-ID routes, and excludes login, templated, and administrative/system/debug/health/metrics paths. It records the selected endpoint and Kiterunner status as discovery evidence, not proof that the route is protected. When no suitable discovered route exists, the authentication test is `skipped` with a reason.

Without any login configuration, MicroScan still sends requests without credentials and with an invalid bearer value. Responses that do not establish the route's expected policy are `inconclusive`; 401/403 responses alone do not establish that the API's complete authentication implementation is secure. A response containing structured data without credentials is reported as `potential`, since the route could intentionally be public.

Login/token endpoints are identified only from discovered `POST` routes that resemble authentication or token endpoints. Discovery does not reveal a request schema, so MicroScan never guesses a login body, creates accounts, or submits credentials automatically. To enable optional authenticated coverage, provide the documented lab credentials or payload. MicroScan loads `.env` from the repository root using `python-dotenv`; values already set in the operating-system environment take precedence. The root `.env` is ignored by Git; use `.env.example` as a template:

- `MICROSHIELD_USERNAME` and `MICROSHIELD_PASSWORD`: build the lab's documented `username` / `password` JSON payload when both values are present.
- `MICROSCAN_LOGIN_ENDPOINT`: optional path or same-origin absolute URL; otherwise the first discovered login candidate is used.
- `MICROSCAN_LOGIN_PAYLOAD`: optional legacy JSON payload object, used instead of the username/password pair when present.
- `MICROSCAN_AUTH_CONFIG`: JSON object with a `payload` object, and optional `login_endpoint`, `content_type`, `method` (`POST` only), `token_field`, `auth_header`, and `auth_scheme`.
- `MICROSCAN_PROTECTED_ENDPOINT`: optional path override; otherwise the test uses an actually discovered suitable `GET` route. `MICROSCAN_PROTECTED_METHOD` is not used; only `GET` probes are supported.

The payload must match the lab's real contract. MicroScan extracts a token only from supported response fields or the configured `token_field`; it sends a valid-token probe only after login actually succeeds. The authorization scheme is taken from configuration, the login response, or an observed challenge. If none is present but the returned token has the standard three-part JWT shape, MicroScan makes a best-effort `Bearer` request and labels that scheme as inferred rather than observed. Other token formats require an explicit or observed scheme. Secrets and raw response values are not included in reports. `potential`, `not_vulnerable_in_test`, `inconclusive`, `skipped`, and `error` describe only the evidence and coverage from this particular test.

Install backend dependencies from the repository root with `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`. Copy `.env.example` to `.env` and replace the placeholders with authorized lab credentials (or set the environment variables in your shell). Do not commit `.env` or put credentials in reports:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
# Edit .env with the authorized lab values before starting the backend.
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

To run basic unauthenticated checks, leave the authentication variables unset. Start the frontend in a separate shell with `cd frontend` and `npm run dev`, then enter the authorized target origin on the Scan page. Unit tests use mocked HTTP responses; they do not establish the behavior or vulnerability status of a live lab.
