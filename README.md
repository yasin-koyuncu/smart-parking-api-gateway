# api-gateway

Single entry point of the Park & View platform (Spring Cloud Gateway, WebFlux, Java 24).
Browsers, drivers and cameras talk only to this service; everything behind it is internal.

```
Browser / camera --HTTPS--> api-gateway --> session | rule | mapping | payment | notification | lookup | file | auth | ingestion | ai | event-streaming
                              |
                              +-- validates the Supabase JWT (ES256, JWKS, issuer + audience)
                              +-- CORS (answered before authorisation), request id, rate limits, size limits, timeouts
                              +-- strips identity headers a client could spoof, adds the service key on the AI route
```

The services validate the JWT again and enforce object ownership (their own zones / plates); the gateway keeps
unauthorised traffic away from them and gives every error the same shape.

## Routing table

| Path prefix | Service | Notes |
|---|---|---|
| `/api/v1/auth/**` | authentication-service | `login`, `register`, `reset-password`: 1 req/s per IP (burst 5), 16 KB bodies |
| `/api/v1/access/**` | authentication-service | roles, grants and audit log (ADR 0002); `access:read` / `access:manage`, `GET /access/me/**` for any signed-in user |
| `/api/v1/violations/**`, `/api/v1/permits/**` | rule-service | |
| `/api/v1/sessions/**` | session-service | |
| `/api/v1/mapping/**`, `/api/v1/zones/**` | parking-mapping-service | spot writes: `spot:write`, zone writes: `zone:write` |
| `/api/v1/events/**` | event-streaming | SSE, no response timeout, `?token=` allowed on `/stream/**` only |
| `/api/v1/cameras/**` | ingestion-service | rewritten to `/cameras/**`; `ingest` and `heartbeat` are public (camera api key), 12 MB bodies |
| `/api/v1/files/**` | file-service | 22 MB bodies |
| `/api/v1/notifications/**`, `/api/v1/lookup/**`, `/api/v1/payments/**` | notification / lookup / payment | `payments/webhook` is public (Stripe signature) |
| `/api/v1/ai/**` | ai-detection-service | rewritten to `/**`, needs `ai:use`, gateway adds `X-Internal-Api-Key` |

GET requests to read-only services are retried twice on 502/503/504. Upstream calls time out after 15 s
(connect 2 s). Failures are returned as `application/problem+json` without internal details.

## Authorisation rules

Declared in `application.yml` under `parkview.gateway.rules` (first match wins, default: authenticated):

| Access | Meaning |
|---|---|
| `PUBLIC` | no token needed |
| `AUTHENTICATED` | any valid token |
| `PERMISSION` | the token holds the authority named in the rule's `permission` field (e.g. `permission: "zone:write"`) |
| `OPERATOR` | `app_metadata.role` = operator or admin (kept for rules that really mean "a role"; no shipped rule uses it) |
| `ADMIN` | `app_metadata.role` = admin |

The operator and admin functions are guarded by permissions, one per function (`/ai/**` `ai:use`, `/cameras/admin/**` `camera:admin`,
`/lookup/**` `lookup:vehicle`, `/permits/**` `permit:manage`, `sessions/zone/**` `session:read`, session start and pay `session:manage`,
`violations/zone/**` `violation:read`, `violations/*/resolve` `violation:resolve`, `events/status` and `events/stream/operator`
`stream:operator`, mapping writes `spot:write`, zone writes `zone:write`, `/access/**` `access:read` for GET and `access:manage` for the rest).
`permission` is only valid with `access: PERMISSION` and must be in the catalogue (`Permissions`, mirrors
`smart-parking-e2e/contracts/permissions.json`): a misspelt or unknown name **fails the startup** instead of guarding nothing.

Claims (written by the Supabase access-token hook, ADR 0002):

* `app_metadata.role` (`admin` \| `operator` \| `driver`) becomes `ROLE_*`; ADMIN implies OPERATOR.
* `app_metadata.permissions` (string[]) becomes one authority per entry, named exactly like the permission. Names are matched exactly (no prefix, case folding or wildcards).
* `parkview.security.legacy-role-fallback` (`LEGACY_ROLE_FALLBACK`, default `true`): a token **without** a `permissions` claim gets the default permissions of its role
  (`defaultsByRole` in the contract), so tokens minted before the rollout keep working. A token that has the claim, even `[]`, is never supplemented:
  an admin whose permissions were all revoked has none. Set it to `false` once all tokens carry the claim.

## Security behaviour worth knowing

* Tokens are verified with ES256 against `<SUPABASE_URL>/auth/v1/.well-known/jwks.json`; issuer and `aud=authenticated` are checked.
* `X-User-Id`, `X-User-Role`, `X-User-Email`, `X-Internal-Api-Key` sent by a client are removed. `X-User-Id`/`X-User-Role` are then set from the verified JWT as a convenience for the services (they must not use them for authorisation).
* CORS is part of the security chain, so preflight requests work without a token. Allowed origins: `FRONTEND_URL` (comma separated). No credentials/cookies.
* `?token=` is honoured only on `parkview.gateway.sse-token-paths`; it is moved into the `Authorization` header and removed from the URL before proxying.
* The access log records route id, status, duration and user id - never paths or query strings (they carry plates and tokens).
* `/actuator/health` and `/actuator/info` are public; `/actuator/prometheus` requires the internal API key; everything else is denied.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | 8080 | listen port |
| `SUPABASE_URL` | - (required) | Supabase project URL; issuer is `<url>/auth/v1` |
| `SUPABASE_AUDIENCE` | `authenticated` | required `aud` claim |
| `INTERNAL_API_KEY` | empty | shared secret for metrics and the AI route; empty disables both |
| `FRONTEND_URL` | `http://localhost:5173` | CORS origin(s) |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` | rate limiter (fails open when Redis is down) |
| `*_SERVICE_URL` etc. | `http://localhost:<port>` | downstream base URLs: `AUTH_SERVICE_URL`, `RULE_ENGINE_URL`, `SESSION_SERVICE_URL`, `PARKING_MAPPING_URL`, `EVENT_STREAMING_URL`, `INGESTION_SERVICE_URL`, `FILE_SERVICE_URL`, `NOTIFICATION_SERVICE_URL`, `LOOKUP_SERVICE_URL`, `PAYMENT_SERVICE_URL`, `AI_SERVICE_URL` |
| `LEGACY_ROLE_FALLBACK` | `true` | derive permissions from the role for tokens without `app_metadata.permissions` (`parkview.security.legacy-role-fallback`) |
| `DOCS_ENABLED` | `false` | aggregated Swagger UI at `/swagger-ui.html` (each service must have `DOCS_ENABLED=true` too). Never in production |

## Run, test, build

```bash
mvn -B -ntp verify            # needs JDK 24 and Docker (Testcontainers starts Redis)
docker build -t api-gateway .
```

`AuthorizationMatrixTest` runs the real rules and converter on a mock server (no sockets, no Docker) and covers permission-only tokens, the role fallback and the fail-closed cases.
Integration tests start the real gateway, use a MockWebServer as every downstream service and serve a JWKS
for genuine ES256 token validation. On a machine where Netty cannot open selectors (some Windows setups report
"Unable to establish loopback connection") run them in a container next to a Redis container:
`docker run --rm --network <net> -e TEST_REDIS_HOST=<redis> -v "$PWD":/src -w /src maven:3.9-eclipse-temurin-24 mvn -B -ntp test`.

## Operations

Health: `/actuator/health/liveness`, `/actuator/health/readiness`. Metrics: `/actuator/prometheus` (internal key).
Every response carries `X-Request-Id`; the same id is forwarded to the services and appears in their logs.
