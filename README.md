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

## Structure

Code layout (`com.parkview.gateway`):

* `config`: `SecurityConfig` (chain: CORS, headers, problem+json errors, actuator rules), `JwtDecoderConfig` (ES256/JWKS decoder with issuer and audience), `CorsConfig`, `RedisConfig`, `DocsRoutesConfig` and the `@ConfigurationProperties` records.
* `security`: `RuleAuthorizer` (applies `parkview.gateway.rules`), `AudienceValidator`, `ParkviewJwtConverter` (claims to authorities), `Permissions` (catalogue), `SseTokenPaths` + `SseTokenBearerConverter` (`?token=` on SSE paths), `RoleHeader` (value of `X-User-Role`).
* `filter`: global route filters (`SseTokenForwardFilter` -2, `AuthForwardFilter` -1, `AccessLogFilter`).
* `web`: edge headers, error handler, problem+json writer.

## Routing table

| Path prefix | Service | Notes |
|---|---|---|
| `/api/v1/auth/**` | authentication-service | `login`, `register`, `reset-password`: 1 req/s per IP (burst 5), 16 KB bodies |
| `/api/v1/access/**` | authentication-service | roles, grants and audit log (ADR 0002); `access:read` / `access:manage`, `GET /access/me/**` for any signed-in user |
| `/api/v1/users/**` | authentication-service | profile of the signed-in user (any role, the service uses the token subject) |
| `/api/v1/violations/**`, `/api/v1/permits/**`, `/api/v1/fines/**`, `/api/v1/disputes/**` | rule-service | fines: any signed-in user, the service decides on ownership and zones; `GET fines/*/evidence` `violation:read`; disputes: `POST fines/*/dispute`, `GET fines/*/dispute`, `GET fines/*/explanation` and `POST disputes/*/withdraw` any signed-in user (the service decides on ownership), the review queue and the decision (`GET /disputes`, `POST disputes/*/decision`) `fine:manage` |
| `/api/v1/sessions/**` | session-service | |
| `/api/v1/mapping/**`, `/api/v1/zones/**` | parking-mapping-service | spot writes: `spot:write`, zone writes: `zone:write`, map history (`zones/*/versions`, `zones/*/changes`, `spots/*/changes`): `mapping:view`; parking areas and camera views (`GET mapping/areas/**`, `GET mapping/views/**`, `GET mapping/cameras/*/views`): `mapping:view`, their writes (every non-GET method under `mapping/**`) `spot:write` |
| `/api/v1/events/**` | event-streaming | SSE, no response timeout, `?token=` allowed on `/stream/**` only |
| `/api/v1/cameras/**` | ingestion-service | rewritten to `/cameras/**` (the bare `/api/v1/cameras` list becomes `/cameras`); `ingest` and `heartbeat` are public (camera api key), `GET /cameras` any signed-in user (the service wants `camera:admin` or `stream:operator` + zone scope), `POST cameras/*/capture` `ai:use`, `POST cameras/*/calibration/scan` `camera:admin` at the edge (the service wants `camera:admin` **and** `ai:use`) with its own route, `GET cameras/*/ptz/presets` `camera:admin`, 12 MB bodies (64 KB on the scan) |
| `/api/v1/detections/**` | ingestion-service | rewritten to `/detections/**` (bare path too), 64 KB bodies, 10 req/s per IP; `GET` `violation:read`, `PATCH detections/*/review` `violation:resolve` |
| `/api/v1/files/**` | file-service | 22 MB bodies; uploads `file:upload`, `GET snapshots/**` `file:view`, `GET evidence/*/url` any signed-in user (owners need it, the service wants `file:view` of staff) |
| `/api/v1/notifications/**`, `/api/v1/lookup/**`, `/api/v1/payments/**` | notification / lookup / payment | `payments/webhook` is public (Stripe signature); everything under `notifications/**` (list, read, read-all, push-subscription, test-push) needs a valid token, the service scopes it to the token subject |
| `/api/v1/ai/**` | ai-detection-service | rewritten to `/**`, needs `ai:use`, gateway adds `X-Internal-Api-Key` |

GET requests to read-only services are retried twice on 502/503/504. Upstream calls time out after 15 s
(connect 2 s), except the stream of `/api/v1/events/**` (no timeout) and `POST /api/v1/cameras/*/calibration/scan`, which has
its own route (`ingestion-calibration-scan`, declared before `ingestion-service`, never retried) with a response timeout of
60 s: the scan moves a PTZ camera, takes a picture and has it analysed, which takes seconds. The longer timeout is route
metadata (`response-timeout`, in milliseconds), so it applies to that path only. Failures are returned as `application/problem+json` without internal details.

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
`GET sessions/search` and `GET sessions/*/history` `session:read`, `POST sessions/*/end`, `POST sessions/*/void` and `PATCH sessions/*` (one segment, so not `.../pay`) `session:correct`,
`POST fines/*/void` and `POST fines/*/mark-paid` `fine:manage`, `GET fines/*/history` and `GET fines/*/evidence` (frozen evidence incl. camera snapshots) `violation:read`,
`GET /disputes` and `/disputes/**` (review queue, decision) `fine:manage` (listed after `POST disputes/*/withdraw`, which any signed-in user may call: rule-service checks that the dispute is the caller's),
`violations/zone/**` `violation:read`, `violations/*/resolve` `violation:resolve`, `events/status` and `events/stream/operator`
`stream:operator`, mapping writes `spot:write`, zone writes `zone:write`, map history GETs `mapping:view`, evidence and snapshot uploads `file:upload`, snapshot GETs `file:view`,
`POST cameras/*/capture` `ai:use` (listed after `cameras/admin/**`, so a camera id `admin` stays under `camera:admin`), `POST cameras/*/calibration/scan` and `GET cameras/*/ptz/presets` `camera:admin` (a rule names one permission, so the scan, which ingestion-service restricts to `camera:admin` **and** `ai:use`, is checked for `camera:admin` here and for both there), `GET mapping/areas/**`, `GET mapping/views/**` and `GET mapping/cameras/*/views` `mapping:view` (staff read parking areas and camera views with their pictures; drivers do not; the writes are the `spot:write` rule for `mapping/**`), `GET detections` and `GET detections/**` `violation:read`, `PATCH detections/*/review` `violation:resolve`,
`/access/**` `access:read` for GET and `access:manage` for the rest). Deliberately **not** gated here, because one gateway permission cannot express them: `GET /files/evidence/*/url`
(owner of the fine, or staff with `file:view`, decided by file-service), `POST /zones/check-overlap` (service accepts `mapping:view`, `zone:write` or `spot:write`, so it is a plain
authenticated rule ahead of the zone-write rule), the other mapping GETs (drivers read zones and spots), the rest of `/fines/**` (incl. `GET fines/*/explanation` and `GET`/`POST fines/*/dispute`, which drivers use for their own fines; rule-service answers 404 for fines the caller may not see) and `/users/**` incl. `/users/me/plates` (any valid token, the services check ownership), `GET /cameras` and `/notifications/**` (any valid token, the services decide).
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

## Tracing

Distributed tracing (OpenTelemetry through Micrometer Tracing, W3C `traceparent`) is **off by default**: while
`TRACING_ENABLED` is unset there is no tracer, no exporter, no trace header and no connection attempt, and the
service behaves exactly as before. It is switched on by environment variables alone:

| Variable | Default | Description |
|---|---|---|
| `TRACING_ENABLED` | `false` | The single switch (`management.tracing.enabled`) |
| `TRACING_SAMPLING` | `0.1` | Share of new traces recorded (`0` to `1`); a caller's sampled trace is always continued |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4318` | OTLP/HTTP collector, spans go to `<endpoint>/v1/traces`; `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` takes a full URL |
| `OTEL_SERVICE_NAME` | `api-gateway` | Service name on the spans (default: `spring.application.name`) |
| `TRACING_TRUST_INCOMING` | `false` | `true` keeps the `traceparent` a caller sent (only behind a trusted tracing proxy); by default the gateway drops it and starts every trace itself |

Traced: every incoming request (a server span), and each proxied call to a downstream service (a client span whose
`traceparent` the service continues). The caller's own `traceparent`/`tracestate`/`baggage` headers are dropped at this
edge unless `TRACING_TRUST_INCOMING=true`, so nobody outside can join or force-sample the platform's traces. While tracing is on,
Reactor context propagation is enabled (the same as `spring.reactor.context-propagation=auto`) so the trace reaches
the filters and the log MDC.

Not traced: `/actuator/**` (probes and scrapes are dropped before export). Spans never carry request or response
bodies or tokens, and the raw URL (paths and queries hold plates and, on the stream, tokens) is removed before
export: only the route template, method and status are recorded. `requestId` in the log pattern is unchanged; with
tracing on Boot adds `[traceId-spanId]` to every log line.

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
