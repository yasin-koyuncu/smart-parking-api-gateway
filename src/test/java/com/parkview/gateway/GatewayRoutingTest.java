package com.parkview.gateway;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.GenericContainer;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Black-box tests of the running gateway: real routes from application.yml, real security chain, real
 * Redis rate limiter (Testcontainers); a MockWebServer plays every downstream service.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@AutoConfigureObservability
class GatewayRoutingTest {

    private static final MockWebServer UPSTREAM = new MockWebServer();
    private static final ECKey SIGNING_KEY = generateKey();
    private static final BlockingQueue<RecordedRequest> RECORDED = new LinkedBlockingQueue<>();

    /** TEST_REDIS_HOST[:PORT] points at an existing Redis (e.g. a sibling container); otherwise Testcontainers starts one. */
    private static final String EXTERNAL_REDIS = System.getenv("TEST_REDIS_HOST");
    private static final GenericContainer<?> REDIS = EXTERNAL_REDIS != null ? null
            : new GenericContainer<>("redis:7").withExposedPorts(6379);

    static {
        if (REDIS != null) {
            REDIS.start();
        }
    }

    @Autowired
    WebTestClient client;

    private static ECKey generateKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("test-key").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String token(String role, String subject, String issuer, String audience, Instant expiresAt, ECKey key) {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer).subject(subject).audience(audience)
                    .issueTime(Date.from(Instant.now().minusSeconds(5))).expirationTime(Date.from(expiresAt))
                    .claim("app_metadata", Map.of("role", role)).build();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String validToken(String role, String subject) {
        return token(role, subject, "http://issuer.test/auth/v1", "authenticated", Instant.now().plusSeconds(300), SIGNING_KEY);
    }

    @BeforeAll
    static void startUpstream() throws IOException {
        UPSTREAM.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if ("/jwks".equals(request.getPath())) {
                    return new MockResponse().setHeader("Content-Type", "application/json").setBody(new JWKSet(SIGNING_KEY.toPublicJWK()).toString());
                }
                RECORDED.add(request);
                return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody("{\"ok\":true}");
            }
        });
        UPSTREAM.start();
    }

    @AfterAll
    static void stopUpstream() throws IOException {
        UPSTREAM.shutdown();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        String upstream = "http://localhost:" + UPSTREAM.getPort();
        registry.add("parkview.security.issuer", () -> "http://issuer.test/auth/v1");
        registry.add("parkview.security.jwks-uri", () -> upstream + "/jwks");
        registry.add("parkview.security.internal-api-key", () -> "test-internal-key");
        registry.add("spring.data.redis.host", () -> REDIS != null ? REDIS.getHost() : EXTERNAL_REDIS);
        registry.add("spring.data.redis.port", () -> REDIS != null ? REDIS.getMappedPort(6379) : 6379);
        registry.add("management.health.redis.enabled", () -> "false");
        for (String name : new String[]{"AUTH_SERVICE_URL", "RULE_ENGINE_URL", "SESSION_SERVICE_URL", "PARKING_MAPPING_URL",
                "EVENT_STREAMING_URL", "INGESTION_SERVICE_URL", "FILE_SERVICE_URL", "NOTIFICATION_SERVICE_URL",
                "PAYMENT_SERVICE_URL", "AI_SERVICE_URL"}) {
            registry.add(name, () -> upstream);
        }
        registry.add("LOOKUP_SERVICE_URL", () -> "http://localhost:1");   // nothing listens: simulates a dead service
        registry.add("INTERNAL_API_KEY", () -> "test-internal-key");
    }

    @BeforeEach
    void clearRecorded() {
        RECORDED.clear();
    }

    private WebTestClient as(String role, String subject) {
        return client.mutateWith(SecurityMockServerConfigurers.mockJwt()
                .jwt(j -> j.subject(subject).claim("app_metadata", Map.of("role", role)))
                .authorities(AuthorityUtils.createAuthorityList(
                        "admin".equals(role) ? new String[]{"ROLE_ADMIN", "ROLE_OPERATOR"} : new String[]{"ROLE_" + role.toUpperCase()})));
    }

    private RecordedRequest upstreamRequest() throws InterruptedException {
        RecordedRequest request = RECORDED.poll(5, TimeUnit.SECONDS);
        assertThat(request).as("upstream received a request").isNotNull();
        return request;
    }

    // ── authentication & identity ────────────────────────────────────────────────

    @Test
    void protectedRouteWithoutTokenIsProblemJson401() {
        client.get().uri("/api/v1/sessions/plate/ABC123").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody().jsonPath("$.status").isEqualTo(401).jsonPath("$.requestId").exists();
    }

    @Test
    void clientCannotSpoofIdentityHeadersOnPublicRoutes() throws Exception {
        client.post().uri("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .header("X-User-Id", "attacker").header("X-User-Role", "admin").header("X-Internal-Api-Key", "stolen")
                .bodyValue("{\"email\":\"a@b.se\",\"password\":\"x\"}")
                .exchange().expectStatus().isOk();

        RecordedRequest upstream = upstreamRequest();
        assertThat(upstream.getHeader("X-User-Id")).isNull();
        assertThat(upstream.getHeader("X-User-Role")).isNull();
        assertThat(upstream.getHeader("X-Internal-Api-Key")).isNull();
    }

    @Test
    void authenticatedRequestReachesUpstreamExactlyOnceWithIdentityHeaders() throws Exception {
        as("operator", "op-1").get().uri("/api/v1/sessions/zone/z1").exchange().expectStatus().isOk();

        RecordedRequest upstream = upstreamRequest();
        assertThat(upstream.getHeader("X-User-Id")).isEqualTo("op-1");
        assertThat(upstream.getHeader("X-User-Role")).isEqualTo("operator");
        assertThat(upstream.getHeader("X-Request-Id")).isNotBlank();
        // regression: AuthForwardFilter once ran the filter chain twice for authenticated calls
        assertThat(RECORDED.poll(300, TimeUnit.MILLISECONDS)).as("no duplicate upstream call").isNull();
    }

    @Test
    void requestIdIsEchoedWhenSafeAndReplacedWhenNot() {
        client.get().uri("/actuator/health").header("X-Request-Id", "trace-123").exchange()
                .expectHeader().valueEquals("X-Request-Id", "trace-123");
        client.get().uri("/actuator/health").header("X-Request-Id", "bad id <script>").exchange()
                .expectHeader().value("X-Request-Id", id -> assertThat(id).doesNotContain("<").hasSize(36));
    }

    // ── authorisation rules ─────────────────────────────────────────────────────

    @Test
    void driverIsKeptOutOfOperatorRoutesButMayReadOwnPlateRoutes() {
        as("driver", "d-1").get().uri("/api/v1/sessions/zone/z1").exchange().expectStatus().isForbidden();
        as("driver", "d-1").patch().uri("/api/v1/sessions/" + java.util.UUID.randomUUID() + "/pay").exchange().expectStatus().isForbidden();
        as("driver", "d-1").post().uri("/api/v1/sessions/start").contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().isForbidden();
        as("driver", "d-1").get().uri("/api/v1/sessions/plate/ABC123").exchange().expectStatus().isOk();
        as("driver", "d-1").get().uri("/api/v1/lookup/plate/ABC123").exchange().expectStatus().isForbidden();
    }

    @Test
    void operatorMayMarkSessionsPaidButZoneWritesNeedAdmin() {
        as("operator", "op-1").patch().uri("/api/v1/sessions/" + java.util.UUID.randomUUID() + "/pay").exchange().expectStatus().isOk();
        as("operator", "op-1").post().uri("/api/v1/zones").contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().isForbidden();
        as("admin", "ad-1").post().uri("/api/v1/zones").contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().isOk();
        as("admin", "ad-1").get().uri("/api/v1/sessions/zone/z1").exchange().expectStatus().isOk();   // ADMIN implies OPERATOR
    }

    @Test
    void zonesAreRoutedToTheMappingService() throws Exception {
        as("driver", "d-1").get().uri("/api/v1/zones/nearest?lng=1&lat=2&radius=300").exchange().expectStatus().isOk();
        assertThat(upstreamRequest().getPath()).startsWith("/api/v1/zones/nearest");
    }

    @Test
    void cameraDeviceEndpointsArePublicAndRewritten() throws Exception {
        client.post().uri("/api/v1/cameras/ingest").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"camera_id\":\"c\",\"api_key\":\"k\",\"plate\":\"ABC123\"}").exchange().expectStatus().isOk();
        assertThat(upstreamRequest().getPath()).isEqualTo("/cameras/ingest");
        client.get().uri("/api/v1/cameras/admin/snapshot-url").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void aiRouteAddsTheServiceKeyAndIgnoresAClientProvidedOne() throws Exception {
        as("operator", "op-1").post().uri("/api/v1/ai/anpr/read").header("X-Internal-Api-Key", "client-guess")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().isOk();
        RecordedRequest upstream = upstreamRequest();
        assertThat(upstream.getPath()).isEqualTo("/anpr/read");
        assertThat(upstream.getHeaders().values("X-Internal-Api-Key")).containsExactly("test-internal-key");
    }

    // ── real JWT validation at the edge ──────────────────────────────────────────

    @Test
    void aValidEs256TokenIsAcceptedAndMapsToTheRole() throws Exception {
        client.get().uri("/api/v1/sessions/zone/z1").header("Authorization", "Bearer " + validToken("operator", "op-9"))
                .exchange().expectStatus().isOk();
        assertThat(upstreamRequest().getHeader("X-User-Id")).isEqualTo("op-9");
        client.get().uri("/api/v1/sessions/zone/z1").header("Authorization", "Bearer " + validToken("driver", "d-9"))
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void tokensWithWrongIssuerAudienceExpiryKeyOrAlgorithmAreRejected() throws Exception {
        ECKey other = new ECKeyGenerator(Curve.P_256).keyID("test-key").generate();   // same kid, different key
        String[] bad = {
                token("admin", "x", "http://evil.test/auth/v1", "authenticated", Instant.now().plusSeconds(300), SIGNING_KEY),
                token("admin", "x", "http://issuer.test/auth/v1", "other-audience", Instant.now().plusSeconds(300), SIGNING_KEY),
                token("admin", "x", "http://issuer.test/auth/v1", "authenticated", Instant.now().minusSeconds(3600), SIGNING_KEY),
                token("admin", "x", "http://issuer.test/auth/v1", "authenticated", Instant.now().plusSeconds(300), other),
                hs256Token(),
                "not-a-jwt"
        };
        for (String token : bad) {
            client.get().uri("/api/v1/sessions/zone/z1").header("Authorization", "Bearer " + token)
                    .exchange().expectStatus().isUnauthorized();
        }
        assertThat(RECORDED).as("rejected tokens never reach a service").isEmpty();
    }

    private static String hs256Token() throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
                .issuer("http://issuer.test/auth/v1").audience("authenticated").subject("x")
                .expirationTime(Date.from(Instant.now().plusSeconds(300))).claim("app_metadata", Map.of("role", "admin")).build());
        jwt.sign(new MACSigner("0123456789abcdef0123456789abcdef"));
        return jwt.serialize();
    }

    // ── SSE token ───────────────────────────────────────────────────────────────

    @Test
    void sseTokenInTheQueryAuthenticatesAndIsMovedIntoTheAuthorizationHeader() throws Exception {
        String token = validToken("operator", "op-1");
        client.get().uri("/api/v1/events/stream/operator?zoneId=z1&token=" + token).exchange().expectStatus().isOk();
        RecordedRequest upstream = upstreamRequest();
        assertThat(upstream.getPath()).isEqualTo("/api/v1/events/stream/operator?zoneId=z1");
        assertThat(upstream.getHeader("Authorization")).isEqualTo("Bearer " + token);
    }

    @Test
    void aTokenInTheQueryIsIgnoredOutsideTheSseEndpoints() {
        client.get().uri("/api/v1/sessions/zone/z1?token=" + validToken("operator", "op-1")).exchange().expectStatus().isUnauthorized();
    }

    // ── CORS, headers, limits ───────────────────────────────────────────────────

    @Test
    void responsesCarrySecurityHeaders() {
        client.get().uri("/actuator/health").exchange()
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().exists("Content-Security-Policy")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer");
    }

    @Test
    void oversizedBodyOnCredentialEndpointIsRejected() {
        String big = "x".repeat(40_000);
        client.post().uri("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"" + big + "\"}").exchange()
                .expectStatus().isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
    }

    @Test
    void credentialEndpointsAreRateLimitedPerClient() {
        int tooMany = 0;
        for (int i = 0; i < 12; i++) {
            var result = client.post().uri("/api/v1/auth/login").header("X-Forwarded-For", "203.0.113.7")
                    .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"email\":\"a@b.se\",\"password\":\"x\"}")
                    .exchange().returnResult(String.class);
            if (result.getStatus().value() == 429) {
                tooMany++;
            }
        }
        assertThat(tooMany).as("requests beyond the burst of 5 are throttled").isGreaterThan(0);
    }

    // ── operability ─────────────────────────────────────────────────────────────

    @Test
    void healthIsPublicButMetricsNeedTheInternalKey() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk();
        client.get().uri("/actuator/prometheus").exchange().expectStatus().isUnauthorized();
        client.get().uri("/actuator/prometheus").header("X-Internal-Api-Key", "wrong").exchange().expectStatus().isUnauthorized();
        client.get().uri("/actuator/prometheus").header(HttpHeaders.ACCEPT, "text/plain").header("X-Internal-Api-Key", "test-internal-key")
                .exchange().expectStatus().isOk();
        as("admin", "ad-1").get().uri("/actuator/env").exchange().expectStatus().isForbidden();
    }

    @Test
    void unknownRouteAndDeadUpstreamProduceProblemJsonWithoutLeakingDetails() {
        as("operator", "op-1").get().uri("/api/v1/nope").exchange()
                .expectStatus().isNotFound()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON);

        as("operator", "op-1").get().uri("/api/v1/lookup/plate/ABC123").exchange()
                .expectStatus().is5xxServerError()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody(String.class).value(body -> assertThat(body).doesNotContain("localhost").doesNotContain("Exception"));
    }
}
