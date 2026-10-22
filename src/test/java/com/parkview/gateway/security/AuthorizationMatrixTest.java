package com.parkview.gateway.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Authorisation matrix of the shipped rules ({@code application.yml}) against permission-only tokens, the legacy
 * role fallback and the fail-closed cases. Runs on a mock server (no sockets), so it also works where Netty
 * cannot open a loopback connection.
 */
@SpringBootTest(classes = AuthorizationTestApp.class, properties = "SUPABASE_URL=http://issuer.test")
class AuthorizationMatrixTest {

    /** method, path, permission that guards it (see parkview.gateway.rules). */
    record Guarded(HttpMethod method, String path, String permission) {
        @Override
        public String toString() {
            return method + " " + path + " -> " + permission;
        }
    }

    static Stream<Guarded> guarded() {
        return Stream.of(
                new Guarded(HttpMethod.POST, "/api/v1/ai/anpr/read", "ai:use"),
                new Guarded(HttpMethod.GET, "/api/v1/cameras/admin/snapshot-url", "camera:admin"),
                new Guarded(HttpMethod.POST, "/api/v1/cameras/c1/capture", "ai:use"),
                new Guarded(HttpMethod.POST, "/api/v1/cameras/c1/calibration/scan", "camera:admin"),
                new Guarded(HttpMethod.GET, "/api/v1/cameras/c1/ptz/presets", "camera:admin"),
                new Guarded(HttpMethod.GET, "/api/v1/detections", "violation:read"),
                new Guarded(HttpMethod.GET, "/api/v1/detections/d1", "violation:read"),
                new Guarded(HttpMethod.PATCH, "/api/v1/detections/d1/review", "violation:resolve"),
                new Guarded(HttpMethod.GET, "/api/v1/lookup/plate/ABC123", "lookup:vehicle"),
                new Guarded(HttpMethod.POST, "/api/v1/permits", "permit:manage"),
                new Guarded(HttpMethod.DELETE, "/api/v1/permits/1", "permit:manage"),
                new Guarded(HttpMethod.GET, "/api/v1/sessions/zone/z1", "session:read"),
                new Guarded(HttpMethod.POST, "/api/v1/sessions/start", "session:manage"),
                new Guarded(HttpMethod.PATCH, "/api/v1/sessions/7/pay", "session:manage"),
                new Guarded(HttpMethod.GET, "/api/v1/sessions/search", "session:read"),
                new Guarded(HttpMethod.GET, "/api/v1/sessions/7/history", "session:read"),
                new Guarded(HttpMethod.POST, "/api/v1/sessions/7/end", "session:correct"),
                new Guarded(HttpMethod.POST, "/api/v1/sessions/7/void", "session:correct"),
                new Guarded(HttpMethod.PATCH, "/api/v1/sessions/7", "session:correct"),
                new Guarded(HttpMethod.GET, "/api/v1/violations/zone/z1", "violation:read"),
                new Guarded(HttpMethod.POST, "/api/v1/fines/f1/void", "fine:manage"),
                new Guarded(HttpMethod.POST, "/api/v1/fines/f1/mark-paid", "fine:manage"),
                new Guarded(HttpMethod.GET, "/api/v1/fines/f1/history", "violation:read"),
                new Guarded(HttpMethod.GET, "/api/v1/fines/f1/evidence", "violation:read"),
                new Guarded(HttpMethod.GET, "/api/v1/disputes", "fine:manage"),
                new Guarded(HttpMethod.GET, "/api/v1/disputes/d1", "fine:manage"),
                new Guarded(HttpMethod.POST, "/api/v1/disputes/d1/decision", "fine:manage"),
                new Guarded(HttpMethod.PATCH, "/api/v1/violations/7/resolve", "violation:resolve"),
                new Guarded(HttpMethod.GET, "/api/v1/events/status", "stream:operator"),
                new Guarded(HttpMethod.GET, "/api/v1/events/stream/operator", "stream:operator"),
                new Guarded(HttpMethod.GET, "/api/v1/mapping/zones/z1/versions", "mapping:view"),
                new Guarded(HttpMethod.HEAD, "/api/v1/mapping/zones/z1/versions", "mapping:view"),
                new Guarded(HttpMethod.GET, "/api/v1/mapping/zones/z1/changes", "mapping:view"),
                new Guarded(HttpMethod.GET, "/api/v1/mapping/spots/s1/changes", "mapping:view"),
                new Guarded(HttpMethod.POST, "/api/v1/files/evidence/f1", "file:upload"),
                new Guarded(HttpMethod.POST, "/api/v1/files/snapshots/c1", "file:upload"),
                new Guarded(HttpMethod.GET, "/api/v1/files/snapshots/url", "file:view"),
                new Guarded(HttpMethod.GET, "/api/v1/mapping/areas", "mapping:view"),
                new Guarded(HttpMethod.GET, "/api/v1/mapping/areas/a1", "mapping:view"),
                new Guarded(HttpMethod.HEAD, "/api/v1/mapping/areas/a1", "mapping:view"),
                new Guarded(HttpMethod.GET, "/api/v1/mapping/views/v1", "mapping:view"),
                new Guarded(HttpMethod.HEAD, "/api/v1/mapping/views/v1", "mapping:view"),
                new Guarded(HttpMethod.GET, "/api/v1/mapping/cameras/c1/views", "mapping:view"),
                new Guarded(HttpMethod.POST, "/api/v1/mapping/areas", "spot:write"),
                new Guarded(HttpMethod.PUT, "/api/v1/mapping/areas/a1", "spot:write"),
                new Guarded(HttpMethod.DELETE, "/api/v1/mapping/areas/a1", "spot:write"),
                new Guarded(HttpMethod.POST, "/api/v1/mapping/cameras/c1/views", "spot:write"),
                new Guarded(HttpMethod.PUT, "/api/v1/mapping/views/v1", "spot:write"),
                new Guarded(HttpMethod.DELETE, "/api/v1/mapping/views/v1", "spot:write"),
                new Guarded(HttpMethod.POST, "/api/v1/mapping/views/v1/import/calibration", "spot:write"),
                new Guarded(HttpMethod.PUT, "/api/v1/mapping/views/v1/georeference", "spot:write"),
                new Guarded(HttpMethod.DELETE, "/api/v1/mapping/views/v1/georeference", "spot:write"),
                new Guarded(HttpMethod.POST, "/api/v1/mapping/spots", "spot:write"),
                new Guarded(HttpMethod.PUT, "/api/v1/mapping/spots/1", "spot:write"),
                new Guarded(HttpMethod.DELETE, "/api/v1/mapping/spots/1", "spot:write"),
                new Guarded(HttpMethod.POST, "/api/v1/zones", "zone:write"),
                new Guarded(HttpMethod.PATCH, "/api/v1/zones/z1", "zone:write"),
                new Guarded(HttpMethod.DELETE, "/api/v1/zones/z1", "zone:write"),
                new Guarded(HttpMethod.GET, "/api/v1/access/roles", "access:read"),
                new Guarded(HttpMethod.GET, "/api/v1/access/users/u1/audit", "access:read"),
                new Guarded(HttpMethod.HEAD, "/api/v1/access/roles", "access:read"),
                new Guarded(HttpMethod.POST, "/api/v1/access/roles", "access:manage"),
                new Guarded(HttpMethod.PUT, "/api/v1/access/users/u1/roles", "access:manage"),
                new Guarded(HttpMethod.PATCH, "/api/v1/access/users/u1/zones", "access:manage"),
                new Guarded(HttpMethod.DELETE, "/api/v1/access/roles/r1", "access:manage"));
    }

    @Autowired
    ApplicationContext context;

    WebTestClient client;

    @BeforeEach
    void bind() {
        client = WebTestClient.bindToApplicationContext(context).build();
    }

    private int status(HttpMethod method, String path, Map<String, Object> appMetadata) {
        WebTestClient.RequestHeadersSpec<?> request = client.method(method).uri(path);
        if (appMetadata != null) {
            request = request.header("Authorization", "Bearer " + AuthorizationTestApp.token(appMetadata));
        }
        return request.exchange().returnResult(String.class).getStatus().value();
    }

    /** A token that carries permissions only: no role at all. */
    private static Map<String, Object> permissionsOnly(Set<String> permissions) {
        return Map.of("permissions", List.copyOf(permissions));
    }

    // ── permission-only tokens ──────────────────────────────────────────────────

    @ParameterizedTest
    @MethodSource("guarded")
    void exactlyThePermissionOpensTheRoute(Guarded g) {
        assertThat(status(g.method(), g.path(), permissionsOnly(Set.of(g.permission())))).as("with " + g.permission()).isEqualTo(200);

        Set<String> everythingElse = new HashSet<>(Permissions.ALL);
        everythingElse.remove(g.permission());
        assertThat(status(g.method(), g.path(), permissionsOnly(everythingElse))).as("with all but " + g.permission()).isEqualTo(403);
    }

    @ParameterizedTest
    @MethodSource("guarded")
    void noTokenIs401AndRolesAloneDoNotCountOnceThePermissionsClaimExists(Guarded g) {
        assertThat(status(g.method(), g.path(), null)).isEqualTo(401);
        // an admin whose permissions were all revoked is locked out of the permission-gated routes
        assertThat(status(g.method(), g.path(), Map.of("role", "admin", "permissions", List.of()))).isEqualTo(403);
        assertThat(status(g.method(), g.path(), Map.of("role", "driver"))).isEqualTo(403);
    }

    @Test
    void aRestrictedOperatorGetsOnlyWhatTheirRolesGrant() {
        Map<String, Object> viewer = Map.of("role", "operator", "permissions", List.of("session:read", "violation:read", "stream:operator"));
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/zone/z1", viewer)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/violations/zone/z1", viewer)).isEqualTo(200);
        assertThat(status(HttpMethod.PATCH, "/api/v1/violations/7/resolve", viewer)).isEqualTo(403);
        assertThat(status(HttpMethod.PATCH, "/api/v1/sessions/7/pay", viewer)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/lookup/plate/ABC123", viewer)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/mapping/spots", viewer)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/zones", viewer)).isEqualTo(403);
    }

    @Test
    void correctionsNeedTheirOwnPermissionAndDoNotLeakIntoTheManageRoutes() {
        Map<String, Object> manager = permissionsOnly(Set.of("session:manage", "session:read", "violation:read", "violation:resolve"));
        // session:manage still starts a session and marks it paid, but corrects nothing
        assertThat(status(HttpMethod.POST, "/api/v1/sessions/start", manager)).isEqualTo(200);
        assertThat(status(HttpMethod.PATCH, "/api/v1/sessions/7/pay", manager)).isEqualTo(200);
        for (String path : List.of("/api/v1/sessions/7/end", "/api/v1/sessions/7/void")) {
            assertThat(status(HttpMethod.POST, path, manager)).as(path).isEqualTo(403);
        }
        assertThat(status(HttpMethod.PATCH, "/api/v1/sessions/7", manager)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/fines/f1/void", manager)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/fines/f1/mark-paid", manager)).isEqualTo(403);

        // session:correct alone is not session:manage: PATCH .../pay (two segments) is not captured by PATCH /sessions/*
        Map<String, Object> corrector = permissionsOnly(Set.of("session:correct"));
        assertThat(status(HttpMethod.PATCH, "/api/v1/sessions/7", corrector)).isEqualTo(200);
        assertThat(status(HttpMethod.PATCH, "/api/v1/sessions/7/pay", corrector)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/sessions/start", corrector)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/search", corrector)).isEqualTo(403);
    }

    @Test
    void sessionSearchIsNotAnIdLookupAndOtherSessionReadsStayAuthenticatedOnly() {
        Map<String, Object> driver = Map.of("role", "driver", "permissions", List.of());
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/search", driver)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/7", driver)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/7/history", driver)).isEqualTo(403);
        // the finer rules apply to the listed methods only
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/7/end", driver)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/fines/f1/void", driver)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/fines/f1/history", driver)).isEqualTo(200);
    }

    @Test
    void permissionNamesAreMatchedExactlyNotByPrefixOrCase() {
        for (String near : List.of("zone", "zone:", "zone:*", "Zone:Write", "zone:write ", "zone:writer", "*")) {
            assertThat(status(HttpMethod.POST, "/api/v1/zones", Map.of("permissions", List.of(near)))).as(near).isEqualTo(403);
        }
    }

    // ── access management routes ────────────────────────────────────────────────

    @Test
    void everyoneSignedInMayReadTheirOwnAccessButNotOthersOrWriteThere() {
        assertThat(status(HttpMethod.GET, "/api/v1/access/me/access", Map.of("role", "driver", "permissions", List.of()))).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/access/me/access", null)).isEqualTo(401);
        assertThat(status(HttpMethod.POST, "/api/v1/access/me/access", Map.of("role", "driver", "permissions", List.of()))).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/access/users", Map.of("role", "driver", "permissions", List.of()))).isEqualTo(403);
    }

    @Test
    void readPermissionDoesNotAllowWrites() {
        Map<String, Object> reader = permissionsOnly(Set.of("access:read"));
        assertThat(status(HttpMethod.GET, "/api/v1/access/roles", reader)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/access/roles", reader)).isEqualTo(403);
    }

    // ── legacy role fallback (tokens minted before permissions existed) ─────────

    @Test
    void tokensWithoutAPermissionsClaimGetTheRoleDefaults() {
        Map<String, Object> operator = Map.of("role", "operator", "zones", List.of("z1"));
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/zone/z1", operator)).isEqualTo(200);
        assertThat(status(HttpMethod.PATCH, "/api/v1/violations/7/resolve", operator)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/mapping/spots", operator)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/events/stream/operator", operator)).isEqualTo(200);
        // not in the operator defaults: corrections of sessions and fines, zone writes (billing) and access management
        assertThat(status(HttpMethod.POST, "/api/v1/sessions/7/void", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.PATCH, "/api/v1/sessions/7", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/fines/f1/void", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/fines/f1/mark-paid", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/disputes", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/disputes/d1/decision", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/search", operator)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/fines/f1/history", operator)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/fines/f1/evidence", operator)).isEqualTo(200);
        // not in the operator defaults: zone writes (billing) and access management
        assertThat(status(HttpMethod.POST, "/api/v1/zones", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/access/roles", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/access/roles", operator)).isEqualTo(403);

        Map<String, Object> admin = Map.of("role", "admin");
        assertThat(status(HttpMethod.POST, "/api/v1/sessions/7/void", admin)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/fines/f1/mark-paid", admin)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/disputes", admin)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/disputes/d1/decision", admin)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/zones", admin)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/access/roles", admin)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/events/stream/operator", admin)).isEqualTo(200);

        Map<String, Object> driver = Map.of("role", "driver", "plates", List.of("ABC123"));
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/zone/z1", driver)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/plate/ABC123", driver)).isEqualTo(200);
    }

    @Test
    void anEmptyPermissionsClaimDisablesTheFallback() {
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/zone/z1", Map.of("role", "operator", "permissions", List.of()))).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/zone/z1", Map.of("role", "operator"))).isEqualTo(200);
    }

    // ── files and mapping reads (permission rules where unambiguous) ────────────

    @Test
    void evidenceUrlIsNotGatedByAPermissionBecauseOwnersNeedIt() {
        // the service holds staff to file:view and drivers to ownership; the gateway only wants a valid token
        for (Map<String, Object> caller : List.<Map<String, Object>>of(Map.of("role", "driver"), Map.of("role", "driver", "permissions", List.of()),
                Map.of("role", "operator", "permissions", List.of()), permissionsOnly(Set.of("session:read")))) {
            assertThat(status(HttpMethod.GET, "/api/v1/files/evidence/f1/url", caller)).as(caller.toString()).isEqualTo(200);
        }
        assertThat(status(HttpMethod.GET, "/api/v1/files/evidence/f1/url", null)).isEqualTo(401);
    }

    @Test
    void operatorsWithTheFileDefaultsReachFilesAndMapHistory() {
        Map<String, Object> operator = Map.of("role", "operator");
        assertThat(status(HttpMethod.POST, "/api/v1/files/evidence/f1", operator)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/files/snapshots/url", operator)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/mapping/zones/z1/versions", operator)).isEqualTo(200);
        Map<String, Object> driver = Map.of("role", "driver");
        assertThat(status(HttpMethod.POST, "/api/v1/files/evidence/f1", driver)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/files/snapshots/url", driver)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/mapping/zones/z1/versions", driver)).isEqualTo(403);
    }

    @Test
    void mapReadsDriversNeedStayOpenAndTheOverlapCheckIsLeftToTheService() {
        Map<String, Object> driver = Map.of("role", "driver", "permissions", List.of());
        for (String path : List.of("/api/v1/mapping/zones/z1/spots", "/api/v1/mapping/zones/z1/geojson", "/api/v1/mapping/spots/s1",
                "/api/v1/zones/nearest", "/api/v1/zones")) {
            assertThat(status(HttpMethod.GET, path, driver)).as(path).isEqualTo(200);
        }
        // mapping:view or spot:write alone must get through the gateway (the service accepts either), without zone:write
        for (String permission : List.of("mapping:view", "spot:write", "zone:write")) {
            assertThat(status(HttpMethod.POST, "/api/v1/zones/check-overlap", permissionsOnly(Set.of(permission)))).as(permission).isEqualTo(200);
        }
        assertThat(status(HttpMethod.POST, "/api/v1/zones/check-overlap", null)).isEqualTo(401);
        // the rest of the zone writes are unchanged
        assertThat(status(HttpMethod.POST, "/api/v1/zones", permissionsOnly(Set.of("mapping:view", "spot:write")))).isEqualTo(403);
    }

    // ── disputes: the driver side needs only a token, the review queue needs fine:manage ──

    @Test
    void theDriverSideOfADisputeNeedsOnlyAValidTokenAndTheServiceDecidesOnOwnership() {
        Map<String, Object> driver = Map.of("role", "driver", "permissions", List.of(), "plates", List.of("ABC123"));
        Map<String, Object> operator = Map.of("role", "operator", "permissions", List.of());
        for (Object[] call : new Object[][]{
                {HttpMethod.GET, "/api/v1/fines/f1/explanation"}, {HttpMethod.GET, "/api/v1/fines/f1/dispute"},
                {HttpMethod.POST, "/api/v1/fines/f1/dispute"}, {HttpMethod.POST, "/api/v1/disputes/d1/withdraw"}}) {
            HttpMethod method = (HttpMethod) call[0];
            String path = (String) call[1];
            assertThat(status(method, path, null)).as(method + " " + path + " anonymous").isEqualTo(401);
            assertThat(status(method, path, driver)).as(method + " " + path + " driver").isEqualTo(200);
            assertThat(status(method, path, operator)).as(method + " " + path + " operator").isEqualTo(200);
        }
    }

    @Test
    void theReviewQueueAndTheDecisionAreClosedToDriversEvenWithTheirOwnRoutesOpen() {
        Map<String, Object> driver = Map.of("role", "driver", "plates", List.of("ABC123"));
        assertThat(status(HttpMethod.GET, "/api/v1/disputes", driver)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/disputes?status=all", driver)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/disputes/d1/decision", driver)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/fines/f1/evidence", driver)).isEqualTo(403);
        // fine:manage opens the queue but not the evidence (violation:read), and the other way round
        Map<String, Object> manager = permissionsOnly(Set.of("fine:manage"));
        assertThat(status(HttpMethod.GET, "/api/v1/disputes", manager)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/fines/f1/evidence", manager)).isEqualTo(403);
        Map<String, Object> reader = permissionsOnly(Set.of("violation:read"));
        assertThat(status(HttpMethod.GET, "/api/v1/fines/f1/evidence", reader)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/disputes", reader)).isEqualTo(403);
        // the finer rules apply to the listed methods only: the evidence is GET, withdraw is POST
        assertThat(status(HttpMethod.POST, "/api/v1/fines/f1/evidence", driver)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/disputes/d1/withdraw", driver)).isEqualTo(403);
    }

    // ── fines and profile: any signed-in user, the services decide ──────────────

    @Test
    void finesAndUserProfileNeedOnlyAValidToken() {
        for (String path : List.of("/api/v1/fines/plate/ABC123", "/api/v1/fines/zone/z1", "/api/v1/fines/f1", "/api/v1/users/me")) {
            assertThat(status(HttpMethod.GET, path, null)).as(path + " anonymous").isEqualTo(401);
            assertThat(status(HttpMethod.GET, path, Map.of("role", "driver", "permissions", List.of()))).as(path + " driver").isEqualTo(200);
            assertThat(status(HttpMethod.GET, path, Map.of("role", "operator", "permissions", List.of()))).as(path + " operator").isEqualTo(200);
        }
        assertThat(status(HttpMethod.PUT, "/api/v1/users/me", Map.of("role", "driver"))).isEqualTo(200);
        assertThat(status(HttpMethod.PUT, "/api/v1/users/me", null)).isEqualTo(401);
    }

    // ── cameras, detections, notifications, own plates ──────────────────────────

    @Test
    void cameraListIsLeftToTheServiceAndTheDeviceAndAdminRulesAreNotShadowed() {
        Map<String, Object> driver = Map.of("role", "driver", "permissions", List.of());
        // GET /cameras: ingestion-service wants camera:admin OR stream:operator with zone scope, so any valid token passes the edge
        assertThat(status(HttpMethod.GET, "/api/v1/cameras", null)).isEqualTo(401);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras", driver)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras", permissionsOnly(Set.of("stream:operator")))).isEqualTo(200);
        // device endpoints stay public (POST only), the admin rule still guards cameras/admin/**
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/ingest", null)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/heartbeat", null)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras/ingest", null)).isEqualTo(401);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras/admin/snapshot-url", permissionsOnly(Set.of("ai:use")))).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/admin/capture", permissionsOnly(Set.of("ai:use")))).as("camera id admin stays under the admin rule").isEqualTo(403);
        // capture is POST only and needs ai:use, not camera:admin; `*` is one segment, so deeper paths are not capture
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/capture", permissionsOnly(Set.of("camera:admin")))).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/capture", null)).isEqualTo(401);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras/c1/capture", driver)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/x/capture", driver)).isEqualTo(200);
    }

    @Test
    void calibrationScanAndPtzPresetsAreForCameraAdminsAndTheServiceAlsoWantsAiUseForTheScan() {
        // the rule format names one permission: the edge asks for camera:admin, ingestion-service checks camera:admin AND ai:use
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/calibration/scan", permissionsOnly(Set.of("camera:admin")))).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/calibration/scan", permissionsOnly(Set.of("ai:use")))).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/calibration/scan", permissionsOnly(Set.of("camera:admin", "ai:use")))).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras/c1/ptz/presets", permissionsOnly(Set.of("camera:admin")))).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras/c1/ptz/presets", permissionsOnly(Set.of("ai:use", "stream:operator")))).isEqualTo(403);
        // the default operator holds both, a driver neither, and nobody gets in without a token
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/calibration/scan", Map.of("role", "operator"))).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras/c1/ptz/presets", Map.of("role", "operator"))).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/calibration/scan", Map.of("role", "driver"))).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras/c1/ptz/presets", Map.of("role", "driver"))).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/calibration/scan", null)).isEqualTo(401);
        assertThat(status(HttpMethod.GET, "/api/v1/cameras/c1/ptz/presets", null)).isEqualTo(401);
        // `*` is one segment, and a camera id `admin` stays under the admin rule
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/admin/calibration/scan", permissionsOnly(Set.of("ai:use")))).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/x/calibration/scan", Map.of("role", "driver", "permissions", List.of()))).isEqualTo(200);
        // the capture rule is untouched
        assertThat(status(HttpMethod.POST, "/api/v1/cameras/c1/capture", permissionsOnly(Set.of("camera:admin")))).isEqualTo(403);
    }

    @Test
    void parkingAreasAndCameraViewsAreReadWithMappingViewAndWrittenWithSpotWrite() {
        Map<String, Object> viewer = permissionsOnly(Set.of("mapping:view"));
        Map<String, Object> editor = permissionsOnly(Set.of("spot:write"));
        Map<String, Object> driver = Map.of("role", "driver", "permissions", List.of());
        for (String path : List.of("/api/v1/mapping/areas", "/api/v1/mapping/areas/a1", "/api/v1/mapping/views/v1", "/api/v1/mapping/cameras/c1/views")) {
            assertThat(status(HttpMethod.GET, path, viewer)).as(path + " viewer").isEqualTo(200);
            assertThat(status(HttpMethod.GET, path, editor)).as(path + " editor (the service wants mapping:view to read)").isEqualTo(403);
            assertThat(status(HttpMethod.GET, path, driver)).as(path + " driver").isEqualTo(403);
            assertThat(status(HttpMethod.GET, path, Map.of("role", "operator"))).as(path + " operator with the defaults").isEqualTo(200);
            assertThat(status(HttpMethod.GET, path, null)).as(path + " anonymous").isEqualTo(401);
        }
        for (String path : List.of("/api/v1/mapping/areas", "/api/v1/mapping/cameras/c1/views", "/api/v1/mapping/views/v1/import/calibration")) {
            assertThat(status(HttpMethod.POST, path, editor)).as(path + " editor").isEqualTo(200);
            assertThat(status(HttpMethod.POST, path, viewer)).as(path + " viewer").isEqualTo(403);
            assertThat(status(HttpMethod.POST, path, driver)).as(path + " driver").isEqualTo(403);
        }
        // what drivers read on the map stays open
        assertThat(status(HttpMethod.GET, "/api/v1/mapping/zones/z1/spots", driver)).isEqualTo(200);
    }

    @Test
    void detectionReadsAndReviewsAreGuardedByTheirOwnPermission() {
        // reading the queue does not allow deciding, and the other way round
        assertThat(status(HttpMethod.PATCH, "/api/v1/detections/d1/review", permissionsOnly(Set.of("violation:read")))).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/detections", permissionsOnly(Set.of("violation:resolve")))).isEqualTo(403);
        assertThat(status(HttpMethod.HEAD, "/api/v1/detections", permissionsOnly(Set.of("violation:read")))).isEqualTo(200);
        // default operator reads and reviews, a driver does neither
        assertThat(status(HttpMethod.GET, "/api/v1/detections", Map.of("role", "operator"))).isEqualTo(200);
        assertThat(status(HttpMethod.PATCH, "/api/v1/detections/d1/review", Map.of("role", "operator"))).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/detections", Map.of("role", "driver"))).isEqualTo(403);
        assertThat(status(HttpMethod.PATCH, "/api/v1/detections/d1/review", Map.of("role", "driver"))).isEqualTo(403);
    }

    @Test
    void notificationsAndOwnPlatesNeedOnlyAValidToken() {
        Map<String, Object> driver = Map.of("role", "driver", "permissions", List.of());
        record Call(HttpMethod method, String path) {
        }
        for (Call call : List.of(new Call(HttpMethod.GET, "/api/v1/notifications"), new Call(HttpMethod.PATCH, "/api/v1/notifications/n1/read"),
                new Call(HttpMethod.POST, "/api/v1/notifications/read-all"), new Call(HttpMethod.PUT, "/api/v1/notifications/push-subscription"),
                new Call(HttpMethod.DELETE, "/api/v1/notifications/push-subscription"), new Call(HttpMethod.POST, "/api/v1/notifications/test-push"),
                new Call(HttpMethod.GET, "/api/v1/users/me/plates"), new Call(HttpMethod.POST, "/api/v1/users/me/plates"),
                new Call(HttpMethod.DELETE, "/api/v1/users/me/plates/ABC123"))) {
            assertThat(status(call.method(), call.path(), null)).as(call + " anonymous").isEqualTo(401);
            assertThat(status(call.method(), call.path(), driver)).as(call + " driver").isEqualTo(200);
            assertThat(status(call.method(), call.path(), Map.of("role", "operator", "permissions", List.of()))).as(call + " operator").isEqualTo(200);
        }
    }

    // ── routes that stay open or role-free ──────────────────────────────────────

    @Test
    void publicAndAuthenticatedRoutesAreUnchanged() {
        assertThat(status(HttpMethod.POST, "/api/v1/auth/login", null)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/count/active", null)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/zones/nearest", Map.of("role", "driver"))).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/mapping/zones/z1", Map.of("role", "driver"))).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/plate/ABC123", null)).isEqualTo(401);
    }
}
