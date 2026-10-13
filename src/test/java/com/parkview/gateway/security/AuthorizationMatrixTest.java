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
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/search", operator)).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/fines/f1/history", operator)).isEqualTo(200);
        // not in the operator defaults: zone writes (billing) and access management
        assertThat(status(HttpMethod.POST, "/api/v1/zones", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/access/roles", operator)).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/access/roles", operator)).isEqualTo(403);

        Map<String, Object> admin = Map.of("role", "admin");
        assertThat(status(HttpMethod.POST, "/api/v1/sessions/7/void", admin)).isEqualTo(200);
        assertThat(status(HttpMethod.POST, "/api/v1/fines/f1/mark-paid", admin)).isEqualTo(200);
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
