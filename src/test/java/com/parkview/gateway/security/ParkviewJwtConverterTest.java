package com.parkview.gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ParkviewJwtConverterTest {

    private static Jwt jwt(Object appMetadata) {
        Jwt.Builder builder = Jwt.withTokenValue("t").header("alg", "ES256").subject("u1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
        if (appMetadata != null) {
            builder.claim("app_metadata", appMetadata);
        } else {
            builder.claim("sub", "u1");
        }
        return builder.build();
    }

    private static List<String> roles(Jwt jwt) {
        return ParkviewJwtConverter.roles(jwt).stream().map(GrantedAuthority::getAuthority).toList();
    }

    @Test
    void adminImpliesOperator() {
        assertThat(roles(jwt(Map.of("role", "admin")))).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_OPERATOR");
    }

    @Test
    void operatorAndDriverMapToTheirOwnRoleOnlyCaseInsensitively() {
        assertThat(roles(jwt(Map.of("role", "Operator")))).containsExactly("ROLE_OPERATOR");
        assertThat(roles(jwt(Map.of("role", "driver")))).containsExactly("ROLE_DRIVER");
    }

    @Test
    void unknownOrMissingRoleGivesNoAuthorities() {
        assertThat(roles(jwt(Map.of("role", "superuser")))).isEmpty();
        assertThat(roles(jwt(Map.of("plates", List.of("ABC123"))))).isEmpty();
        assertThat(roles(jwt(null))).isEmpty();
    }

    @Test
    void legacyUserRoleClaimIsNotHonoured() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "ES256").subject("u1").claim("user_role", "operator")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        assertThat(roles(jwt)).isEmpty();
    }

    // ── permissions (ADR 0002) ─────────────────────────────────────────────────

    private static List<String> permissions(Jwt jwt, boolean fallback) {
        return ParkviewJwtConverter.permissions(jwt, fallback).stream().map(GrantedAuthority::getAuthority).toList();
    }

    private static List<String> all(Jwt jwt, boolean fallback) {
        return ParkviewJwtConverter.authorities(fallback).convert(jwt).map(GrantedAuthority::getAuthority).collectList().block();
    }

    @Test
    void permissionsClaimBecomesOneAuthorityPerPermissionNamedExactly() {
        Jwt jwt = jwt(Map.of("role", "operator", "permissions", List.of("zone:write", "stream:operator", "zone:write")));
        assertThat(permissions(jwt, true)).containsExactlyInAnyOrder("zone:write", "stream:operator");
        assertThat(all(jwt, true)).containsExactlyInAnyOrder("ROLE_OPERATOR", "zone:write", "stream:operator");
    }

    @Test
    void presentClaimIsAuthoritativeEvenWhenEmptyOrMalformedAndNeverFallsBack() {
        assertThat(permissions(jwt(Map.of("role", "admin", "permissions", List.of())), true)).isEmpty();
        assertThat(all(jwt(Map.of("role", "admin", "permissions", List.of())), true)).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_OPERATOR");
        assertThat(permissions(jwt(Map.of("role", "admin", "permissions", "zone:write")), true)).isEmpty();
        assertThat(permissions(jwt(Map.of("role", "operator", "permissions", List.of(" ", 7, "ai:use"))), true)).containsExactly("ai:use");
    }

    @Test
    void absentClaimFallsBackToTheRoleDefaultsOnlyWhileTheFallbackIsOn() {
        assertThat(permissions(jwt(Map.of("role", "admin")), true)).containsExactlyInAnyOrderElementsOf(Permissions.ALL).hasSize(18);
        assertThat(permissions(jwt(Map.of("role", "Operator")), true))
                .containsExactlyInAnyOrderElementsOf(Permissions.DEFAULTS_BY_ROLE.get("operator"))
                .doesNotContain("zone:write", "access:read", "access:manage", "session:correct", "fine:manage");
        assertThat(permissions(jwt(Map.of("role", "driver")), true)).isEmpty();
        assertThat(permissions(jwt(Map.of("role", "superuser")), true)).isEmpty();
        assertThat(permissions(jwt(null), true)).isEmpty();

        assertThat(permissions(jwt(Map.of("role", "admin")), false)).isEmpty();
        assertThat(all(jwt(Map.of("role", "admin")), false)).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_OPERATOR");
    }
}
