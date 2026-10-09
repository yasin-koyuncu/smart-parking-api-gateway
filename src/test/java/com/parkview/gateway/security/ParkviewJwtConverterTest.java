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
}
