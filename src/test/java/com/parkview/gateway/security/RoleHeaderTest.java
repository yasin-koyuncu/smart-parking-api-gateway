package com.parkview.gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class RoleHeaderTest {

    private static String of(String... authorities) {
        return RoleHeader.of(Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList());
    }

    @Test
    void adminWinsOverOperator() {
        assertThat(of("ROLE_OPERATOR", "ROLE_ADMIN", "zone:write")).isEqualTo("admin");
    }

    @Test
    void operatorWithoutAdmin() {
        assertThat(of("ROLE_OPERATOR", "zone:write")).isEqualTo("operator");
    }

    @Test
    void everyoneElseIsDriver() {
        assertThat(of("ROLE_DRIVER")).isEqualTo("driver");
        assertThat(of()).isEqualTo("driver");
    }

    @Test
    void permissionsNamedLikeRolesDoNotCount() {
        assertThat(of("admin", "operator", "ROLE_ADMINISTRATOR")).isEqualTo("driver");
    }
}
