package com.parkview.gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** With {@code parkview.security.legacy-role-fallback=false} only the permissions claim counts. */
@SpringBootTest(classes = AuthorizationTestApp.class,
        properties = {"SUPABASE_URL=http://issuer.test", "parkview.security.legacy-role-fallback=false"})
class LegacyFallbackDisabledTest {

    @Autowired
    ApplicationContext context;

    private int status(HttpMethod method, String path, Map<String, Object> appMetadata) {
        return WebTestClient.bindToApplicationContext(context).build().method(method).uri(path)
                .header("Authorization", "Bearer " + AuthorizationTestApp.token(appMetadata))
                .exchange().returnResult(String.class).getStatus().value();
    }

    @Test
    void aTokenWithoutPermissionsGetsNoPermissionRoutesWhateverItsRole() {
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/zone/z1", Map.of("role", "operator"))).isEqualTo(403);
        assertThat(status(HttpMethod.POST, "/api/v1/zones", Map.of("role", "admin"))).isEqualTo(403);
        assertThat(status(HttpMethod.GET, "/api/v1/events/stream/operator", Map.of("role", "admin"))).isEqualTo(403);
    }

    @Test
    void tokensWithPermissionsAndRoleFreeRoutesStillWork() {
        assertThat(status(HttpMethod.GET, "/api/v1/sessions/zone/z1", Map.of("role", "operator", "permissions", List.of("session:read")))).isEqualTo(200);
        assertThat(status(HttpMethod.GET, "/api/v1/access/me/access", Map.of("role", "operator"))).isEqualTo(200);
    }
}
