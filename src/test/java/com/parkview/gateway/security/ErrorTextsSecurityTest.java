package com.parkview.gateway.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.List;
import java.util.Map;

/**
 * The 401 and 403 that the gateway's security chain writes follow the {@code Accept-Language} header (Swedish, English; any other
 * language and no header get English) and carry the stable {@code code}. Runs on a mock server like the authorisation matrix.
 */
@SpringBootTest(classes = AuthorizationTestApp.class, properties = "SUPABASE_URL=http://issuer.test")
class ErrorTextsSecurityTest {

    private static final String GUARDED = "/api/v1/zones";

    @Autowired
    ApplicationContext context;

    WebTestClient client;

    @BeforeEach
    void bind() {
        client = WebTestClient.bindToApplicationContext(context).build();
    }

    private static String driverToken() {
        return AuthorizationTestApp.token(Map.of("role", "driver", "permissions", List.of()));
    }

    @Test
    void unauthenticatedCallerGetsTheTextInTheirLanguage() {
        client.post().uri(GUARDED).header("Accept-Language", "sv-SE,sv;q=0.9").exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.title").isEqualTo("Inte inloggad")
                .jsonPath("$.detail").isEqualTo("Du måste logga in")
                .jsonPath("$.message").isEqualTo("Du måste logga in")
                .jsonPath("$.code").isEqualTo("error.unauthorized");
    }

    @Test
    void callerWithoutLanguageOrWithAnUnknownOneGetsEnglish() {
        for (String language : new String[] {null, "fr"}) {
            WebTestClient.RequestHeadersSpec<?> request = client.post().uri(GUARDED);
            if (language != null) {
                request = request.header("Accept-Language", language);
            }
            request.exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.title").isEqualTo("Unauthorized")
                    .jsonPath("$.detail").isEqualTo("Authentication is required")
                    .jsonPath("$.code").isEqualTo("error.unauthorized");
        }
    }

    @Test
    void forbiddenCallerGetsTheTextInTheirLanguage() {
        client.post().uri(GUARDED).header("Authorization", "Bearer " + driverToken()).header("Accept-Language", "sv").exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.title").isEqualTo("Inte tillåtet")
                .jsonPath("$.detail").isEqualTo("Du har inte behörighet att göra detta")
                .jsonPath("$.code").isEqualTo("error.forbidden");

        client.post().uri(GUARDED).header("Authorization", "Bearer " + driverToken()).exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.title").isEqualTo("Forbidden")
                .jsonPath("$.detail").isEqualTo("You are not allowed to perform this action");
    }
}
