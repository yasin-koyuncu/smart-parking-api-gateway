package com.parkview.gateway.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.parkview.gateway.config.CorsConfig;
import com.parkview.gateway.config.SecurityConfig;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.EnableWebFlux;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * The real security chain with the real rules from application.yml and the real {@link ParkviewJwtConverter}, but
 * no Netty, Redis or routes: a probe answers 200 wherever the rules let a request through. A stand-in decoder turns
 * the bearer token (base64url of the {@code app_metadata} JSON) into a Jwt, so the tests need no signing keys.
 */
@Configuration
@TestComponent   // keeps it out of the component scan of the full-context tests (GatewayRoutingTest)
@EnableWebFlux
@ImportAutoConfiguration({JacksonAutoConfiguration.class, ValidationAutoConfiguration.class})
@Import({SecurityConfig.class, CorsConfig.class})
class AuthorizationTestApp {

    static String token(Map<String, Object> appMetadata) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(new ObjectMapper().writeValueAsBytes(appMetadata));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Bean
    @Primary
    ReactiveJwtDecoder testJwtDecoder() {
        return token -> {
            try {
                Map<String, Object> appMetadata = new ObjectMapper().readValue(Base64.getUrlDecoder().decode(token), new TypeReference<>() {
                });
                return Mono.just(Jwt.withTokenValue(token).header("alg", "none").subject("user-1").claim("app_metadata", appMetadata)
                        .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300)).build());
            } catch (IOException | IllegalArgumentException e) {
                return Mono.error(new JwtException("bad test token"));
            }
        };
    }

    @RestController
    static class Probe {
        @RequestMapping("/**")
        String any() {
            return "ok";
        }
    }
}
