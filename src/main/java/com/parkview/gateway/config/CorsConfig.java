package com.parkview.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.List;

/**
 * CORS must be answered by the security chain: a preflight ({@code OPTIONS}) carries no token, so if
 * authorisation ran first every cross-origin call to a protected route would fail in the browser.
 * Bearer tokens travel in the Authorization header, so cookies/credentials are not allowed.
 */
@Configuration
public class CorsConfig {

    @Bean
    CorsConfigurationSource corsConfigurationSource(GatewayProperties properties) {
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOriginPatterns(properties.allowedOrigins());
        cors.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        cors.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "X-Request-Id", "Last-Event-ID"));
        cors.setExposedHeaders(List.of("X-Request-Id", "X-Total-Count", "Retry-After", "WWW-Authenticate"));
        cors.setAllowCredentials(false);
        cors.setMaxAge(Duration.ofHours(1));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);
        return source;
    }
}
