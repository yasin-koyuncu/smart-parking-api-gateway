package com.parkview.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;

import java.util.List;

/**
 * JWT-baserad säkerhetskonfiguration.
 * Supabase-JWT valideras mot JWKS-endpointen.
 *
 * Roller:
 *   authenticated  → kan se egna sessioner och betala böter
 *   operator       → kan se alla sessioner, violations, kamera-admin
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex
                        // Publika endpoints
                        .pathMatchers(HttpMethod.GET,  "/actuator/health").permitAll()
                        .pathMatchers(HttpMethod.GET,  "/api/v1/sessions/count/active").permitAll()

                        // Förare — kräver inloggning
                        .pathMatchers("/api/v1/sessions/plate/**").authenticated()
                        .pathMatchers(HttpMethod.PATCH, "/api/v1/sessions/*/pay").authenticated()

                        // Operatör — kräver operator-roll
                        .pathMatchers("/api/v1/violations/**").hasRole("operator")
                        .pathMatchers("/api/v1/sessions/zone/**").hasRole("operator")
                        .pathMatchers("/api/v1/ai/**").hasRole("operator")

                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter()))
                )
                .build();
    }

    /**
     * Extraherar roller från Supabase JWT.
     * Supabase lagrar app_metadata.role i JWT-claims.
     */
    @Bean
    public ReactiveJwtAuthenticationConverter jwtConverter() {
        var converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var authorities = new java.util.ArrayList<org.springframework.security.core.GrantedAuthority>();

            // Standard authenticated-roll
            authorities.add(() -> "ROLE_authenticated");

            // Supabase: app_metadata.role
            var appMeta = jwt.getClaimAsMap("app_metadata");
            if (appMeta != null) {
                Object role = appMeta.get("role");
                if ("operator".equals(role) || "admin".equals(role)) {
                    authorities.add(() -> "ROLE_operator");
                }
            }

            // Supabase: user_role claim (alternativt format)
            String userRole = jwt.getClaimAsString("user_role");
            if ("operator".equals(userRole) || "admin".equals(userRole)) {
                authorities.add(() -> "ROLE_operator");
            }

            return Flux.fromIterable(authorities);
        });
        return converter;
    }
}