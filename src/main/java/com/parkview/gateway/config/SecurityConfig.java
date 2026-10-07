package com.parkview.gateway.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;

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
@EnableConfigurationProperties(GatewayPathsProperties.class)
public class SecurityConfig {

    private final GatewayPathsProperties paths;

    public SecurityConfig(GatewayPathsProperties paths) {
        this.paths = paths;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex
                        // Publika endpoints (från parkview.gateway.public-paths) —
                        // t.ex. /api/v1/auth/**, /api/v1/payments/webhook och de två
                        // kamera-device-autentiserade endpoints (api_key i body, inget JWT).
                        .pathMatchers(paths.getPublicPaths().toArray(new String[0])).permitAll()

                        // Förare — kräver inloggning
                        .pathMatchers("/api/v1/sessions/plate/**").authenticated()
                        .pathMatchers(HttpMethod.PATCH, "/api/v1/sessions/*/pay").authenticated()

                        // Operatör — kräver operator-roll (från parkview.gateway.operator-paths)
                        .pathMatchers(paths.getOperatorPaths().toArray(new String[0])).hasRole("operator")
                        .pathMatchers("/api/v1/sessions/zone/**").hasRole("operator")

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
