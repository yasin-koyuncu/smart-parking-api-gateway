package com.parkview.gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.parkview.gateway.security.ParkviewJwtConverter;
import com.parkview.gateway.security.RuleAuthorizer;
import com.parkview.gateway.security.SseTokenBearerConverter;
import com.parkview.gateway.web.ProblemResponses;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Edge security: answer CORS before authorisation, write the security headers and error bodies, validate the JWT
 * (decoder: {@link JwtDecoderConfig}) and apply the declarative rules from {@code parkview.gateway.rules}
 * ({@link RuleAuthorizer}).
 * Authorities: roles ADMIN (implies OPERATOR), OPERATOR, DRIVER from {@code app_metadata.role} and one authority per
 * entry of {@code app_metadata.permissions} (see {@link ParkviewJwtConverter}); rules use either.
 */
@Configuration
@EnableWebFluxSecurity
@EnableConfigurationProperties({GatewayProperties.class, SecurityProperties.class})
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            GatewayProperties gateway,
            SecurityProperties security,
            ReactiveJwtDecoder jwtDecoder,
            CorsConfigurationSource cors,
            ObjectMapper objectMapper) {

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .cors(c -> c.configurationSource(cors));
        writeHeaders(http, gateway.docsEnabled());
        writeProblemErrors(http, objectMapper);
        http.oauth2ResourceServer(o -> o
                .bearerTokenConverter(new SseTokenBearerConverter(gateway))
                .jwt(j -> j.jwtDecoder(jwtDecoder).jwtAuthenticationConverter(ParkviewJwtConverter.create(security.legacyRoleFallback()))));

        http.authorizeExchange(ex -> {
            ex.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll();
            ex.pathMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
            ex.pathMatchers("/actuator/prometheus").access(internalKey(security));
            ex.pathMatchers("/actuator/**").denyAll();

            if (gateway.docsEnabled()) {
                ex.pathMatchers("/docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/**", "/v3/api-docs/**").permitAll();
            }

            RuleAuthorizer.apply(ex, gateway.rules());
            ex.anyExchange().authenticated();
        });
        return http.build();
    }

    private static void writeHeaders(ServerHttpSecurity http, boolean docsEnabled) {
        String csp = docsEnabled
                ? "default-src 'self' 'unsafe-inline' data:"
                : "default-src 'none'; frame-ancestors 'none'";
        http.headers(h -> h
                .contentSecurityPolicy(p -> p.policyDirectives(csp))
                .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
                .permissionsPolicy(p -> p.policy("camera=(), microphone=(), geolocation=()")));
    }

    private static void writeProblemErrors(ServerHttpSecurity http, ObjectMapper objectMapper) {
        http.exceptionHandling(e -> e
                .authenticationEntryPoint((exchange, ex) -> ProblemResponses.write(
                        exchange, objectMapper, HttpStatus.UNAUTHORIZED, "Unauthorized", "Authentication is required"))
                .accessDeniedHandler((exchange, ex) -> ProblemResponses.write(
                        exchange, objectMapper, HttpStatus.FORBIDDEN, "Forbidden", "You are not allowed to perform this action")));
    }

    /** Metrics are for the platform only: callers must present the internal API key. */
    private static ReactiveAuthorizationManager<AuthorizationContext> internalKey(SecurityProperties security) {
        return (Mono<Authentication> authentication, AuthorizationContext context) -> {
            String presented = context.getExchange().getRequest().getHeaders().getFirst("X-Internal-Api-Key");
            boolean ok = security.internalApiEnabled() && presented != null && MessageDigest.isEqual(
                    security.internalApiKey().getBytes(StandardCharsets.UTF_8), presented.getBytes(StandardCharsets.UTF_8));
            return Mono.just(new AuthorizationDecision(ok));
        };
    }
}
