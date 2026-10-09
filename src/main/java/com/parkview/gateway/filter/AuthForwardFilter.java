package com.parkview.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Tells downstream services who is calling (convenience headers {@code X-User-Id}, {@code X-User-Role}).
 * They are informational only: the services validate the forwarded JWT themselves and never trust these
 * headers for authorisation. Client-supplied copies are removed earlier by the EdgeHeadersWebFilter.
 */
@Component
public class AuthForwardFilter implements GlobalFilter, Ordered {

    public static final String USER_ID_ATTRIBUTE = "parkview.userId";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // chain.filter must run exactly once: resolve the (possibly mutated) exchange first and call it last
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .filter(JwtAuthenticationToken.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .map(auth -> withUserHeaders(exchange, auth))
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    private static ServerWebExchange withUserHeaders(ServerWebExchange exchange, JwtAuthenticationToken auth) {
        Jwt jwt = auth.getToken();
        boolean admin = auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean operator = auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_OPERATOR"));
        ServerHttpRequest mutated = exchange.getRequest().mutate()
                .header("X-User-Id", jwt.getSubject())
                .header("X-User-Role", admin ? "admin" : operator ? "operator" : "driver")
                .build();
        ServerWebExchange result = exchange.mutate().request(mutated).build();
        result.getAttributes().put(USER_ID_ATTRIBUTE, jwt.getSubject());
        return result;
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
