package com.parkview.gateway.filter;

import lombok.extern.slf4j.Slf4j;
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
 * Lägger till X-User-Id och X-User-Role headers på alla requests
 * så att downstream-tjänster vet vem som anropar utan att validera JWT igen.
 */
@Slf4j
@Component
public class AuthForwardFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(ctx -> {
                    var auth = ctx.getAuthentication();
                    if (auth instanceof JwtAuthenticationToken jwtAuth) {
                        Jwt jwt = jwtAuth.getToken();
                        ServerHttpRequest mutated = exchange.getRequest().mutate()
                                .header("X-User-Id",   jwt.getSubject())
                                .header("X-User-Email", jwt.getClaimAsString("email") != null
                                        ? jwt.getClaimAsString("email") : "")
                                .header("X-User-Role",  jwtAuth.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("ROLE_operator"))
                                        ? "operator" : "driver")
                                .build();
                        return chain.filter(exchange.mutate().request(mutated).build());
                    }
                    return chain.filter(exchange);
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    @Override
    public int getOrder() {
        return -1;  // Kör före alla andra filter
    }
}