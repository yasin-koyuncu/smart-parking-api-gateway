package com.parkview.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Konverterar ?token=<jwt> query-parameter till Authorization-header.
 * Behövs för SSE-endpoints eftersom EventSource inte stöder custom headers.
 *
 * Används BARA för /api/v1/events/stream/** endpoints.
 */
@Component
public class TokenQueryParamFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        var request = exchange.getRequest();
        var path    = request.getPath().value();

        // Bara för SSE-endpoints
        if (!path.startsWith("/api/v1/events/stream")) {
            return chain.filter(exchange);
        }

        var token = request.getQueryParams().getFirst("token");
        if (token == null || token.isBlank()) {
            return chain.filter(exchange);
        }

        // Flytta token från query-param till Authorization-header
        ServerHttpRequest mutated = request.mutate()
                .header("Authorization", "Bearer " + token)
                .build();

        return chain.filter(exchange.mutate().request(mutated).build());
    }

    @Override
    public int getOrder() {
        return -2;  // Kör innan AuthForwardFilter
    }
}