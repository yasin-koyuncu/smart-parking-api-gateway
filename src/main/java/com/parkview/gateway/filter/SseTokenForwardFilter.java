package com.parkview.gateway.filter;

import com.parkview.gateway.config.GatewayProperties;
import com.parkview.gateway.security.SseTokenPaths;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

/**
 * The SSE token is accepted from {@code ?token=} during authentication (see SseTokenBearerConverter).
 * Before proxying it is moved into the Authorization header and removed from the URL, so the upstream
 * service stays header-only and the token never appears in upstream access logs.
 */
@Component
public class SseTokenForwardFilter implements GlobalFilter, Ordered {

    private final SseTokenPaths ssePaths;

    public SseTokenForwardFilter(GatewayProperties properties) {
        this.ssePaths = new SseTokenPaths(properties);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        var request = exchange.getRequest();
        String token = ssePaths.tokenOf(request).orElse(null);
        if (token == null) {
            return chain.filter(exchange);
        }

        var uri = UriComponentsBuilder.fromUri(request.getURI()).replaceQueryParam("token").build(true).toUri();
        var mutated = request.mutate().uri(uri).headers(h -> {
            if (!h.containsKey(HttpHeaders.AUTHORIZATION)) {
                h.setBearerAuth(token);
            }
        }).build();
        return chain.filter(exchange.mutate().request(mutated).build());
    }

    @Override
    public int getOrder() {
        return -2;
    }
}
