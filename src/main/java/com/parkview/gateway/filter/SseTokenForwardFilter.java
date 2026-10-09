package com.parkview.gateway.filter;

import com.parkview.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * The SSE token is accepted from {@code ?token=} during authentication (see SseTokenBearerConverter).
 * Before proxying it is moved into the Authorization header and removed from the URL, so the upstream
 * service stays header-only and the token never appears in upstream access logs.
 */
@Component
public class SseTokenForwardFilter implements GlobalFilter, Ordered {

    private final List<PathPattern> ssePaths;

    public SseTokenForwardFilter(GatewayProperties properties) {
        PathPatternParser parser = new PathPatternParser();
        this.ssePaths = properties.sseTokenPaths().stream().map(parser::parse).toList();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        var request = exchange.getRequest();
        boolean sse = ssePaths.stream().anyMatch(p -> p.matches(request.getPath().pathWithinApplication()));
        String token = request.getQueryParams().getFirst("token");
        if (!sse || !StringUtils.hasText(token)) {
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
