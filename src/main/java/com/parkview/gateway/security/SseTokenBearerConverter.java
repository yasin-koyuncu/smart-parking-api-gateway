package com.parkview.gateway.security;

import com.parkview.gateway.config.GatewayProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Reads the bearer token from the Authorization header and - only for the configured SSE paths - from
 * the {@code ?token=} query parameter. Browsers' {@code EventSource} cannot send headers, and this has to
 * happen inside the security chain (a gateway route filter runs too late for authentication).
 */
public class SseTokenBearerConverter implements ServerAuthenticationConverter {

    private final ServerBearerTokenAuthenticationConverter headerConverter = new ServerBearerTokenAuthenticationConverter();
    private final List<PathPattern> ssePaths;

    public SseTokenBearerConverter(GatewayProperties properties) {
        PathPatternParser parser = new PathPatternParser();
        this.ssePaths = properties.sseTokenPaths().stream().map(parser::parse).toList();
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        Mono<Authentication> fromHeader = headerConverter.convert(exchange);
        return fromHeader.switchIfEmpty(Mono.defer(() -> fromQuery(exchange)));
    }

    private Mono<Authentication> fromQuery(ServerWebExchange exchange) {
        if (exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return Mono.empty();
        }
        boolean ssePath = ssePaths.stream().anyMatch(p -> p.matches(exchange.getRequest().getPath().pathWithinApplication()));
        String token = exchange.getRequest().getQueryParams().getFirst("token");
        if (!ssePath || !StringUtils.hasText(token)) {
            return Mono.empty();
        }
        return Mono.just(new BearerTokenAuthenticationToken(token));
    }
}
