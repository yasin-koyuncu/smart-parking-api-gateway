package com.parkview.gateway.security;

import com.parkview.gateway.config.GatewayProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Reads the bearer token from the Authorization header and - only for the configured SSE paths - from
 * the {@code ?token=} query parameter. Browsers' {@code EventSource} cannot send headers, and this has to
 * happen inside the security chain (a gateway route filter runs too late for authentication).
 */
public class SseTokenBearerConverter implements ServerAuthenticationConverter {

    private final ServerBearerTokenAuthenticationConverter headerConverter = new ServerBearerTokenAuthenticationConverter();
    private final SseTokenPaths ssePaths;

    public SseTokenBearerConverter(GatewayProperties properties) {
        this.ssePaths = new SseTokenPaths(properties);
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
        return ssePaths.tokenOf(exchange.getRequest())
                .<Authentication>map(BearerTokenAuthenticationToken::new)
                .map(Mono::just)
                .orElseGet(Mono::empty);
    }
}
