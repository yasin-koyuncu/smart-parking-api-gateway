package com.parkview.gateway.security;

import com.parkview.gateway.config.GatewayProperties;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.List;
import java.util.Optional;

/**
 * The paths ({@code parkview.gateway.sse-token-paths}) on which a {@code ?token=} query parameter may carry the
 * bearer token. Shared by the authentication converter and the forwarding filter so both agree on what counts as
 * an SSE token.
 */
public final class SseTokenPaths {

    private static final String TOKEN_PARAM = "token";

    private final List<PathPattern> patterns;

    public SseTokenPaths(GatewayProperties properties) {
        PathPatternParser parser = new PathPatternParser();
        this.patterns = properties.sseTokenPaths().stream().map(parser::parse).toList();
    }

    /** The {@code ?token=} value, only when the request path is an SSE path and the value is not blank. */
    public Optional<String> tokenOf(ServerHttpRequest request) {
        boolean ssePath = patterns.stream().anyMatch(p -> p.matches(request.getPath().pathWithinApplication()));
        String token = request.getQueryParams().getFirst(TOKEN_PARAM);
        return ssePath && StringUtils.hasText(token) ? Optional.of(token) : Optional.empty();
    }
}
