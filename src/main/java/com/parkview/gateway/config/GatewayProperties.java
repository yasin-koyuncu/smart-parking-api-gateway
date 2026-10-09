package com.parkview.gateway.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;

/**
 * Gateway behaviour that is configured rather than coded ({@code parkview.gateway.*}).
 *
 * @param rules          ordered authorisation rules; the first matching rule wins and
 *                       anything unmatched requires an authenticated user. The services enforce
 *                       roles and object ownership again (defence in depth); these rules keep
 *                       obviously unauthorised traffic away from them.
 * @param allowedOrigins browser origins allowed by CORS (the frontend)
 * @param sseTokenPaths  Ant patterns where a {@code ?token=} query parameter may carry the
 *                       bearer token (EventSource cannot set headers)
 * @param docsEnabled    expose the aggregated Swagger UI ({@code /swagger-ui.html}) - never in production
 * @param services       base URLs of the downstream services, used for the aggregated API docs routes
 */
@Validated
@ConfigurationProperties("parkview.gateway")
public record GatewayProperties(
        @DefaultValue @Valid List<Rule> rules,
        @DefaultValue List<String> allowedOrigins,
        @DefaultValue List<String> sseTokenPaths,
        @DefaultValue("false") boolean docsEnabled,
        @DefaultValue Map<String, String> services) {

    public enum Access {
        PUBLIC,
        AUTHENTICATED,
        OPERATOR,
        ADMIN
    }

    /**
     * @param paths   Ant patterns
     * @param methods HTTP methods the rule applies to; empty = all
     * @param access  required access level
     */
    public record Rule(
            @NotEmpty List<String> paths,
            @DefaultValue List<String> methods,
            @NotNull Access access) {
    }
}
