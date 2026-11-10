package com.parkview.gateway.config;

import com.parkview.gateway.security.Permissions;
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
 *                       anything unmatched is denied (a path open to every signed-in user needs an explicit
 *                       {@code AUTHENTICATED} rule). The services enforce
 *                       roles and object ownership again (defence in depth); these rules keep
 *                       obviously unauthorised traffic away from them.
 * @param allowedOrigins browser origins allowed by CORS (the frontend)
 * @param sseTokenPaths  Ant patterns where a {@code ?token=} query parameter may carry the
 *                       bearer token (EventSource cannot set headers)
 * @param docsEnabled    expose the aggregated Swagger UI ({@code /swagger-ui.html}) - never in production
 * @param services       base URLs of the downstream services, used for the aggregated API docs routes
 * @param trustedProxies required, no default (the infrastructure decides): the number of reverse proxies / load
 *                       balancers between the internet and this gateway. {@code 0} = nobody: {@code X-Forwarded-For}
 *                       is ignored and the rate-limit key is the socket address; {@code n >= 1} = the address
 *                       {@code n} hops from the right of {@code X-Forwarded-For} is the client. Too low and every
 *                       client shares the proxy's bucket; too high and a client can pick its own bucket.
 */
@Validated
@ConfigurationProperties("parkview.gateway")
public record GatewayProperties(
        @DefaultValue @Valid List<Rule> rules,
        @DefaultValue List<String> allowedOrigins,
        @DefaultValue List<String> sseTokenPaths,
        @DefaultValue("false") boolean docsEnabled,
        @DefaultValue Map<String, String> services,
        Integer trustedProxies) {

    public GatewayProperties {
        if (trustedProxies == null || trustedProxies < 0) {
            throw new IllegalArgumentException("parkview.gateway.trusted-proxies (GATEWAY_TRUSTED_PROXIES) must be set to an integer >= 0: "
                    + "the number of reverse proxies in front of the gateway (0 = none, X-Forwarded-For is ignored); got " + trustedProxies);
        }
    }

    public enum Access {
        PUBLIC,
        AUTHENTICATED,
        OPERATOR,
        ADMIN,
        /** the authority named by {@link Rule#permission()}, e.g. {@code zone:write} */
        PERMISSION
    }

    /**
     * @param paths      Ant patterns
     * @param methods    HTTP methods the rule applies to; empty = all
     * @param access     required access level
     * @param permission required permission, only with {@code access: PERMISSION} (and then mandatory). Must be in
     *                   the catalogue ({@link Permissions}); an unknown name fails the startup instead of silently
     *                   guarding nothing or locking everyone out
     */
    public record Rule(
            @NotEmpty List<String> paths,
            @DefaultValue List<String> methods,
            @NotNull Access access,
            String permission) {

        public Rule {
            if (access == Access.PERMISSION) {
                if (!Permissions.isKnown(permission)) {
                    throw new IllegalArgumentException("Rule " + paths + " requires permission '" + permission
                            + "', which is not one of " + Permissions.sorted());
                }
            } else if (permission != null && !permission.isBlank()) {
                throw new IllegalArgumentException("Rule " + paths + " sets permission '" + permission
                        + "' but access is " + access + "; use access: PERMISSION");
            }
        }
    }
}
