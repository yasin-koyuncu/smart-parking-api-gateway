package com.parkview.gateway.security;

import com.parkview.gateway.config.GatewayProperties;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;

import java.util.List;

/** Applies the declarative {@code parkview.gateway.rules} to the authorisation chain, in declaration order. */
public final class RuleAuthorizer {

    private RuleAuthorizer() {
    }

    public static void apply(AuthorizeExchangeSpec exchanges, List<GatewayProperties.Rule> rules) {
        for (GatewayProperties.Rule rule : rules) {
            String[] paths = rule.paths().toArray(String[]::new);
            if (rule.methods().isEmpty()) {
                require(rule, exchanges.pathMatchers(paths));
            } else {
                for (String method : rule.methods()) {
                    require(rule, exchanges.pathMatchers(HttpMethod.valueOf(method), paths));
                }
            }
        }
    }

    private static void require(GatewayProperties.Rule rule, AuthorizeExchangeSpec.Access spec) {
        switch (rule.access()) {
            case PUBLIC -> spec.permitAll();
            case AUTHENTICATED -> spec.authenticated();
            case OPERATOR -> spec.hasRole("OPERATOR");
            case ADMIN -> spec.hasRole("ADMIN");
            case PERMISSION -> spec.hasAuthority(rule.permission());
        }
    }
}
