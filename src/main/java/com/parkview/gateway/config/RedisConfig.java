package com.parkview.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Principal;

/** Rate-limit key resolution for the {@code RequestRateLimiter} route filter. */
@Configuration
public class RedisConfig {

    /**
     * Rate-limit key: the authenticated user, otherwise the client IP. Without a custom resolver
     * Spring uses the principal name only, which is empty for anonymous calls (cameras, login) and
     * makes {@code RequestRateLimiter} answer 403.
     */
    @Bean
    public KeyResolver principalOrIpKeyResolver() {
        return exchange -> exchange.getPrincipal()
                .map(Principal::getName)
                .switchIfEmpty(Mono.fromSupplier(() -> clientIp(exchange)));
    }

    static String clientIp(ServerWebExchange exchange) {
        String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        var remote = exchange.getRequest().getRemoteAddress();
        return remote != null && remote.getAddress() != null ? remote.getAddress().getHostAddress() : "unknown";
    }
}
