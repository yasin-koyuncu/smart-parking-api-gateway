package com.parkview.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.support.ipresolver.RemoteAddressResolver;
import org.springframework.cloud.gateway.support.ipresolver.XForwardedRemoteAddressResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.security.Principal;

/** Rate-limit key resolution for the {@code RequestRateLimiter} route filter. */
@Configuration
public class RedisConfig {

    static final String UNKNOWN_CLIENT = "unknown";

    /**
     * Rate-limit key: the authenticated user, otherwise the client address. Without a custom resolver
     * Spring uses the principal name only, which is empty for anonymous calls (cameras, login) and
     * makes {@code RequestRateLimiter} answer 403. The client address honours {@code X-Forwarded-For} only as far as
     * {@code parkview.gateway.trusted-proxies} says (see {@link #remoteAddressResolver(int)}).
     */
    @Bean
    public KeyResolver principalOrIpKeyResolver(GatewayProperties gateway) {
        RemoteAddressResolver addresses = remoteAddressResolver(gateway.trustedProxies());
        return exchange -> exchange.getPrincipal()
                .map(Principal::getName)
                .switchIfEmpty(Mono.fromSupplier(() -> clientAddress(addresses, exchange)));
    }

    /**
     * {@code 0}: the socket address, {@code X-Forwarded-For} is ignored. {@code n >= 1}: the address {@code n} hops from
     * the right of {@code X-Forwarded-For} (each trusted proxy appends the address it received the call from, so the
     * entries a client wrote itself are to the left of it and never chosen); without the header, or with several
     * {@code X-Forwarded-For} headers, the socket address.
     */
    static RemoteAddressResolver remoteAddressResolver(int trustedProxies) {
        return trustedProxies == 0 ? new RemoteAddressResolver() { } : XForwardedRemoteAddressResolver.maxTrustedIndex(trustedProxies);
    }

    static String clientAddress(RemoteAddressResolver addresses, ServerWebExchange exchange) {
        InetSocketAddress resolved = addresses.resolve(exchange);
        if (resolved == null) {
            return UNKNOWN_CLIENT;
        }
        if (resolved.getAddress() != null) {
            return resolved.getAddress().getHostAddress();
        }
        String host = resolved.getHostString();
        return host == null || host.isBlank() ? UNKNOWN_CLIENT : host;
    }
}
