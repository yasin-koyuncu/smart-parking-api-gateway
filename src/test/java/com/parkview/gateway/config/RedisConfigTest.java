package com.parkview.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The rate-limit key of an anonymous call: the client address as far as {@code trusted-proxies} allows, nothing a client can choose. */
class RedisConfigTest {

    private static final String SOCKET = "10.0.0.5";

    private static ServerWebExchange exchange(String remote, String... forwardedForHeaders) throws UnknownHostException {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/api/v1/auth/login");
        if (remote != null) {
            request.remoteAddress(new InetSocketAddress(InetAddress.getByName(remote), 4711));
        }
        for (String header : forwardedForHeaders) {
            request.header("X-Forwarded-For", header);
        }
        return MockServerWebExchange.from(request);
    }

    private static String key(int trustedProxies, ServerWebExchange exchange) {
        return RedisConfig.clientAddress(RedisConfig.remoteAddressResolver(trustedProxies), exchange);
    }

    @Test
    void noTrustedProxyUsesTheSocketAddressAndIgnoresXForwardedFor() throws Exception {
        assertThat(key(0, exchange(SOCKET))).isEqualTo(SOCKET);
        assertThat(key(0, exchange(SOCKET, "203.0.113.7"))).isEqualTo(SOCKET);
        assertThat(key(0, exchange(SOCKET, "203.0.113.7, 198.51.100.9"))).isEqualTo(SOCKET);
    }

    @Test
    void oneTrustedProxyTakesTheLastEntryTheProxyAppended() throws Exception {
        assertThat(key(1, exchange(SOCKET, "203.0.113.7"))).isEqualTo("203.0.113.7");
        assertThat(key(1, exchange(SOCKET, "198.51.100.1, 203.0.113.7"))).isEqualTo("203.0.113.7");
    }

    @Test
    void aSpoofedLeadingXForwardedForEntryDoesNotChangeTheKey() throws Exception {
        // the client wrote "1.2.3.4" and the trusted proxy appended the address it really saw
        String honest = key(1, exchange(SOCKET, "203.0.113.7"));
        assertThat(key(1, exchange(SOCKET, "1.2.3.4, 203.0.113.7"))).isEqualTo(honest);
        assertThat(key(1, exchange(SOCKET, "5.6.7.8, 1.2.3.4, 203.0.113.7"))).isEqualTo(honest);
        // and with nobody trusted the spoofed value is never even looked at
        assertThat(key(0, exchange(SOCKET, "1.2.3.4"))).isEqualTo(key(0, exchange(SOCKET)));
    }

    @Test
    void twoTrustedProxiesSkipTheInnerProxyAddress() throws Exception {
        // the client wrote "1.2.3.4", the outer proxy appended the client's real address, the inner proxy appended the outer proxy
        assertThat(key(2, exchange(SOCKET, "1.2.3.4, 203.0.113.7, 10.1.1.1"))).isEqualTo("203.0.113.7");
    }

    @Test
    void withoutTheHeaderOrWithSeveralHeadersTheSocketAddressIsUsed() throws Exception {
        assertThat(key(1, exchange(SOCKET))).isEqualTo(SOCKET);
        assertThat(key(1, exchange(SOCKET, "1.2.3.4", "5.6.7.8"))).isEqualTo(SOCKET);
    }

    @Test
    void theLiteralUnknownBucketIsUsedOnlyWhenNoAddressCanBeResolved() throws Exception {
        assertThat(key(0, exchange(null))).isEqualTo("unknown");
        assertThat(key(1, exchange(null))).isEqualTo("unknown");
        assertThat(key(1, exchange(null, "203.0.113.7"))).isEqualTo("203.0.113.7");
    }

    @Test
    void theKeyResolverBeanKeysAnonymousCallsOnTheResolvedAddress() throws Exception {
        GatewayProperties gateway = new GatewayProperties(null, null, null, false, null, 1);
        KeyResolver resolver = new RedisConfig().principalOrIpKeyResolver(gateway);
        assertThat(resolver.resolve(exchange(SOCKET, "1.2.3.4, 203.0.113.7")).block()).isEqualTo("203.0.113.7");
    }

    @Test
    void aNegativeNumberOfProxiesIsRejectedByTheResolverFactory() {
        assertThatThrownBy(() -> RedisConfig.remoteAddressResolver(-1)).isInstanceOf(IllegalArgumentException.class);
    }
}
