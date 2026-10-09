package com.parkview.gateway.security;

import com.parkview.gateway.config.GatewayProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SseTokenBearerConverterTest {

    private final SseTokenBearerConverter converter = new SseTokenBearerConverter(
            new GatewayProperties(List.of(), List.of(), List.of("/api/v1/events/stream/**"), false, Map.of()));

    private static MockServerWebExchange exchange(MockServerHttpRequest.BaseBuilder<?> request) {
        return MockServerWebExchange.from(request.build());
    }

    @Test
    void headerTokenWorksEverywhere() {
        var auth = converter.convert(exchange(MockServerHttpRequest.get("/api/v1/sessions/zone/z1")
                .header("Authorization", "Bearer from-header"))).block();
        assertThat(auth).isInstanceOf(BearerTokenAuthenticationToken.class);
        assertThat(((BearerTokenAuthenticationToken) auth).getToken()).isEqualTo("from-header");
    }

    @Test
    void queryTokenIsAcceptedOnlyOnSseEndpoints() {
        var sse = converter.convert(exchange(MockServerHttpRequest.get("/api/v1/events/stream/driver?token=q-token"))).block();
        assertThat(((BearerTokenAuthenticationToken) sse).getToken()).isEqualTo("q-token");

        var other = converter.convert(exchange(MockServerHttpRequest.get("/api/v1/sessions/zone/z1?token=q-token"))).block();
        assertThat(other).as("a token in the URL of an ordinary endpoint must be ignored").isNull();
    }

    @Test
    void headerWinsOverQueryAndBlankQueryIsIgnored() {
        var both = converter.convert(exchange(MockServerHttpRequest.get("/api/v1/events/stream/driver?token=q-token")
                .header("Authorization", "Bearer from-header"))).block();
        assertThat(((BearerTokenAuthenticationToken) both).getToken()).isEqualTo("from-header");

        assertThat(converter.convert(exchange(MockServerHttpRequest.get("/api/v1/events/stream/driver?token="))).block()).isNull();
        assertThat(converter.convert(exchange(MockServerHttpRequest.get("/api/v1/events/stream/driver"))).block()).isNull();
    }
}
