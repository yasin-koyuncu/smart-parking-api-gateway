package com.parkview.gateway.config;

import com.parkview.gateway.web.EdgeHeadersWebFilter;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CorsConfigTest {

    private final GatewayProperties props = new GatewayProperties(List.of(), List.of("http://localhost:5173"), List.of(), false, Map.of());
    private final CorsConfigurationSource source = new CorsConfig().corsConfigurationSource(props);

    private MockServerWebExchange preflight(String origin) {
        return MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.OPTIONS, java.net.URI.create("http://localhost:8080/api/v1/sessions/plate/ABC123"))
                .header("Origin", origin)
                .header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", "authorization")
                .build());
    }

    @Test
    void allowedOriginPassesPreflightAndUnknownOriginIsRejected() {
        WebFilterChain chain = e -> Mono.empty();
        var ok = preflight("http://localhost:5173");
        new CorsWebFilter(source).filter(ok, chain).block();
        assertThat(ok.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ok.getResponse().getHeaders().getFirst("Access-Control-Allow-Origin")).isEqualTo("http://localhost:5173");

        var bad = preflight("https://evil.example");
        new CorsWebFilter(source).filter(bad, chain).block();
        assertThat(bad.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void preflightStillPassesAfterTheEdgeHeadersFilterMutatedTheRequest() {
        var exchange = preflight("http://localhost:5173");
        new EdgeHeadersWebFilter().filter(exchange, mutated ->
                new CorsWebFilter(source).filter(mutated, e -> Mono.empty())).block();
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
    }
}
