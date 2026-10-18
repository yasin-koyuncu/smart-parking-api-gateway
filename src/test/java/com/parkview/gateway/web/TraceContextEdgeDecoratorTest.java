package com.parkview.gateway.web;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class TraceContextEdgeDecoratorTest {

    private static final String TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    private static HttpHeaders seenByTheGateway(TraceContextEdgeDecorator decorator) {
        var request = MockServerHttpRequest.get("/api/v1/zones")
                .header("traceparent", TRACEPARENT).header("tracestate", "a=b").header("baggage", "k=v")
                .header("X-Request-Id", "req-1").build();
        AtomicReference<HttpHeaders> seen = new AtomicReference<>();
        decorator.apply((req, res) -> {
            seen.set(req.getHeaders());
            return Mono.empty();
        }).handle(request, new MockServerHttpResponse()).block();
        return seen.get();
    }

    @Test
    void callerSuppliedTraceHeadersAreDroppedAtTheEdge() {
        var headers = seenByTheGateway(new TraceContextEdgeDecorator(false));
        assertThat(headers.containsKey("traceparent")).isFalse();
        assertThat(headers.containsKey("tracestate")).isFalse();
        assertThat(headers.containsKey("baggage")).isFalse();
        assertThat(headers.getFirst("X-Request-Id")).isEqualTo("req-1");
    }

    @Test
    void behindATrustedProxyTheHeadersAreKept() {
        var headers = seenByTheGateway(new TraceContextEdgeDecorator(true));
        assertThat(headers.getFirst("traceparent")).isEqualTo(TRACEPARENT);
    }
}
