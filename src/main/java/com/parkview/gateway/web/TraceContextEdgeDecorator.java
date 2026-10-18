package com.parkview.gateway.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.HttpHandlerDecoratorFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.server.adapter.HttpWebHandlerAdapter;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import java.util.List;

/**
 * Public edge of the platform: drops the W3C trace headers a caller sent, so the gateway starts every trace itself.
 * Otherwise anyone on the internet could join (and, with the sampled flag, force the recording of) traces in the
 * platform. Set {@code TRACING_TRUST_INCOMING=true} when the gateway sits behind a trusted tracing proxy.
 *
 * <p>This is an {@code HttpHandler} decorator and not a {@code WebFilter} on purpose: WebFlux opens the server
 * observation (and reads {@code traceparent}) in {@link HttpWebHandlerAdapter}, before any web filter runs.
 * {@link WebHttpHandlerBuilder} applies decorator factories around that adapter.
 *
 * <p>Only exists while tracing is on; with tracing off the headers are forwarded untouched, as they always were.
 */
@Component
@ConditionalOnProperty(name = "management.tracing.enabled", havingValue = "true")
public class TraceContextEdgeDecorator implements HttpHandlerDecoratorFactory {

    static final List<String> TRACE_HEADERS = List.of("traceparent", "tracestate", "baggage");

    private final boolean trustIncoming;

    public TraceContextEdgeDecorator(@Value("${parkview.tracing.trust-incoming-context:false}") boolean trustIncoming) {
        this.trustIncoming = trustIncoming;
    }

    @Override
    public HttpHandler apply(HttpHandler handler) {
        return (request, response) -> {
            HttpHeaders headers = request.getHeaders();
            if (trustIncoming || TRACE_HEADERS.stream().noneMatch(headers::containsKey)) {
                return handler.handle(request, response);
            }
            return handler.handle(request.mutate().headers(h -> TRACE_HEADERS.forEach(h::remove)).build(), response);
        };
    }
}
