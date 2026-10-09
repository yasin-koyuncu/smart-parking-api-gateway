package com.parkview.gateway.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.handler.timeout.ReadTimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.util.concurrent.TimeoutException;

/**
 * Turns gateway-level failures (no such route, upstream down, upstream too slow) into the platform's
 * problem+json instead of Spring's default error page, without leaking hostnames or stack traces.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GatewayErrorHandler implements ErrorWebExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GatewayErrorHandler.class);

    private final ObjectMapper mapper;

    public GatewayErrorHandler(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        HttpStatusCode status = statusFor(ex);
        HttpStatus http = HttpStatus.valueOf(status.value());

        if (http.is5xxServerError()) {
            log.warn("Gateway error {} for requestId={}: {}",
                    http.value(), exchange.getAttribute(EdgeHeadersWebFilter.REQUEST_ID_ATTRIBUTE), ex.toString());
        }
        return ProblemResponses.write(exchange, mapper, http, title(http), detail(http));
    }

    private static HttpStatusCode statusFor(Throwable ex) {
        Throwable cause = ex;
        while (cause != null) {
            if (cause instanceof ResponseStatusException rse) {
                return rse.getStatusCode();
            }
            if (cause instanceof TimeoutException || cause instanceof ReadTimeoutException) {
                return HttpStatus.GATEWAY_TIMEOUT;
            }
            if (cause instanceof ConnectException || cause.getClass().getName().contains("ConnectTimeout")
                    || cause.getClass().getName().contains("PrematureClose")) {
                return HttpStatus.BAD_GATEWAY;
            }
            cause = cause.getCause() == cause ? null : cause.getCause();
        }
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    private static String title(HttpStatus status) {
        return switch (status) {
            case NOT_FOUND -> "Not found";
            case BAD_GATEWAY -> "Bad gateway";
            case GATEWAY_TIMEOUT -> "Gateway timeout";
            case SERVICE_UNAVAILABLE -> "Service unavailable";
            default -> status.getReasonPhrase();
        };
    }

    private static String detail(HttpStatus status) {
        return switch (status) {
            case NOT_FOUND -> "No route matches this request";
            case BAD_GATEWAY, SERVICE_UNAVAILABLE -> "The upstream service is currently unavailable";
            case GATEWAY_TIMEOUT -> "The upstream service did not answer in time";
            default -> status.is5xxServerError() ? "An unexpected error occurred" : status.getReasonPhrase();
        };
    }
}
