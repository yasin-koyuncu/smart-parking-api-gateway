package com.parkview.gateway.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Writes RFC 7807 {@code application/problem+json} bodies with the same members the services use
 * ({@code timestamp}, {@code requestId}, {@code message}) so every error that reaches a client looks alike.
 */
public final class ProblemResponses {

    private ProblemResponses() {
    }

    public static Mono<Void> write(ServerWebExchange exchange, ObjectMapper mapper, HttpStatus status,
                                   String title, String detail) {
        if (exchange.getResponse().isCommitted()) {
            return Mono.empty();
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "about:blank");
        body.put("title", title);
        body.put("status", status.value());
        body.put("detail", detail);
        body.put("timestamp", Instant.now().toString());
        Object requestId = exchange.getAttribute(EdgeHeadersWebFilter.REQUEST_ID_ATTRIBUTE);
        if (requestId != null) {
            body.put("requestId", requestId);
        }
        body.put("message", detail);

        byte[] bytes;
        try {
            bytes = mapper.writeValueAsBytes(body);
        } catch (JsonProcessingException e) {
            bytes = ("{\"status\":" + status.value() + "}").getBytes(StandardCharsets.UTF_8);
        }
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
