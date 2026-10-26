package com.parkview.gateway.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.MessageSource;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Writes RFC 7807 {@code application/problem+json} bodies with the same members the services use
 * ({@code timestamp}, {@code requestId}, {@code message}) so every error that reaches a client looks alike.
 * The texts of the gateway's own errors are in the language of the {@code Accept-Language} header (see
 * {@link #writeLocalized}) and carry the stable {@code code} of the text.
 */
public final class ProblemResponses {

    private ProblemResponses() {
    }

    /** The text of {@code key} in {@code locale}, or {@code fallback} (English) when there is no entry. */
    public static String text(MessageSource messages, Locale locale, String key, String fallback) {
        String text = messages.getMessage(key, null, null, locale);
        return text != null ? text : fallback;
    }

    /**
     * Writes a problem whose title is {@code titleKey} and whose detail is {@code errorKey} of the error bundles, in the language of
     * the request; {@code errorKey} is also the stable {@code code} of the response. The English {@code title} and {@code detail}
     * stay the texts when the bundle has no entry.
     */
    public static Mono<Void> writeLocalized(ServerWebExchange exchange, ObjectMapper mapper, MessageSource messages, HttpStatus status,
                                            String titleKey, String title, String errorKey, String detail) {
        Locale locale = RequestLocales.of(exchange);
        return write(exchange, mapper, status, text(messages, locale, titleKey, title), text(messages, locale, errorKey, detail), errorKey);
    }

    public static Mono<Void> write(ServerWebExchange exchange, ObjectMapper mapper, HttpStatus status,
                                   String title, String detail) {
        return write(exchange, mapper, status, title, detail, null);
    }

    public static Mono<Void> write(ServerWebExchange exchange, ObjectMapper mapper, HttpStatus status,
                                   String title, String detail, String code) {
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
        if (code != null) {
            body.put("code", code);
        }

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
