package com.parkview.gateway.web;

import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * The language of a caller of the gateway: the first language of the {@code Accept-Language} header by weight, English when the
 * header is missing, empty or malformed. Never the language of the server. (Reactive: no servlet classes, the exchange's own locale
 * context would fall back to the default locale of the JVM.)
 */
public final class RequestLocales {

    private RequestLocales() {
    }

    public static Locale of(ServerWebExchange exchange) {
        return fromHeader(exchange.getRequest().getHeaders().getFirst(HttpHeaders.ACCEPT_LANGUAGE));
    }

    static Locale fromHeader(String header) {
        if (header == null || header.isBlank()) {
            return Locale.ENGLISH;
        }
        try {
            List<Locale.LanguageRange> ranges = Locale.LanguageRange.parse(header).stream()
                    .sorted(Comparator.comparingDouble(Locale.LanguageRange::getWeight).reversed()).toList();
            for (Locale.LanguageRange range : ranges) {
                String tag = range.getRange();
                if (range.getWeight() > 0 && !"*".equals(tag)) {
                    Locale locale = Locale.forLanguageTag(tag);
                    if (!locale.getLanguage().isEmpty()) {
                        return locale;
                    }
                }
            }
        } catch (IllegalArgumentException malformed) {
            // an unusable header is the same as none
        }
        return Locale.ENGLISH;
    }
}
