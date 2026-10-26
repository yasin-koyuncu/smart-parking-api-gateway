package com.parkview.gateway.web;

import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.nio.charset.StandardCharsets;

/**
 * The texts of the errors that the gateway writes itself (401, 403, no route, upstream down or too slow).
 * {@code messages/errors.properties} is the English base and is complete; {@code errors_sv.properties} (and any other language) holds
 * the translations; a region file ({@code errors_sv_SE}) only what differs. The language is the one of the {@code Accept-Language}
 * header ({@link RequestLocales}); an unknown language gets the English base, never the server's own language. Logs stay English.
 */
@Configuration
public class ErrorMessagesConfig {

    @Bean("errorMessages")
    MessageSource errorMessages() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("messages/errors");
        source.setDefaultEncoding(StandardCharsets.UTF_8.name());
        source.setFallbackToSystemLocale(false);
        return source;
    }
}
