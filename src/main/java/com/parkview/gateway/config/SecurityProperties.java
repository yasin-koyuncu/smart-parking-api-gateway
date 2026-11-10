package com.parkview.gateway.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Same property names as every other service ({@code parkview.security.*}).
 *
 * @param issuer         expected JWT issuer, {@code <SUPABASE_URL>/auth/v1}
 * @param jwksUri        JWKS endpoint; defaults to {@code <issuer>/.well-known/jwks.json}
 * @param audience       required {@code aud} claim
 * @param internalApiKey key that protects this gateway's own {@code /actuator/prometheus} (the AI route uses {@code AI_DETECTION_INTERNAL_API_KEY} instead);
 *                       blank disables those features
 */
@Validated
@ConfigurationProperties("parkview.security")
public record SecurityProperties(
        @NotBlank String issuer,
        String jwksUri,
        @DefaultValue("authenticated") String audience,
        String internalApiKey) {

    public String resolvedJwksUri() {
        return jwksUri == null || jwksUri.isBlank() ? issuer + "/.well-known/jwks.json" : jwksUri;
    }

    public boolean internalApiEnabled() {
        return internalApiKey != null && !internalApiKey.isBlank();
    }
}
