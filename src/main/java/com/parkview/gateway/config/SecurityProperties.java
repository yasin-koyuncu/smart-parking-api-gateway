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
 * @param internalApiKey shared secret presented to internal endpoints (actuator metrics, AI service);
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
