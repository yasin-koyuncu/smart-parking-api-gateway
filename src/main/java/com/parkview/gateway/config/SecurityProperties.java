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
 * @param legacyRoleFallback while true, a token without {@code app_metadata.permissions} gets the default
 *                       permissions of its role (rollout of ADR 0002); a token that has the claim, even
 *                       empty, is never supplemented
 */
@Validated
@ConfigurationProperties("parkview.security")
public record SecurityProperties(
        @NotBlank String issuer,
        String jwksUri,
        @DefaultValue("authenticated") String audience,
        String internalApiKey,
        @DefaultValue("true") boolean legacyRoleFallback) {

    public String resolvedJwksUri() {
        return jwksUri == null || jwksUri.isBlank() ? issuer + "/.well-known/jwks.json" : jwksUri;
    }

    public boolean internalApiEnabled() {
        return internalApiKey != null && !internalApiKey.isBlank();
    }
}
