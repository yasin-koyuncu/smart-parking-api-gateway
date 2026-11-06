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
 * @param legacyRoleFallback off by default. While true, a token without {@code app_metadata.permissions} gets the
 *                       default permissions of its role (rollout of ADR 0002); a token that has the claim, even
 *                       empty, is never supplemented. The token hook always writes the claim, so a token without it
 *                       is authorised for nothing that needs a permission
 */
@Validated
@ConfigurationProperties("parkview.security")
public record SecurityProperties(
        @NotBlank String issuer,
        String jwksUri,
        @DefaultValue("authenticated") String audience,
        String internalApiKey,
        @DefaultValue("false") boolean legacyRoleFallback) {

    public String resolvedJwksUri() {
        return jwksUri == null || jwksUri.isBlank() ? issuer + "/.well-known/jwks.json" : jwksUri;
    }

    public boolean internalApiEnabled() {
        return internalApiKey != null && !internalApiKey.isBlank();
    }
}
