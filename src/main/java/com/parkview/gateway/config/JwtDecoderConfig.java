package com.parkview.gateway.config;

import com.parkview.gateway.security.AudienceValidator;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/** Verifies the Supabase JWT: ES256 signature through JWKS, issuer and audience. */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class JwtDecoderConfig {

    @Bean
    ReactiveJwtDecoder jwtDecoder(SecurityProperties props) {
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(props.resolvedJwksUri())
                .jwsAlgorithm(SignatureAlgorithm.ES256)
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(props.issuer()), new AudienceValidator(props.audience())));
        return decoder;
    }
}
