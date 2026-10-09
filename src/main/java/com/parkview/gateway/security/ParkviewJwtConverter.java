package com.parkview.gateway.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Maps the Supabase claim {@code app_metadata.role} (admin | operator | driver) to {@code ROLE_*}
 * authorities. ADMIN implies OPERATOR (same hierarchy as in the services).
 */
public final class ParkviewJwtConverter {

    private ParkviewJwtConverter() {
    }

    public static ReactiveJwtAuthenticationConverter create() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities());
        return converter;
    }

    static Converter<Jwt, Flux<GrantedAuthority>> authorities() {
        return jwt -> Flux.fromIterable(roles(jwt));
    }

    static List<GrantedAuthority> roles(Jwt jwt) {
        List<GrantedAuthority> result = new ArrayList<>();
        Map<String, Object> appMetadata = jwt.getClaimAsMap("app_metadata");
        Object role = appMetadata == null ? null : appMetadata.get("role");
        if (role == null) {
            return result;
        }
        switch (role.toString().trim().toUpperCase(Locale.ROOT)) {
            case "ADMIN" -> {
                result.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                result.add(new SimpleGrantedAuthority("ROLE_OPERATOR"));
            }
            case "OPERATOR" -> result.add(new SimpleGrantedAuthority("ROLE_OPERATOR"));
            case "DRIVER" -> result.add(new SimpleGrantedAuthority("ROLE_DRIVER"));
            default -> {
                // unknown role: no authority, the request is authenticated but not authorised for role rules
            }
        }
        return result;
    }
}
