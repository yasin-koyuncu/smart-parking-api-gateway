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
 * Maps the Supabase claims to authorities:
 * <ul>
 *   <li>{@code app_metadata.role} (admin | operator | driver) to {@code ROLE_*}; ADMIN implies OPERATOR
 *       (same hierarchy as in the services)</li>
 *   <li>{@code app_metadata.permissions} (string[]) to one authority per permission, named exactly like the
 *       permission ({@code zone:write})</li>
 * </ul>
 * Tokens minted before permissions existed have no {@code permissions} claim: while the legacy fallback is on
 * the defaults of the role are granted instead. A claim that is present, even empty, is never supplemented.
 */
public final class ParkviewJwtConverter {

    private ParkviewJwtConverter() {
    }

    public static ReactiveJwtAuthenticationConverter create(boolean legacyRoleFallback) {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities(legacyRoleFallback));
        return converter;
    }

    static Converter<Jwt, Flux<GrantedAuthority>> authorities(boolean legacyRoleFallback) {
        return jwt -> {
            List<GrantedAuthority> result = new ArrayList<>(roles(jwt));
            result.addAll(permissions(jwt, legacyRoleFallback));
            return Flux.fromIterable(result);
        };
    }

    static List<GrantedAuthority> roles(Jwt jwt) {
        List<GrantedAuthority> result = new ArrayList<>();
        Object role = appMetadata(jwt).get("role");
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

    static List<GrantedAuthority> permissions(Jwt jwt, boolean legacyRoleFallback) {
        Map<String, Object> appMetadata = appMetadata(jwt);
        List<GrantedAuthority> result = new ArrayList<>();
        if (appMetadata.containsKey("permissions")) {
            // present (even empty or malformed) means the token is authoritative: no fallback
            if (appMetadata.get("permissions") instanceof List<?> granted) {
                granted.stream()
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .filter(p -> !p.isBlank())
                        .distinct()   // exact names, no trimming or case folding
                        .forEach(p -> result.add(new SimpleGrantedAuthority(p)));
            }
        } else if (legacyRoleFallback && appMetadata.get("role") != null) {
            Permissions.defaultsFor(appMetadata.get("role").toString()).stream().sorted()
                    .forEach(p -> result.add(new SimpleGrantedAuthority(p)));
        }
        return result;
    }

    private static Map<String, Object> appMetadata(Jwt jwt) {
        Map<String, Object> appMetadata = jwt.getClaimAsMap("app_metadata");
        return appMetadata == null ? Map.of() : appMetadata;
    }
}
