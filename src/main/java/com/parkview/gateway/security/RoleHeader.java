package com.parkview.gateway.security;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/** The value of the informational {@code X-User-Role} header: the highest role among the authorities. */
public final class RoleHeader {

    private RoleHeader() {
    }

    /** {@code admin} (implies operator), {@code operator}, otherwise {@code driver}. */
    public static String of(Collection<? extends GrantedAuthority> authorities) {
        if (has(authorities, "ROLE_ADMIN")) {
            return "admin";
        }
        return has(authorities, "ROLE_OPERATOR") ? "operator" : "driver";
    }

    private static boolean has(Collection<? extends GrantedAuthority> authorities, String role) {
        return authorities.stream().anyMatch(a -> role.equals(a.getAuthority()));
    }
}
