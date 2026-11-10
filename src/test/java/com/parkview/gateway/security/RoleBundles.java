package com.parkview.gateway.security;

import java.util.Locale;
import java.util.Set;

/**
 * Test fixture: the permissions the token hook puts into a token of the generic staff bundles (the built-in access
 * roles {@code admin} and {@code operator}). Written out on purpose: the gateway holds no per-role table in its main code.
 * {@code PermissionsContractTest} keeps these sets equal to {@code defaultsByRole} of the e2e contract.
 */
public final class RoleBundles {

    public static final Set<String> ADMIN = Permissions.ALL;

    public static final Set<String> OPERATOR = Set.of(
            "zone:read", "spot:read", "spot:write", "session:read", "session:manage", "violation:read", "violation:resolve",
            "fine:read", "permit:read", "permit:manage", "lookup:vehicle", "file:upload", "file:view", "stream:operator",
            "camera:read", "camera:admin", "ai:use");

    private RoleBundles() {
    }

    /** The bundle of a base role; a driver holds none. */
    public static Set<String> of(String role) {
        return switch (role.trim().toLowerCase(Locale.ROOT)) {
            case "admin" -> ADMIN;
            case "operator" -> OPERATOR;
            default -> Set.of();
        };
    }
}
