package com.parkview.gateway.security;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The permission catalogue and the per-role defaults. Mirrors {@code contracts/permissions.json} of the e2e
 * repo (the single source of truth, see ADR 0002); {@code PermissionsContractTest} fails when they drift.
 * The defaults are only used while {@code parkview.security.legacy-role-fallback} is on and a token has no
 * {@code app_metadata.permissions} claim.
 */
public final class Permissions {

    // BEGIN GENERATED permissions (contracts/permissions.json in smart-parking-e2e; do not edit)
    private static final Set<String> OPERATOR = Set.of(
            "mapping:view", "spot:write", "session:read", "session:manage", "violation:read", "violation:resolve",
            "permit:manage", "lookup:vehicle", "file:upload", "file:view", "stream:operator", "camera:admin", "ai:use");

    /** Every permission the gateway knows; a rule naming anything else fails the startup. */
    public static final Set<String> ALL = Set.of(
            "mapping:view", "zone:write", "spot:write", "session:read", "session:manage", "session:correct",
            "violation:read", "violation:resolve", "fine:manage", "permit:manage", "lookup:vehicle", "file:upload",
            "file:view", "stream:operator", "camera:admin", "ai:use", "access:read", "access:manage");

    /** Keyed by lower-case role name (admin | operator | driver). */
    public static final Map<String, Set<String>> DEFAULTS_BY_ROLE = Map.of(
            "admin", ALL,
            "operator", OPERATOR,
            "driver", Set.of());
    // END GENERATED permissions

    private Permissions() {
    }

    public static boolean isKnown(String permission) {
        return permission != null && ALL.contains(permission);
    }

    public static Set<String> defaultsFor(String role) {
        return role == null ? Set.of() : DEFAULTS_BY_ROLE.getOrDefault(role.trim().toLowerCase(Locale.ROOT), Set.of());
    }

    /** For messages: the catalogue in a stable order. */
    public static List<String> sorted() {
        return ALL.stream().sorted().toList();
    }
}
