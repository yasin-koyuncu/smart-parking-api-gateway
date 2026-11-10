package com.parkview.gateway.security;

import java.util.List;
import java.util.Set;

/**
 * The permission catalogue. Mirrors {@code contracts/permissions.json} of the e2e repo (the single source of
 * truth, see ADR 0002); {@code PermissionsContractTest} fails when they drift.
 */
public final class Permissions {

    // BEGIN GENERATED permissions (contracts/permissions.json in smart-parking-e2e; do not edit)
    /** Every permission the gateway knows; a rule naming anything else fails the startup. */
    public static final Set<String> ALL = Set.of(
            "zone:read", "zone:write", "spot:read", "spot:write", "session:read", "session:manage", "session:correct",
            "violation:read", "violation:resolve", "fine:read", "fine:manage", "permit:read", "permit:manage",
            "lookup:vehicle", "file:upload", "file:view", "stream:operator", "camera:read", "camera:admin", "ai:use",
            "access:read", "access:manage", "role:manage");
    // END GENERATED permissions

    private Permissions() {
    }

    public static boolean isKnown(String permission) {
        return permission != null && ALL.contains(permission);
    }

    /** For messages: the catalogue in a stable order. */
    public static List<String> sorted() {
        return ALL.stream().sorted().toList();
    }
}
