package com.parkview.gateway.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Keeps {@link Permissions} identical to {@code smart-parking-e2e/contracts/permissions.json}. Skipped when the e2e repo
 * is not checked out next to this one (CI builds of a single repository).
 */
class PermissionsContractTest {

    private static final Path CONTRACT = Path.of("..", "smart-parking-e2e", "contracts", "permissions.json");

    @Test
    void catalogueAndRoleDefaultsMatchTheContract() throws IOException {
        assumeTrue(Files.exists(CONTRACT), "e2e contract not checked out next to this repository");
        JsonNode contract = new ObjectMapper().readTree(Files.readString(CONTRACT));

        Set<String> names = new HashSet<>();
        contract.get("permissions").fieldNames().forEachRemaining(names::add);
        assertThat(Permissions.ALL).isEqualTo(names);

        for (String role : new String[]{"admin", "operator", "driver"}) {
            Set<String> defaults = new HashSet<>();
            contract.get("defaultsByRole").get(role).forEach(n -> defaults.add(n.asText()));
            assertThat(Permissions.DEFAULTS_BY_ROLE.get(role)).as("defaults of " + role).isEqualTo(defaults);
        }
    }
}
