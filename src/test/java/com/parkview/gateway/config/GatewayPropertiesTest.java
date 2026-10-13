package com.parkview.gateway.config;

import com.parkview.gateway.config.GatewayProperties.Access;
import com.parkview.gateway.security.Permissions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.PropertySourcesPlaceholdersResolver;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The declarative rules: permission rules are validated when the properties bind, i.e. at startup. */
class GatewayPropertiesTest {

    private static GatewayProperties bind(Map<String, Object> properties) {
        MutablePropertySources sources = new MutablePropertySources();
        sources.addFirst(new MapPropertySource("test", properties));
        return new Binder(ConfigurationPropertySources.from(sources)).bind("parkview.gateway", GatewayProperties.class).get();
    }

    private static Map<String, Object> rule(String access, String permission) {
        Map<String, Object> props = new HashMap<>(Map.of(
                "parkview.gateway.rules[0].paths[0]", "/api/v1/x/**",
                "parkview.gateway.rules[0].access", access));
        if (permission != null) {
            props.put("parkview.gateway.rules[0].permission", permission);
        }
        return props;
    }

    @Test
    void aPermissionRuleBindsWithItsPermission() {
        GatewayProperties.Rule rule = bind(rule("PERMISSION", "zone:write")).rules().get(0);
        assertThat(rule.access()).isEqualTo(Access.PERMISSION);
        assertThat(rule.permission()).isEqualTo("zone:write");
    }

    @Test
    void existingRoleRulesKeepWorkingWithoutAPermission() {
        assertThat(bind(rule("OPERATOR", null)).rules().get(0).permission()).isNull();
        assertThat(bind(rule("PUBLIC", null)).rules().get(0).access()).isEqualTo(Access.PUBLIC);
    }

    @Test
    void anUnknownPermissionFailsTheStartup() {
        assertThatThrownBy(() -> bind(rule("PERMISSION", "zone:wrtie")))
                .isInstanceOf(BindException.class)
                .hasStackTraceContaining("zone:wrtie");
    }

    @Test
    void aPermissionRuleWithoutAPermissionOrAPermissionOnAnotherAccessTypeFails() {
        assertThatThrownBy(() -> bind(rule("PERMISSION", null))).isInstanceOf(BindException.class);
        assertThatThrownBy(() -> bind(rule("OPERATOR", "ai:use"))).isInstanceOf(BindException.class);
    }

    @Test
    void theShippedApplicationYmlBindsAndEveryRuleNamesAKnownPermission() throws IOException {
        MutablePropertySources sources = new MutablePropertySources();
        new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yml")).forEach(sources::addLast);
        GatewayProperties props = new Binder(ConfigurationPropertySources.from(sources), new PropertySourcesPlaceholdersResolver(sources))
                .bind("parkview.gateway", GatewayProperties.class).get();

        List<GatewayProperties.Rule> permissionRules = props.rules().stream().filter(r -> r.access() == Access.PERMISSION).toList();
        assertThat(permissionRules).isNotEmpty().allSatisfy(r -> assertThat(Permissions.isKnown(r.permission())).isTrue());
        // the operator/admin functions are all migrated to permissions
        assertThat(props.rules()).noneMatch(r -> r.access() == Access.OPERATOR || r.access() == Access.ADMIN);
    }
}
