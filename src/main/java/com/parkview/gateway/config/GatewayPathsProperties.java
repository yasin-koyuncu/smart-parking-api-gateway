package com.parkview.gateway.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Bakbinder parkview.gateway.public-paths/operator-paths från application.yml.
 * Fanns tidigare deklarerat men var aldrig faktiskt inläst — SecurityConfig
 * hade sina egna hårdkodade path-regler istället, vilket bland annat gjorde
 * att /api/v1/auth/** aldrig var publik (ingen kunde logga in via gatewayn).
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "parkview.gateway")
public class GatewayPathsProperties {
    private List<String> publicPaths   = List.of();
    private List<String> operatorPaths = List.of();
}
