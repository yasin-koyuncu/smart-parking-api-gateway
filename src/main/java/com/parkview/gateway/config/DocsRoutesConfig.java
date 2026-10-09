package com.parkview.gateway.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Aggregated API documentation: {@code /docs/<service>/v3/api-docs} is routed to each service's own OpenAPI
 * endpoint, and the gateway's Swagger UI lists them all. Only active with {@code DOCS_ENABLED=true}
 * ({@code parkview.gateway.docs-enabled}); never enable in production.
 */
@Configuration
@ConditionalOnProperty(prefix = "parkview.gateway", name = "docs-enabled", havingValue = "true")
public class DocsRoutesConfig {

    @Bean
    RouteLocator docsRoutes(RouteLocatorBuilder builder, GatewayProperties properties) {
        RouteLocatorBuilder.Builder routes = builder.routes();
        properties.services().forEach((name, url) -> routes.route("docs-" + name, r -> r
                .path("/docs/" + name + "/v3/api-docs", "/docs/" + name + "/v3/api-docs/**")
                .filters(f -> f.rewritePath("/docs/" + name + "/(?<segment>.*)", "/${segment}"))
                .uri(url)));
        return routes.build();
    }
}
