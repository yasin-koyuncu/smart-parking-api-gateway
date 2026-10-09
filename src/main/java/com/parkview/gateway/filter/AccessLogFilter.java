package com.parkview.gateway.filter;

import com.parkview.gateway.web.EdgeHeadersWebFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * One access-log line per proxied request. Deliberately logs the route id, never the path or the query:
 * paths carry plates and ids (personal data) and SSE URLs may carry tokens.
 */
@Component
public class AccessLogFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger("gateway.access");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        long start = System.nanoTime();
        return chain.filter(exchange).doFinally(signal -> {
            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            var status = exchange.getResponse().getStatusCode();
            long ms = (System.nanoTime() - start) / 1_000_000;
            String line = "requestId={} method={} route={} status={} durationMs={} user={}";
            Object[] args = {
                    exchange.getAttribute(EdgeHeadersWebFilter.REQUEST_ID_ATTRIBUTE),
                    exchange.getRequest().getMethod(),
                    route != null ? route.getId() : "-",
                    status != null ? status.value() : 0,
                    ms,
                    exchange.getAttributeOrDefault(AuthForwardFilter.USER_ID_ATTRIBUTE, "-")
            };
            if (status != null && status.is5xxServerError()) {
                log.warn(line, args);
            } else {
                log.info(line, args);
            }
        });
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
