package com.parkview.gateway;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SpanExporter;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.GenericContainer;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The running gateway with {@code TRACING_ENABLED=true}: a request opens a trace at the gateway, the proxied call
 * to the downstream service carries a {@code traceparent} of that same trace, a trace id forged by the caller is not
 * joined, and probes are not exported. The OTLP exporter is off; spans are collected in memory.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@AutoConfigureObservability
@Import(GatewayTracingTest.CollectingExporterConfig.class)
class GatewayTracingTest {

    private static final MockWebServer UPSTREAM = new MockWebServer();
    private static final ECKey SIGNING_KEY = generateKey();
    private static final BlockingQueue<RecordedRequest> RECORDED = new LinkedBlockingQueue<>();
    private static final List<SpanData> SPANS = new CopyOnWriteArrayList<>();
    private static final String FORGED_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";

    /** TEST_REDIS_HOST[:PORT] points at an existing Redis (e.g. a sibling container); otherwise Testcontainers starts one. */
    private static final String EXTERNAL_REDIS = System.getenv("TEST_REDIS_HOST");
    private static final GenericContainer<?> REDIS = EXTERNAL_REDIS != null ? null
            : new GenericContainer<>("redis:7").withExposedPorts(6379);

    static {
        if (REDIS != null) {
            REDIS.start();
        }
    }

    @Autowired
    WebTestClient client;
    @Autowired
    SdkTracerProvider tracerProvider;

    @TestConfiguration(proxyBeanMethods = false)
    static class CollectingExporterConfig {
        @Bean
        SpanExporter collectingExporter() {
            return new SpanExporter() {
                @Override
                public CompletableResultCode export(Collection<SpanData> spans) {
                    SPANS.addAll(spans);
                    return CompletableResultCode.ofSuccess();
                }

                @Override
                public CompletableResultCode flush() {
                    return CompletableResultCode.ofSuccess();
                }

                @Override
                public CompletableResultCode shutdown() {
                    return CompletableResultCode.ofSuccess();
                }
            };
        }
    }

    private static ECKey generateKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("test-key").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    @BeforeAll
    static void startUpstream() throws IOException {
        UPSTREAM.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if ("/jwks".equals(request.getPath())) {
                    return new MockResponse().setHeader("Content-Type", "application/json").setBody(new JWKSet(SIGNING_KEY.toPublicJWK()).toString());
                }
                RECORDED.add(request);
                return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody("{\"ok\":true}");
            }
        });
        UPSTREAM.start();
    }

    @AfterAll
    static void stopUpstream() throws IOException {
        UPSTREAM.shutdown();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        String upstream = "http://localhost:" + UPSTREAM.getPort();
        registry.add("management.tracing.enabled", () -> "true");
        registry.add("management.tracing.sampling.probability", () -> "1.0");
        registry.add("management.otlp.tracing.export.enabled", () -> "false");
        registry.add("parkview.security.issuer", () -> "http://issuer.test/auth/v1");
        registry.add("parkview.security.jwks-uri", () -> upstream + "/jwks");
        registry.add("parkview.security.internal-api-key", () -> "test-internal-key");
        registry.add("spring.data.redis.host", () -> REDIS != null ? REDIS.getHost() : EXTERNAL_REDIS);
        registry.add("spring.data.redis.port", () -> REDIS != null ? REDIS.getMappedPort(6379) : 6379);
        registry.add("management.health.redis.enabled", () -> "false");
        registry.add("INGESTION_SERVICE_URL", () -> upstream);
        registry.add("INTERNAL_API_KEY", () -> "test-internal-key");
    }

    @BeforeEach
    void clear() {
        RECORDED.clear();
        SPANS.clear();
    }

    private List<SpanData> exported() {
        tracerProvider.forceFlush().join(5, TimeUnit.SECONDS);
        return List.copyOf(SPANS);
    }

    @Test
    void theProxiedCallContinuesTheTraceTheGatewayStartedAndIgnoresAForgedOne() throws Exception {
        client.post().uri("/api/v1/cameras/ingest").contentType(MediaType.APPLICATION_JSON)
                .header("traceparent", "00-" + FORGED_TRACE_ID + "-00f067aa0ba902b7-01")
                .bodyValue("{\"camera_id\":\"c\",\"api_key\":\"k\",\"plate\":\"ABC123\"}")
                .exchange().expectStatus().isOk();

        RecordedRequest upstream = RECORDED.poll(5, TimeUnit.SECONDS);
        assertThat(upstream).as("upstream received the request").isNotNull();
        String traceparent = upstream.getHeader("traceparent");
        assertThat(traceparent).matches("00-[0-9a-f]{32}-[0-9a-f]{16}-01");
        String traceId = traceparent.split("-")[1];
        assertThat(traceId).isNotEqualTo(FORGED_TRACE_ID);

        List<SpanData> spans = exported();
        assertThat(spans).extracting(SpanData::getTraceId).contains(traceId).doesNotContain(FORGED_TRACE_ID);
        // the request id the services log is still the one the edge assigned
        assertThat(upstream.getHeader("X-Request-Id")).isNotBlank();
        // nothing sensitive in the span attributes: no body, no plate
        assertThat(spans.toString()).doesNotContain("ABC123").doesNotContain("api_key");
    }

    @Test
    void probesAreNotExported() {
        client.get().uri("/actuator/health").exchange();
        assertThat(exported()).extracting(SpanData::getName).noneMatch(name -> name.contains("actuator"));
    }
}
