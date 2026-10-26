package com.parkview.gateway.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ResponseStatusException;

import java.net.ConnectException;
import java.util.Locale;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The texts of the errors the gateway writes itself follow the {@code Accept-Language} header (Swedish, English; any other
 * language and no header get English) and carry the stable {@code code}. No Spring context: the handler is built by hand.
 */
class GatewayErrorHandlerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final GatewayErrorHandler handler = new GatewayErrorHandler(mapper, new ErrorMessagesConfig().errorMessages());

    private JsonNode answer(String acceptLanguage, Throwable failure, HttpStatus expected) throws Exception {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/api/v1/nothing");
        if (acceptLanguage != null) {
            request.header("Accept-Language", acceptLanguage);
        }
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        handler.handle(exchange, failure).block();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(expected);
        return mapper.readTree(exchange.getResponse().getBodyAsString().block());
    }

    @Test
    void swedishCallerGetsSwedishTitleDetailAndCode() throws Exception {
        JsonNode body = answer("sv-SE,sv;q=0.9", new ResponseStatusException(HttpStatus.NOT_FOUND), HttpStatus.NOT_FOUND);

        assertThat(body.get("title").asText()).isEqualTo("Hittades inte");
        assertThat(body.get("detail").asText()).isEqualTo("Ingen adress matchar den här förfrågan");
        assertThat(body.get("message").asText()).isEqualTo("Ingen adress matchar den här förfrågan");
        assertThat(body.get("code").asText()).isEqualTo("error.noRoute");
        assertThat(body.get("status").asInt()).isEqualTo(404);
    }

    @Test
    void callerWithoutLanguageGetsEnglish() throws Exception {
        JsonNode body = answer(null, new ResponseStatusException(HttpStatus.NOT_FOUND), HttpStatus.NOT_FOUND);

        assertThat(body.get("title").asText()).isEqualTo("Not found");
        assertThat(body.get("detail").asText()).isEqualTo("No route matches this request");
        assertThat(body.get("code").asText()).isEqualTo("error.noRoute");
    }

    @Test
    void unknownLanguageGetsEnglishNotTheLanguageOfTheServer() throws Exception {
        Locale before = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("sv-SE"));
            JsonNode body = answer("fr", new ConnectException("refused"), HttpStatus.BAD_GATEWAY);

            assertThat(body.get("title").asText()).isEqualTo("Bad gateway");
            assertThat(body.get("detail").asText()).isEqualTo("The upstream service is currently unavailable");
            assertThat(body.get("code").asText()).isEqualTo("error.upstreamUnavailable");
        } finally {
            Locale.setDefault(before);
        }
    }

    @Test
    void anUpstreamThatIsTooSlowIsTranslated() throws Exception {
        JsonNode body = answer("sv", new TimeoutException("slow"), HttpStatus.GATEWAY_TIMEOUT);

        assertThat(body.get("title").asText()).isEqualTo("Tjänsten svarade inte i tid");
        assertThat(body.get("detail").asText()).isEqualTo("Tjänsten svarade inte i tid");
        assertThat(body.get("code").asText()).isEqualTo("error.upstreamTimeout");
    }

    @Test
    void anUnexpectedFailureAndAnUntranslatedStatusKeepTheirEnglishText() throws Exception {
        JsonNode unexpected = answer("sv", new IllegalStateException("boom"), HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(unexpected.get("detail").asText()).isEqualTo("Ett oväntat fel inträffade");
        assertThat(unexpected.get("code").asText()).isEqualTo("error.internal");

        JsonNode teapot = answer("sv", new ResponseStatusException(HttpStatus.I_AM_A_TEAPOT), HttpStatus.I_AM_A_TEAPOT);
        assertThat(teapot.get("title").asText()).isEqualTo("I'm a teapot");
        assertThat(teapot.get("detail").asText()).isEqualTo("I'm a teapot");
        assertThat(teapot.get("code").asText()).isEqualTo("error.http.418");
    }

    @Test
    void theLanguageIsTheFirstOneByWeightAndMalformedHeadersAreEnglish() {
        assertThat(RequestLocales.fromHeader("sv-SE,sv;q=0.9,en;q=0.8").getLanguage()).isEqualTo("sv");
        assertThat(RequestLocales.fromHeader("en;q=0.5, sv;q=0.9").getLanguage()).isEqualTo("sv");
        assertThat(RequestLocales.fromHeader("*").getLanguage()).isEqualTo("en");
        assertThat(RequestLocales.fromHeader("").getLanguage()).isEqualTo("en");
        assertThat(RequestLocales.fromHeader(null).getLanguage()).isEqualTo("en");
        assertThat(RequestLocales.fromHeader(";;;q==").getLanguage()).isEqualTo("en");
    }
}
