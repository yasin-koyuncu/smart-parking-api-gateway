package com.parkview.gateway.web;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** The Swedish error texts follow the English base: same keys, no blank text, same placeholders. */
class ErrorBundleParityTest {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{[A-Za-z0-9]+}");

    private static Properties load(String name) throws IOException {
        try (InputStream in = ErrorBundleParityTest.class.getResourceAsStream(name)) {
            assertThat(in).as(name).isNotNull();
            Properties properties = new Properties();
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            return properties;
        }
    }

    private static TreeSet<String> placeholders(String text) {
        TreeSet<String> found = new TreeSet<>();
        Matcher m = PLACEHOLDER.matcher(text);
        while (m.find()) {
            found.add(m.group());
        }
        return found;
    }

    @Test
    void everyKeyOfTheEnglishBaseIsTranslatedAndNothingIsBlank() throws IOException {
        Properties en = load("/messages/errors.properties");
        Properties sv = load("/messages/errors_sv.properties");

        assertThat(en).isNotEmpty();
        assertThat(sv.stringPropertyNames()).containsExactlyInAnyOrderElementsOf(en.stringPropertyNames());
        en.forEach((key, text) -> assertThat(text.toString()).as("English text of " + key).isNotBlank());
        sv.forEach((key, text) -> assertThat(text.toString()).as("Swedish text of " + key).isNotBlank());
    }

    @Test
    void theSwedishTextsKeepThePlaceholdersOfTheEnglishOnes() throws IOException {
        Properties en = load("/messages/errors.properties");
        Properties sv = load("/messages/errors_sv.properties");

        for (String key : en.stringPropertyNames()) {
            assertThat(placeholders(sv.getProperty(key))).as("placeholders of " + key).isEqualTo(placeholders(en.getProperty(key)));
        }
    }

    @Test
    void anApostropheIsDoubledExactlyWhereTheTextHasParameters() throws IOException {
        for (String name : new String[] {"/messages/errors.properties", "/messages/errors_sv.properties"}) {
            Properties bundle = load(name);
            for (String key : bundle.stringPropertyNames()) {
                String text = bundle.getProperty(key);
                boolean hasArguments = text.matches("(?s).*\\{[0-9]}.*");
                if (hasArguments) {
                    assertThat(text.replace("''", "")).as(name + " " + key).doesNotContain("'");
                } else {
                    assertThat(text).as(name + " " + key).doesNotContain("''");
                }
            }
        }
    }
}
