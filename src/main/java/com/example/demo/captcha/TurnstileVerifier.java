package com.example.demo.captcha;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** Verifies a Cloudflare Turnstile token against the siteverify endpoint.
 *  Fails closed: any error/timeout treated as invalid. */
@Service
public class TurnstileVerifier {

    private static final Logger log = LoggerFactory.getLogger(TurnstileVerifier.class);
    private static final String SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    @Value("${app.turnstile.secret:}")
    private String secret;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final ObjectMapper json = new ObjectMapper();

    public boolean verify(String token, String remoteIp) {
        if (secret == null || secret.isBlank()) {
            log.warn("Turnstile secret not configured — refusing verification (failing closed)");
            return false;
        }
        if (token == null || token.isBlank()) return false;

        try {
            String body = "secret=" + java.net.URLEncoder.encode(secret, "UTF-8")
                        + "&response=" + java.net.URLEncoder.encode(token, "UTF-8")
                        + (remoteIp != null ? "&remoteip=" + java.net.URLEncoder.encode(remoteIp, "UTF-8") : "");
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(SITEVERIFY))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                log.warn("Turnstile siteverify HTTP {}", resp.statusCode());
                return false;
            }
            JsonNode root = json.readTree(resp.body());
            boolean ok = root.path("success").asBoolean(false);
            if (!ok) log.info("Turnstile rejected token: {}", root.path("error-codes"));
            return ok;
        } catch (Exception e) {
            log.warn("Turnstile verification failed: {}", e.getMessage());
            return false;
        }
    }
}
