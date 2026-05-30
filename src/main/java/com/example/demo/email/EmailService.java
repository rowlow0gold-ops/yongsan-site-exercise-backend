package com.example.demo.email;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Thin wrapper over Resend's REST API (https://resend.com/docs).
 *
 * Why no SDK: the HTTP shape is dead-simple — POST /emails with a JSON body
 * and a Bearer token — and adding a third-party SDK means one more upstream
 * to track for vulns. Two dozen lines of HttpClient does the same job.
 *
 * The send is @Async so /signup, /password-reset/request etc don't block
 * waiting on SMTP to come back. A failed send is logged but does not fail
 * the user-facing request — the user can always re-request a verification
 * or reset email.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class EmailService {

    private static final String RESEND_ENDPOINT = "https://api.resend.com/emails";

    private final ObjectMapper json;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Value("${app.email.resendApiKey}")
    private String apiKey;

    @Value("${app.email.fromAddress}")
    private String fromAddress;

    @Value("${app.email.fromName}")
    private String fromName;

    @Async
    public void sendHtml(String to, String subject, String htmlBody) {
        if (apiKey == null || apiKey.isBlank()) {
            log.warn("EmailService.sendHtml called but no Resend API key configured; dropping email to={}", to);
            return;
        }
        try {
            String fromLine = (fromName == null || fromName.isBlank())
                    ? fromAddress
                    : fromName + " <" + fromAddress + ">";

            String body = json.writeValueAsString(Map.of(
                    "from", fromLine,
                    "to", new String[]{to},
                    "subject", subject,
                    "html", htmlBody
            ));

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(RESEND_ENDPOINT))
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() >= 200 && res.statusCode() < 300) {
                log.info("Resend send ok to={} subject=\"{}\"", to, subject);
            } else {
                log.warn("Resend send failed status={} to={} body={}", res.statusCode(), to, res.body());
            }
        } catch (Exception e) {
            log.warn("Resend send threw for to={} subject=\"{}\"", to, subject, e);
        }
    }
}
