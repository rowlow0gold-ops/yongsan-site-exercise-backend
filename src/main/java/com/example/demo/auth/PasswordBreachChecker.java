package com.example.demo.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;

/**
 * Check a candidate password against haveibeenpwned.com's k-anonymity API.
 * We send only the first 5 hex chars of the SHA-1 hash; the API returns all
 * suffixes that match. The full password never leaves our server, and we
 * never store it.
 *
 * Failure modes (network down, HIBP returns 5xx): we *fail open* — i.e. we
 * do NOT block signup, because doing so would give attackers a DoS button
 * on user registration. The trade-off is one breached password might slip
 * through during an HIBP outage; that's acceptable.
 *
 * Toggle off entirely with `app.security.passwordBreachCheck=false`.
 */
@Service
public class PasswordBreachChecker {

    private static final Logger log = LoggerFactory.getLogger(PasswordBreachChecker.class);
    private static final String API = "https://api.pwnedpasswords.com/range/";
    private static final Duration TIMEOUT = Duration.ofSeconds(2);

    private final HttpClient http;
    private final boolean enabled;

    public PasswordBreachChecker(
            @Value("${app.security.passwordBreachCheck:true}") boolean enabled
    ) {
        this.enabled = enabled;
        this.http = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                .build();
    }

    /**
     * Returns true if the password's SHA-1 suffix appears in HIBP's dataset.
     * Returns false on disable, network error, or no match.
     */
    public boolean isBreached(String password) {
        if (!enabled || password == null || password.isEmpty()) return false;

        String sha1 = sha1Hex(password).toUpperCase();
        String prefix = sha1.substring(0, 5);
        String suffix = sha1.substring(5);

        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(API + prefix))
                    .timeout(TIMEOUT)
                    .header("Add-Padding", "true")            // mitigates traffic analysis
                    .header("User-Agent", "yongsan-site-signup")
                    .GET()
                    .build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() != 200) {
                log.warn("HIBP returned non-200 status {}; failing open", res.statusCode());
                return false;
            }
            // Body is `SUFFIX:COUNT` per line.
            for (String line : res.body().split("\\r?\\n")) {
                int colon = line.indexOf(':');
                if (colon <= 0) continue;
                if (suffix.equalsIgnoreCase(line.substring(0, colon).trim())) {
                    // Count is in line.substring(colon+1). Any non-zero count = breached.
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            log.warn("HIBP lookup failed ({}); failing open", e.getMessage());
            return false;
        }
    }

    private static String sha1Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] dig = md.digest(s.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(dig);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
