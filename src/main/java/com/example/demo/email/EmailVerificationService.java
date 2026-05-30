package com.example.demo.email;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

/**
 * Email verification tokens, single-use, 24-hour TTL, stored in Redis
 * (no new DB table needed). Token is 256 random bits, base64url-encoded.
 *
 *   verify:<token>  ->  userId    TTL = 24h
 *
 * On verify we delete the token so it can't be replayed.
 */
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private static final String PREFIX = "verify:";
    private static final Duration TTL = Duration.ofHours(24);
    private static final SecureRandom RNG = new SecureRandom();

    private final StringRedisTemplate redis;
    private final AppUserRepository users;
    private final EmailService email;

    @Value("${app.email.appBaseUrl}")
    private String appBaseUrl;

    public void sendVerificationEmail(AppUser user) {
        String token = newToken();
        redis.opsForValue().set(PREFIX + token, String.valueOf(user.getId()), TTL);
        String url = appBaseUrl.replaceAll("/+$", "") + "/verify?token=" + token;
        email.sendHtml(
                user.getEmail(),
                "[용산구 홈페이지] 이메일 인증을 완료해주세요",
                EmailTemplates.verification(user.getName(), url)
        );
    }

    /** Returns the userId the token belongs to (and marks the user verified), or empty if bad token. */
    public Optional<Long> consume(String token) {
        if (token == null || token.isBlank()) return Optional.empty();
        String uidStr = redis.opsForValue().get(PREFIX + token);
        if (uidStr == null) return Optional.empty();
        redis.delete(PREFIX + token);
        try {
            Long uid = Long.parseLong(uidStr);
            users.findById(uid).ifPresent(u -> {
                u.setEmailVerified(true);
                users.save(u);
            });
            return Optional.of(uid);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    private static String newToken() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
