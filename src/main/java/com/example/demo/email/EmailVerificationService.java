package com.example.demo.email;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Optional;

/**
 * 6-digit OTP-style email verification (Microsoft / Google pattern).
 *
 * Why a 6-digit code instead of a magic link:
 *  - Phishing-resistant: user retypes it, no clickable URL to spoof
 *  - Cross-device: receive on phone, type on desktop
 *  - Familiar UX from every modern product
 *
 * Redis layout:
 *   verify-code:<userId>      -> 6-digit code   TTL 10 min  (one active code per user)
 *   verify-attempts:<userId>  -> int counter    TTL 10 min  (lockout after N wrong)
 *
 * Resending overwrites the code (and resets the counter), so an old code from
 * a previous email instantly becomes useless.
 */
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private static final String CODE_PREFIX = "verify-code:";
    private static final String ATTEMPTS_PREFIX = "verify-attempts:";
    private static final Duration TTL = Duration.ofMinutes(10);
    private static final int MAX_ATTEMPTS = 10;
    private static final SecureRandom RNG = new SecureRandom();

    private final StringRedisTemplate redis;
    private final AppUserRepository users;
    private final EmailService email;

    @Value("${app.email.appBaseUrl}")
    private String appBaseUrl;

    /** @return the wall-clock time when the newly-sent code will expire. */
    public java.time.Instant sendVerificationEmail(AppUser user) {
        String code = newCode();
        java.time.Instant expiresAt = java.time.Instant.now().plus(TTL);
        redis.opsForValue().set(CODE_PREFIX + user.getId(), code, TTL);
        redis.delete(ATTEMPTS_PREFIX + user.getId()); // reset on resend
        email.sendHtml(
                user.getEmail(),
                "[테스트 홈페이지] 이메일 인증 코드: " + code,
                EmailTemplates.verificationCode(user.getName(), code, (int) TTL.toMinutes())
        );
        return expiresAt;
    }

    /**
     * Validate the user-supplied code for the currently-authenticated user.
     * Returns:
     *   OK      — code matched; user is now email_verified=true
     *   WRONG   — code didn't match (counter incremented)
     *   EXPIRED — code TTL ran out (no active code in Redis for this user)
     *   LOCKED  — too many wrong attempts; user must request a new code
     */
    public Result verify(Long userId, String code) {
        if (userId == null || code == null || code.isBlank()) return Result.WRONG;
        String trimmed = code.trim();

        String attemptsStr = redis.opsForValue().get(ATTEMPTS_PREFIX + userId);
        int attempts = attemptsStr == null ? 0 : Integer.parseInt(attemptsStr);
        if (attempts >= MAX_ATTEMPTS) return Result.LOCKED;

        String expected = redis.opsForValue().get(CODE_PREFIX + userId);
        if (expected == null) return Result.EXPIRED;

        if (!expected.equals(trimmed)) {
            Long n = redis.opsForValue().increment(ATTEMPTS_PREFIX + userId);
            if (n != null && n == 1L) redis.expire(ATTEMPTS_PREFIX + userId, TTL);
            return Result.WRONG;
        }

        // Match — burn the code + counter and flip the flag.
        redis.delete(CODE_PREFIX + userId);
        redis.delete(ATTEMPTS_PREFIX + userId);
        users.findById(userId).ifPresent(u -> {
            u.setEmailVerified(true);
            users.save(u);
        });
        return Result.OK;
    }

    private static String newCode() {
        // Always exactly 6 digits, zero-padded if RNG yields a small number.
        int n = RNG.nextInt(1_000_000);
        return String.format("%06d", n);
    }

    public enum Result { OK, WRONG, EXPIRED, LOCKED }
}
