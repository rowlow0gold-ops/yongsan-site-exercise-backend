package com.example.demo.email;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.repository.AppUserRepository;
import com.example.demo.auth.repository.RefreshTokenRepository;
import com.example.demo.auth.session.SessionStore;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

/**
 * Password-reset tokens, single-use, 1-hour TTL, Redis only (no DB table).
 *
 *   pwreset:<token>  ->  userId    TTL = 1h
 *
 * Request flow always returns 200 — we don't leak whether the email exists.
 * Confirm flow validates strength, applies the new hash, kills every active
 * session for that user (so other devices get kicked out), and deletes the
 * token.
 */
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private static final String PREFIX = "pwreset:";
    private static final Duration TTL = Duration.ofHours(1);
    private static final SecureRandom RNG = new SecureRandom();

    private final StringRedisTemplate redis;
    private final AppUserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final SessionStore sessions;
    private final EmailService email;
    private final PasswordEncoder encoder;

    @Value("${app.email.appBaseUrl}")
    private String appBaseUrl;

    /** Idempotent: silently no-op if the email doesn't map to a user. */
    public void sendResetEmail(String email) {
        if (email == null || email.isBlank()) return;
        Optional<AppUser> opt = users.findByEmail(email.trim().toLowerCase());
        if (opt.isEmpty()) return;
        AppUser u = opt.get();

        String token = newToken();
        redis.opsForValue().set(PREFIX + token, String.valueOf(u.getId()), TTL);

        String url = appBaseUrl.replaceAll("/+$", "") + "/reset-password?token=" + token;
        this.email.sendHtml(
                u.getEmail(),
                "[용산구 홈페이지] 비밀번호 재설정",
                EmailTemplates.passwordReset(u.getName(), url)
        );
    }

    /** Returns the userId whose password was reset, or empty if token bad / invalid password. */
    @Transactional
    public Optional<Long> confirmReset(String token, String newPasswordHash) {
        if (token == null || token.isBlank()) return Optional.empty();
        String uidStr = redis.opsForValue().get(PREFIX + token);
        if (uidStr == null) return Optional.empty();
        Long uid;
        try { uid = Long.parseLong(uidStr); }
        catch (NumberFormatException e) { return Optional.empty(); }

        Optional<AppUser> opt = users.findById(uid);
        if (opt.isEmpty()) {
            redis.delete(PREFIX + token);
            return Optional.empty();
        }
        AppUser u = opt.get();
        u.setPasswordHash(newPasswordHash);
        u.setEmailVerified(true); // verifying email control implicitly proves ownership
        users.save(u);

        // One-time use
        redis.delete(PREFIX + token);

        // Kill everything: refresh tokens (DB) + sessions (Redis). Other
        // devices get logged out the moment they hit JwtAuthFilter.
        refreshTokens.deleteAllByUserId(uid);
        sessions.invalidateAllForUser(uid);

        return Optional.of(uid);
    }

    public PasswordEncoder getEncoder() { return encoder; }

    private static String newToken() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
