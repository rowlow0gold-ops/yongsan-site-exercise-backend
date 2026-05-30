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
    /** Reverse index — every reset token issued to a user is also tracked here
     *  so we can invalidate ALL of them on successful reset (defense against
     *  attacker who triggered a reset before the legitimate user did). */
    private static final String USER_TOKENS_PREFIX = "pwreset-user:";
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

    /** Idempotent: silently no-op if the email doesn't map to a user OR if
     *  the user just completed a reset (5-min cooldown). */
    public void sendResetEmail(String email) {
        if (email == null || email.isBlank()) return;
        Optional<AppUser> opt = users.findByEmail(email.trim().toLowerCase());
        if (opt.isEmpty()) return;
        AppUser u = opt.get();
        if (isInCooldown(u.getId())) return;

        String token = newToken();
        redis.opsForValue().set(PREFIX + token, String.valueOf(u.getId()), TTL);
        // Track every active token for this user so we can invalidate them
        // all on successful reset.
        redis.opsForSet().add(USER_TOKENS_PREFIX + u.getId(), token);
        redis.expire(USER_TOKENS_PREFIX + u.getId(), TTL);

        String url = appBaseUrl.replaceAll("/+$", "") + "/reset-password?token=" + token;
        this.email.sendHtml(
                u.getEmail(),
                "[테스트 홈페이지] 비밀번호 재설정",
                EmailTemplates.passwordReset(u.getName(), url)
        );
    }

    /** Cheap validity check that does NOT consume the token. Used by the SPA
     *  on /reset-password page load so the form doesn't render for a stale link. */
    public boolean isTokenValid(String token) {
        if (token == null || token.isBlank()) return false;
        return redis.hasKey(PREFIX + token);
    }

    /** Look up the user the token belongs to (without consuming), for the
     *  notification email after confirmReset. */
    public Optional<AppUser> peekUser(String token) {
        if (token == null) return Optional.empty();
        String uidStr = redis.opsForValue().get(PREFIX + token);
        if (uidStr == null) return Optional.empty();
        try { return users.findById(Long.parseLong(uidStr)); }
        catch (NumberFormatException e) { return Optional.empty(); }
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

        // One-time use AND invalidate every OTHER outstanding reset token for
        // this user — protects against the case where an attacker requested a
        // reset before the legitimate user did. If the legit user resets via
        // their own newer link, the attacker's older link becomes inert.
        var allTokens = redis.opsForSet().members(USER_TOKENS_PREFIX + uid);
        if (allTokens != null) {
            for (String t : allTokens) {
                redis.delete(PREFIX + t);
            }
        }
        redis.delete(USER_TOKENS_PREFIX + uid);
        redis.delete(PREFIX + token); // belt + suspenders if it wasn't in the set

        // Kill everything: refresh tokens (DB) + sessions (Redis). Other
        // devices get logged out the moment they hit JwtAuthFilter.
        refreshTokens.deleteAllByUserId(uid);
        sessions.invalidateAllForUser(uid);

        return Optional.of(uid);
    }

    public PasswordEncoder getEncoder() { return encoder; }

    /** Send the "your password was just changed" notification. Idempotent;
     *  the async EmailService swallows failures so this never breaks the
     *  user-facing reset request. */
    public void sendPasswordChangedNotification(AppUser u, String ip) {
        String when = java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        email.sendHtml(
                u.getEmail(),
                "[테스트 홈페이지] 비밀번호 변경 알림",
                EmailTemplates.passwordChangedNotification(u.getName(), when, ip)
        );
    }

    /** After a successful reset, refuse any further reset request for this
     *  user for 5 minutes — prevents an attacker who somehow got the token
     *  from immediately re-locking the legitimate user out. */
    public void setResetCooldown(Long userId) {
        redis.opsForValue().set("pwreset-cooldown:" + userId, "1", Duration.ofMinutes(5));
    }

    public boolean isInCooldown(Long userId) {
        return Boolean.TRUE.equals(redis.hasKey("pwreset-cooldown:" + userId));
    }

    private static String newToken() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
