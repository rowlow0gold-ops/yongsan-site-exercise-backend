package com.example.demo.auth.session;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

/**
 * Redis-backed authoritative session store.
 *
 * The JWT itself is enough to *say* who you are (signed claims), but it can't
 * be revoked once issued — until expiry, anyone with the token is "logged in"
 * as that user. That's a problem for: explicit logout, account deletion,
 * admin-initiated kicks, and "sign out everywhere".
 *
 * Fix: every authenticated request also checks `session:<sid>` in Redis. If
 * the key is gone, the JWT is rejected even though it's still cryptographically
 * valid. That gives us instant revocation without paying the cost of a DB
 * round-trip on every request (Redis GET is ~0.5ms).
 *
 * Key layout:
 *   session:<sid>          STRING  = userId           TTL = sessionTtl
 *   user-sessions:<userId> SET     = { sid, sid, ... } TTL = sessionTtl (refreshed)
 *
 * The reverse index lets us efficiently invalidate every active session for
 * a single user without scanning the whole keyspace.
 */
@Service
@RequiredArgsConstructor
public class SessionStore {

    private static final String SESSION_PREFIX = "session:";
    private static final String USER_SESSIONS_PREFIX = "user-sessions:";

    private final StringRedisTemplate redis;

    @Value("${app.jwt.refreshTtlSeconds}")
    private long refreshTtlSeconds;

    /** Mint a new sid for a fresh login. */
    public String create(Long userId) {
        String sid = UUID.randomUUID().toString().replace("-", "");
        Duration ttl = Duration.ofSeconds(refreshTtlSeconds);
        redis.opsForValue().set(SESSION_PREFIX + sid, String.valueOf(userId), ttl);
        redis.opsForSet().add(USER_SESSIONS_PREFIX + userId, sid);
        redis.expire(USER_SESSIONS_PREFIX + userId, ttl);
        return sid;
    }

    /** Extend the TTL on an existing sid (e.g. on a successful refresh). */
    public void extend(String sid, Long userId) {
        if (sid == null) return;
        Duration ttl = Duration.ofSeconds(refreshTtlSeconds);
        redis.expire(SESSION_PREFIX + sid, ttl);
        redis.expire(USER_SESSIONS_PREFIX + userId, ttl);
    }

    /** True if the sid is still in Redis (i.e. not logged out, not expired). */
    public boolean isActive(String sid) {
        if (sid == null || sid.isEmpty()) return false;
        Boolean exists = redis.hasKey(SESSION_PREFIX + sid);
        return Boolean.TRUE.equals(exists);
    }

    /** Look up the user id that owns a sid, or null if expired/unknown. */
    public Long userIdOf(String sid) {
        if (sid == null) return null;
        String v = redis.opsForValue().get(SESSION_PREFIX + sid);
        if (v == null) return null;
        try { return Long.parseLong(v); } catch (NumberFormatException e) { return null; }
    }

    /** Kill a single session (logout button). */
    public void invalidate(String sid, Long userId) {
        if (sid == null) return;
        redis.delete(SESSION_PREFIX + sid);
        if (userId != null) {
            redis.opsForSet().remove(USER_SESSIONS_PREFIX + userId, sid);
        }
    }

    /** Kill every active session belonging to a user (탈퇴, password change, etc). */
    public int invalidateAllForUser(Long userId) {
        Set<String> sids = redis.opsForSet().members(USER_SESSIONS_PREFIX + userId);
        if (sids == null || sids.isEmpty()) {
            redis.delete(USER_SESSIONS_PREFIX + userId);
            return 0;
        }
        for (String sid : sids) {
            redis.delete(SESSION_PREFIX + sid);
        }
        redis.delete(USER_SESSIONS_PREFIX + userId);
        return sids.size();
    }
}
