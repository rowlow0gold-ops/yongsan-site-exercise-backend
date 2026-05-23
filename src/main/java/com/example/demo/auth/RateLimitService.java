package com.example.demo.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Sliding-window-ish rate limiter backed by Redis counters.
 *
 * Two flavors:
 *   - Legacy single-arg API (used by /auth/login) — counts under "ratelimit:login:<ip>",
 *     5 attempts / 1 minute. Kept stable so existing callers don't change.
 *   - Generic API with an explicit key, max, and window — used by signup / refresh
 *     and anywhere we need a separate bucket.
 */
@Service
@RequiredArgsConstructor
public class RateLimitService {

    private static final String LEGACY_PREFIX = "ratelimit:login:";
    private static final String GENERIC_PREFIX = "ratelimit:k:";
    private static final int LEGACY_MAX_ATTEMPTS = 5;
    private static final Duration LEGACY_WINDOW = Duration.ofMinutes(1);

    private final StringRedisTemplate redis;

    // ---------------- Legacy /auth/login API ----------------

    public boolean isAllowed(String ip) {
        String key = LEGACY_PREFIX + ip;
        String val = redis.opsForValue().get(key);
        int count = (val == null) ? 0 : Integer.parseInt(val);
        return count < LEGACY_MAX_ATTEMPTS;
    }

    public void recordFailure(String ip) {
        String key = LEGACY_PREFIX + ip;
        Long newCount = redis.opsForValue().increment(key);
        if (newCount != null && newCount == 1) {
            redis.expire(key, LEGACY_WINDOW);
        }
    }

    public void clearAttempts(String ip) {
        redis.delete(LEGACY_PREFIX + ip);
    }

    public long getRetryAfterSeconds(String ip) {
        Long ttl = redis.getExpire(LEGACY_PREFIX + ip);
        if (ttl != null && ttl >= 0) return ttl;
        // generic key form ("signup:1.2.3.4" etc.) — fall through to the namespaced bucket
        Long generic = redis.getExpire(GENERIC_PREFIX + ip);
        return (generic == null || generic < 0) ? 60 : generic;
    }

    // ---------------- Generic API ----------------

    /**
     * Fixed-window rate limiter. Atomically increments the bucket and returns
     * true if the caller is under the limit. One call == one slot consumed.
     *
     * Note this differs from the legacy isAllowed/recordFailure split: here a
     * single tryAcquire both checks and consumes, which is what you almost
     * always want for incoming requests.
     */
    public boolean tryAcquire(String key, int max, Duration window) {
        String fullKey = GENERIC_PREFIX + key;
        Long newCount = redis.opsForValue().increment(fullKey);
        if (newCount == null) {
            // Redis hiccup — fail open rather than locking everyone out.
            return true;
        }
        if (newCount == 1L) {
            redis.expire(fullKey, window);
        }
        return newCount <= max;
    }
}
