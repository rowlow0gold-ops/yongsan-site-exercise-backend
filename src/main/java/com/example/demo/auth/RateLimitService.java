package com.example.demo.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RateLimitService {

    private static final String PREFIX = "ratelimit:login:";
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final StringRedisTemplate redis;

    /**
     * Check if the IP is allowed to attempt login.
     * Returns true if allowed, false if rate-limited.
     */
    public boolean isAllowed(String ip) {
        String key = PREFIX + ip;
        String val = redis.opsForValue().get(key);
        int count = (val == null) ? 0 : Integer.parseInt(val);
        return count < MAX_ATTEMPTS;
    }

    /**
     * Record a failed login attempt for the IP.
     */
    public void recordFailure(String ip) {
        String key = PREFIX + ip;
        Long newCount = redis.opsForValue().increment(key);
        if (newCount != null && newCount == 1) {
            redis.expire(key, WINDOW);
        }
    }

    /**
     * Clear attempts on successful login.
     */
    public void clearAttempts(String ip) {
        redis.delete(PREFIX + ip);
    }

    /**
     * Get remaining seconds until the rate limit resets.
     */
    public long getRetryAfterSeconds(String ip) {
        Long ttl = redis.getExpire(PREFIX + ip);
        return (ttl == null || ttl < 0) ? 60 : ttl;
    }
}
