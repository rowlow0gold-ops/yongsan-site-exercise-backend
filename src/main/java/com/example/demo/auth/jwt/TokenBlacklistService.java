package com.example.demo.auth.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private static final String PREFIX = "blacklist:";

    private final StringRedisTemplate redis;

    /**
     * Blacklist a token for the given duration (remaining TTL of the token).
     */
    public void blacklist(String token, Duration ttl) {
        if (ttl.isNegative() || ttl.isZero()) return;
        redis.opsForValue().set(PREFIX + token, "1", ttl);
    }

    /**
     * Check if a token has been blacklisted.
     */
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redis.hasKey(PREFIX + token));
    }
}
