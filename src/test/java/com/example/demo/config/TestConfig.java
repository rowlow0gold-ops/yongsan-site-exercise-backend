package com.example.demo.config;

import com.example.demo.auth.RateLimitService;
import com.example.demo.auth.jwt.TokenBlacklistService;
import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Provides mock Redis-dependent beans for tests so that
 * tests can run without a live Redis instance.
 */
@TestConfiguration
public class TestConfig {

    @Bean
    @Primary
    public StringRedisTemplate testStringRedisTemplate() {
        return Mockito.mock(StringRedisTemplate.class);
    }

    @Bean
    @Primary
    public RateLimitService testRateLimitService(StringRedisTemplate redis) {
        RateLimitService mock = Mockito.mock(RateLimitService.class);
        when(mock.isAllowed(anyString())).thenReturn(true);
        when(mock.getRetryAfterSeconds(anyString())).thenReturn(60L);
        return mock;
    }

    @Bean
    @Primary
    public TokenBlacklistService testTokenBlacklistService(StringRedisTemplate redis) {
        TokenBlacklistService mock = Mockito.mock(TokenBlacklistService.class);
        when(mock.isBlacklisted(anyString())).thenReturn(false);
        return mock;
    }
}
