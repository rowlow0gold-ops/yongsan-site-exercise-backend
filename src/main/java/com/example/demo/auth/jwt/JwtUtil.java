package com.example.demo.auth.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;

@Component
public class JwtUtil {

    private final Key key;
    private final long accessTtlSeconds;

    public JwtUtil(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.accessTtlSeconds}") long accessTtlSeconds
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
    }

    // Two-arg variant kept for any call site that doesn't have a session id yet
    // (e.g. some legacy / test code). New callers should pass a sid so the
    // server-side SessionStore can revoke the token before its JWT TTL is up.
    public String createAccessToken(Long userId, String role) {
        return createAccessToken(userId, role, null);
    }

    public String createAccessToken(Long userId, String role, String sid) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(accessTtlSeconds);

        JwtBuilder b = Jwts.builder()
                .setSubject(String.valueOf(userId))
                .claim("role", role)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .signWith(key, SignatureAlgorithm.HS256);

        if (sid != null) b.claim("sid", sid);

        return b.compact();
    }

    public Jws<Claims> parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }
}