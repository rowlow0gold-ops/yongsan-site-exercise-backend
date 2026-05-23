package com.example.demo.auth.controller;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.entity.RefreshToken;
import com.example.demo.auth.jwt.JwtUtil;
import com.example.demo.auth.repository.AppUserRepository;
import com.example.demo.auth.repository.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.example.demo.auth.ClientIpResolver;
import com.example.demo.auth.PasswordBreachChecker;
import com.example.demo.auth.RateLimitService;
import com.example.demo.auth.jwt.TokenBlacklistService;
import io.jsonwebtoken.Claims;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;


@RestController
@RequestMapping("/auth")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Auth", description = "인증 API (로그인/회원가입/토큰)")
public class AuthController {

    private static final String OAUTH_EXCHANGE_PREFIX = "oauth-exchange:";

    private final AppUserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final JwtUtil jwt;
    private final TokenBlacklistService blacklist;
    private final RateLimitService rateLimit;
    private final StringRedisTemplate redis;
    private final ClientIpResolver clientIpResolver;
    private final PasswordBreachChecker passwordBreachChecker;

    private final long refreshTtlSeconds;
    private final long accessTtlSeconds;
    private final String refreshCookieName;
    private final String accessCookieName;
    private final boolean cookieSecure;

    private final PasswordEncoder encoder;

    public AuthController(
            AppUserRepository users,
            RefreshTokenRepository refreshTokens,
            JwtUtil jwt,
            TokenBlacklistService blacklist,
            RateLimitService rateLimit,
            PasswordEncoder encoder,
            StringRedisTemplate redis,
            ClientIpResolver clientIpResolver,
            PasswordBreachChecker passwordBreachChecker,
            @Value("${app.jwt.refreshTtlSeconds}") long refreshTtlSeconds,
            @Value("${app.jwt.accessTtlSeconds}") long accessTtlSeconds,
            @Value("${app.jwt.refreshCookieName}") String refreshCookieName,
            @Value("${app.jwt.accessCookieName:access_token}") String accessCookieName,
            @Value("${app.cookie.secure:true}") boolean cookieSecure
    ) {
        this.users = users;
        this.refreshTokens = refreshTokens;
        this.jwt = jwt;
        this.blacklist = blacklist;
        this.rateLimit = rateLimit;
        this.redis = redis;
        this.clientIpResolver = clientIpResolver;
        this.passwordBreachChecker = passwordBreachChecker;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshCookieName = refreshCookieName;
        this.accessCookieName = accessCookieName;
        this.cookieSecure = cookieSecure;
        this.encoder = encoder;
    }

    private String clientIp(HttpServletRequest req) {
        return clientIpResolver.resolve(req);
    }

    /**
     * Exchange a short-lived one-time code (handed out by OAuth2SuccessHandler in
     * the redirect URL) for the actual access token. This keeps the access token
     * out of the browser URL, server access logs, and Referer headers.
     */
    @PostMapping("/exchange")
    public ResponseEntity<?> exchange(@RequestBody ExchangeReq req, HttpServletResponse res) {
        if (req == null || req.getCode() == null || req.getCode().isBlank()) {
            return ResponseEntity.status(400).body(new Msg("Missing code"));
        }
        String key = OAUTH_EXCHANGE_PREFIX + req.getCode();
        String accessToken = redis.opsForValue().get(key);
        if (accessToken == null) {
            return ResponseEntity.status(401).body(new Msg("Invalid or expired code"));
        }
        // one-time use
        redis.delete(key);
        // Deliver the access token via HttpOnly cookie — never expose it to JS.
        setAccessCookie(res, accessToken, (int) accessTtlSeconds);
        return ResponseEntity.ok(new Msg("OK"));
    }

    @Data
    public static class ExchangeReq {
        @NotBlank @Size(max = 100)
        private String code;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginReq req,
                                   HttpServletRequest httpReq, HttpServletResponse res) {
        String ip = clientIp(httpReq);

        if (!rateLimit.isAllowed(ip)) {
            long retryAfter = rateLimit.getRetryAfterSeconds(ip);
            return ResponseEntity.status(429)
                    .header("Retry-After", String.valueOf(retryAfter))
                    .body(new Msg("Too many login attempts. Try again in " + retryAfter + " seconds."));
        }

        String email = req.getEmail().trim().toLowerCase();

        AppUser u = users.findByEmail(email).orElse(null);
        if (u == null || !encoder.matches(req.getPassword(), u.getPasswordHash())) {
            rateLimit.recordFailure(ip);
            return ResponseEntity.status(401).body(new Msg("Invalid credentials"));
        }

        rateLimit.clearAttempts(ip);
        String accessToken = jwt.createAccessToken(u.getId(), u.getRole());

        String rawRefresh = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID();
        String refreshHash = sha256Hex(rawRefresh);

        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(refreshTtlSeconds);
        refreshTokens.save(new RefreshToken(u.getId(), refreshHash, expiresAt));

        setRefreshCookie(res, rawRefresh, (int) refreshTtlSeconds);
        setAccessCookie(res, accessToken, (int) accessTtlSeconds);

        // Note: access token is no longer in the response body — it's in an
        // HttpOnly cookie. JS can read the user info, never the token itself.
        return ResponseEntity.ok(new UserRes(u));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest req, HttpServletResponse res) {
        // 30 refreshes / minute / IP — enough headroom for a legitimate
        // multi-tab user, low enough to make brute-force pointless.
        String ip = clientIp(req);
        if (!rateLimit.tryAcquire("refresh:" + ip, 30, Duration.ofMinutes(1))) {
            return ResponseEntity.status(429)
                    .header("Retry-After", "60")
                    .body(new Msg("Too many refresh attempts."));
        }

        String raw = readCookie(req, refreshCookieName).orElse(null);
        if (raw == null) return ResponseEntity.status(401).body(new Msg("No refresh cookie"));

        String hash = sha256Hex(raw);

        RefreshToken rt = refreshTokens.findTopByTokenHashAndRevokedAtIsNull(hash)
                .orElse(null);

        if (rt == null) return ResponseEntity.status(401).body(new Msg("Invalid refresh"));
        if (rt.getExpiresAt().isBefore(LocalDateTime.now())) return ResponseEntity.status(401).body(new Msg("Refresh expired"));

        AppUser u = users.findById(rt.getUserId()).orElse(null);
        if (u == null) return ResponseEntity.status(401).body(new Msg("Invalid refresh"));

        // ✅ ROTATE refresh token: revoke old + issue new
        rt.revokeNow();
        refreshTokens.save(rt);

        String newRawRefresh = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID();
        String newHash = sha256Hex(newRawRefresh);
        LocalDateTime newExpiresAt = LocalDateTime.now().plusSeconds(refreshTtlSeconds);

        refreshTokens.save(new RefreshToken(u.getId(), newHash, newExpiresAt));
        setRefreshCookie(res, newRawRefresh, (int) refreshTtlSeconds);

        String newAccess = jwt.createAccessToken(u.getId(), u.getRole());
        setAccessCookie(res, newAccess, (int) accessTtlSeconds);
        return ResponseEntity.ok(new Msg("OK"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest req, HttpServletResponse res) {
        // Blacklist the access token in Redis. Prefer the cookie; fall back to
        // the legacy Authorization header for any still-cached pre-cookie clients.
        String accessToken = readCookie(req, accessCookieName).orElse(null);
        if (accessToken == null) {
            String authHeader = req.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                accessToken = authHeader.substring(7);
            }
        }
        if (accessToken != null) {
            try {
                Claims claims = jwt.parse(accessToken).getBody();
                Date exp = claims.getExpiration();
                Duration remaining = Duration.between(Instant.now(), exp.toInstant());
                blacklist.blacklist(accessToken, remaining);
            } catch (Exception ignored) {
                // token already expired or invalid — no need to blacklist
            }
        }

        // Revoke refresh token in DB
        readCookie(req, refreshCookieName).ifPresent(raw -> {
            String hash = sha256Hex(raw);
            refreshTokens.findTopByTokenHashAndRevokedAtIsNull(hash).ifPresent(token -> {
                token.revokeNow();
                refreshTokens.save(token);
            });
        });

        clearRefreshCookie(res);
        clearAccessCookie(res);
        return ResponseEntity.ok(new Msg("OK"));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(org.springframework.security.core.Authentication auth) {
        if (auth == null) return ResponseEntity.status(401).build();
        Long userId = Long.valueOf(String.valueOf(auth.getPrincipal()));
        AppUser u = users.findById(userId).orElseThrow();
        return ResponseEntity.ok(new UserRes(u));
    }

    private void setRefreshCookie(HttpServletResponse res, String value, int maxAgeSeconds) {
        writeCookie(res, refreshCookieName, value, maxAgeSeconds);
    }

    private void setAccessCookie(HttpServletResponse res, String value, int maxAgeSeconds) {
        writeCookie(res, accessCookieName, value, maxAgeSeconds);
    }

    private void clearAccessCookie(HttpServletResponse res) {
        writeCookie(res, accessCookieName, "", 0);
    }

    private void writeCookie(HttpServletResponse res, String name, String value, int maxAgeSeconds) {
        StringBuilder sb = new StringBuilder()
                .append(name).append('=').append(value)
                .append("; Path=/")
                .append("; HttpOnly")
                .append("; Max-Age=").append(maxAgeSeconds)
                .append("; SameSite=Lax");
        if (cookieSecure) sb.append("; Secure");
        res.addHeader("Set-Cookie", sb.toString());
    }

    private void clearRefreshCookie(HttpServletResponse res) {
        String cookie = refreshCookieName + "=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax";
        res.addHeader("Set-Cookie", cookie);
    }

    private Optional<String> readCookie(HttpServletRequest req, String name) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) return Optional.empty();
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) return Optional.ofNullable(c.getValue());
        }
        return Optional.empty();
    }

    private String sha256Hex(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(raw.getBytes());
            return HexFormat.of().formatHex(dig);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Data
    public static class LoginReq {
        @Email @NotBlank @Size(max = 255)
        private String email;

        @NotBlank @Size(max = 100)
        private String password;
    }

    // (LoginRes and RefreshRes were removed: the access token is now delivered
    // via an HttpOnly cookie, not in the response body.)
    public record Msg(String message) {}

    public record UserRes(Long id, String email, String role, String name) {
        public UserRes(AppUser u) { this(u.getId(), u.getEmail(), u.getRole(), u.getName()); }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupReq req, HttpServletRequest httpReq) {
        // 10 signups / 10 minutes / IP — enough for legitimate retries on
        // validation errors, low enough to make account-creation flooding hurt.
        String ip = clientIp(httpReq);
        if (!rateLimit.tryAcquire("signup:" + ip, 10, Duration.ofMinutes(10))) {
            return ResponseEntity.status(429)
                    .header("Retry-After", "600")
                    .body(new Msg("Too many signup attempts. Try again later."));
        }

        // The password-breach check is the one error we surface directly: this
        // is feedback the user can act on (pick a different password), and it
        // doesn't reveal anything about existing accounts.
        if (passwordBreachChecker.isBreached(req.getPassword())) {
            return ResponseEntity.badRequest()
                    .body(new Msg("This password appears in known data breaches. Please choose another."));
        }

        String email = req.getEmail().trim().toLowerCase();

        // Reply with the same body whether or not the email already exists, so
        // attackers can't probe which addresses are registered. We only persist
        // when the address is new.
        if (users.findByEmail(email).isEmpty()) {
            AppUser u = new AppUser();
            u.setEmail(email);
            u.setName(req.getName());
            u.setRole("USER");
            u.setPasswordHash(encoder.encode(req.getPassword()));
            users.save(u);
        }

        return ResponseEntity.ok(new Msg("OK"));
    }

    @Data
    public static class SignupReq {
        @NotBlank @Size(max = 100)
        private String name;

        @Email @NotBlank @Size(max = 255)
        private String email;

        @NotBlank @Size(min = 8, max = 100)
        private String password;
    }
}