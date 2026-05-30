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

import com.example.demo.auth.AccountDeletionService;
import com.example.demo.auth.ClientIpResolver;
import com.example.demo.auth.PasswordBreachChecker;
import com.example.demo.auth.RateLimitService;
import com.example.demo.auth.session.SessionStore;
import com.example.demo.email.EmailVerificationService;
import com.example.demo.email.PasswordResetService;
import com.example.demo.audit.AuditLog;
import com.example.demo.captcha.TurnstileVerifier;
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
    private final AuditLog audit;
    private final TurnstileVerifier turnstile;
    private final StringRedisTemplate redis;
    private final ClientIpResolver clientIpResolver;
    private final PasswordBreachChecker passwordBreachChecker;
    private final AccountDeletionService accountDeletionService;
    private final SessionStore sessions;
    private final EmailVerificationService emailVerification;
    private final PasswordResetService passwordReset;

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
            AuditLog audit,
            TurnstileVerifier turnstile,
            PasswordEncoder encoder,
            StringRedisTemplate redis,
            ClientIpResolver clientIpResolver,
            PasswordBreachChecker passwordBreachChecker,
            AccountDeletionService accountDeletionService,
            SessionStore sessions,
            EmailVerificationService emailVerification,
            PasswordResetService passwordReset,
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
        this.audit = audit;
        this.turnstile = turnstile;
        this.redis = redis;
        this.clientIpResolver = clientIpResolver;
        this.passwordBreachChecker = passwordBreachChecker;
        this.accountDeletionService = accountDeletionService;
        this.sessions = sessions;
        this.emailVerification = emailVerification;
        this.passwordReset = passwordReset;
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
            audit.record(null, "LOGIN_RATELIMITED", ip, false, "retry_after=" + retryAfter);
            return ResponseEntity.status(429)
                    .header("Retry-After", String.valueOf(retryAfter))
                    .body(new Msg("Too many login attempts. Try again in " + retryAfter + " seconds."));
        }

        // Turnstile — verify the human-check token before doing any DB work.
        if (!turnstile.verify(req.getCfTurnstileToken(), ip)) {
            audit.record(null, "LOGIN_TURNSTILE_FAILED", ip, false, null);
            return ResponseEntity.status(403).body(new Msg("Captcha verification failed. Please reload and try again."));
        }

        String email = req.getEmail().trim().toLowerCase();

        AppUser u = users.findByEmail(email).orElse(null);
        if (u == null || !encoder.matches(req.getPassword(), u.getPasswordHash())) {
            rateLimit.recordFailure(ip);
            audit.record(email, "LOGIN_FAILURE", ip, false, null);
            return ResponseEntity.status(401).body(new Msg("Invalid credentials"));
        }

        // Credentials are correct but the account is not email-verified.
        // Don't mint any session. Send a fresh verification code and tell
        // the SPA it needs to collect one (it'll show the 6-digit input).
        if (!u.isEmailVerified()) {
            emailVerification.sendVerificationEmail(u);
            audit.record(u.getEmail(), "LOGIN_NEEDS_VERIFICATION", ip, false, null);
            return ResponseEntity.status(403).body(java.util.Map.of(
                    "code", "EMAIL_NOT_VERIFIED",
                    "message", "이메일 인증이 필요합니다. 발송된 6자리 코드를 입력해주세요.",
                    "email", u.getEmail()
            ));
        }

        rateLimit.clearAttempts(ip);
        audit.record(u.getEmail(), "LOGIN_SUCCESS", ip, true, null);
        String sid = sessions.create(u.getId());
        String accessToken = jwt.createAccessToken(u.getId(), u.getRole(), sid);

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

        // SECURITY: look up ANY row with this hash (including revoked) so we
        // can detect refresh-token reuse. If a token that's already been
        // rotated out is presented, treat it as a compromise: revoke every
        // active refresh token for the user. This burns one legitimate login
        // session but kills the attacker's stolen-token chain.
        RefreshToken rt = refreshTokens.findTopByTokenHash(hash).orElse(null);
        if (rt == null) return ResponseEntity.status(401).body(new Msg("Invalid refresh"));

        if (rt.getRevokedAt() != null) {
            // Reuse detected — revoke all active tokens for this user.
            for (RefreshToken active : refreshTokens.findAllByUserIdAndRevokedAtIsNull(rt.getUserId())) {
                active.revokeNow();
                refreshTokens.save(active);
            }
            clearRefreshCookie(res);
            clearAccessCookie(res);
            return ResponseEntity.status(401).body(new Msg("Session revoked. Please log in again."));
        }

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

        // Carry the existing sid forward if the old access cookie still has one,
        // so the user's session continues uninterrupted. Otherwise mint a fresh
        // one (this also covers grandfathered pre-sid tokens during deploy).
        String existingSid = readCookie(req, accessCookieName)
                .map(t -> {
                    try { return String.valueOf(jwt.parse(t).getBody().get("sid")); }
                    catch (Exception e) { return null; }
                })
                .filter(s -> s != null && !s.equals("null") && !s.isEmpty())
                .orElse(null);
        String sid = (existingSid != null && sessions.isActive(existingSid))
                ? existingSid
                : sessions.create(u.getId());
        sessions.extend(sid, u.getId());

        String newAccess = jwt.createAccessToken(u.getId(), u.getRole(), sid);
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

                // Kill the Redis session — JWTs already issued with this sid
                // become inert the moment the next request hits JwtAuthFilter.
                Object sidClaim = claims.get("sid");
                Object subClaim = claims.getSubject();
                if (sidClaim != null) {
                    Long uid = null;
                    try { uid = Long.parseLong(String.valueOf(subClaim)); } catch (Exception ignored2) {}
                    sessions.invalidate(String.valueOf(sidClaim), uid);
                }
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

    /**
     * Profile update — only the display name is mutable from here. Email is
     * the account identifier (changing it would need a re-verification flow);
     * role / passwordHash / emailVerified are admin-or-system-managed.
     */
    @PatchMapping("/me")
    public ResponseEntity<?> patchMe(org.springframework.security.core.Authentication auth,
                                     @Valid @RequestBody UpdateMeReq req,
                                     HttpServletRequest httpReq) {
        if (auth == null) return ResponseEntity.status(401).build();
        Long userId = Long.valueOf(String.valueOf(auth.getPrincipal()));
        AppUser u = users.findById(userId).orElse(null);
        if (u == null) return ResponseEntity.status(404).body(new Msg("Account not found"));

        if (req.name != null) {
            String trimmed = req.name.trim();
            if (trimmed.isEmpty() || trimmed.length() < 2 || trimmed.length() > 50) {
                return ResponseEntity.badRequest().body(new Msg("이름은 2자 이상 50자 이하로 입력해주세요."));
            }
            u.setName(trimmed);
        }
        users.save(u);
        audit.record(u.getEmail(), "PROFILE_UPDATED", clientIp(httpReq), true, "name");
        return ResponseEntity.ok(new UserRes(u));
    }

    @Data
    public static class UpdateMeReq {
        @Size(min = 2, max = 50)
        private String name;
    }

    /**
     * 탈퇴 — permanent account deletion. The caller must be authenticated;
     * we look up their email from the JWT principal, run the deletion
     * transaction, blacklist the current access token, revoke their refresh
     * cookie, and clear both cookies on the response so the next request
     * comes in as anonymous.
     */
    @DeleteMapping("/me")
    public ResponseEntity<?> deleteMe(org.springframework.security.core.Authentication auth,
                                      HttpServletRequest req,
                                      HttpServletResponse res) {
        if (auth == null) return ResponseEntity.status(401).build();
        Long userId = Long.valueOf(String.valueOf(auth.getPrincipal()));
        AppUser u = users.findById(userId).orElse(null);
        if (u == null) return ResponseEntity.status(404).body(new Msg("Account not found"));

        String ip = clientIp(req);
        accountDeletionService.deleteAccount(userId, u.getEmail(), ip);

        // Blacklist the access token so it can't be reused while it's still
        // within its TTL window.
        readCookie(req, accessCookieName).ifPresent(token -> {
            try {
                Claims claims = jwt.parse(token).getBody();
                Date exp = claims.getExpiration();
                Duration remaining = Duration.between(Instant.now(), exp.toInstant());
                blacklist.blacklist(token, remaining);
            } catch (Exception ignored) {}
        });

        clearRefreshCookie(res);
        clearAccessCookie(res);
        return ResponseEntity.ok(new Msg("탈퇴 처리되었습니다."));
    }

    /**
     * Lightweight "does this email belong to a registered account?" probe used
     * by the login dialog before kicking off WebAuthn / OAuth. Microsoft-style:
     * we want to tell the user "no such account" up front instead of letting
     * them attempt a passkey assertion that the server would silently swap
     * for someone else's account.
     *
     * Note: this technically leaks email enumeration (anyone can enumerate
     * which emails are registered). That's an accepted trade-off for the UX
     * here — the same enumeration is possible via signup ("email taken")
     * and OAuth. Rate-limited by `rateLimit` so brute-force is bounded.
     */
    @PostMapping("/email-exists")
    public ResponseEntity<?> emailExists(@RequestBody EmailExistsReq req,
                                         HttpServletRequest httpReq) {
        if (req == null || req.email == null || req.email.isBlank()) {
            return ResponseEntity.badRequest().body(java.util.Map.of("message", "email required"));
        }
        String ip = clientIpResolver.resolve(httpReq);
        // 30 probes / minute / IP — enough for normal use, blocks enumeration scrapers.
        if (!rateLimit.tryAcquire("email-exists:" + ip, 30, Duration.ofMinutes(1))) {
            return ResponseEntity.status(429).body(java.util.Map.of("message", "Too many requests"));
        }
        boolean exists = users.findByEmail(req.email.trim()).isPresent();
        return ResponseEntity.ok(java.util.Map.of("exists", exists));
    }

    @Data
    public static class EmailExistsReq {
        @Email @NotBlank @Size(max = 254)
        private String email;
    }

    // Name of the JS-readable companion cookie that just carries the access
    // token's expiry timestamp (unix millis). The token itself stays in an
    // HttpOnly cookie — only the *expiry time* is exposed to JS so the SPA
    // can render a countdown / session indicator.
    private static final String ACCESS_EXP_COOKIE = "access_expires_at";

    private void setRefreshCookie(HttpServletResponse res, String value, int maxAgeSeconds) {
        writeCookie(res, refreshCookieName, value, maxAgeSeconds);
    }

    private void setAccessCookie(HttpServletResponse res, String value, int maxAgeSeconds) {
        writeCookie(res, accessCookieName, value, maxAgeSeconds);
        // Companion expiry cookie: JS-readable, holds only the expiration
        // timestamp (not the token). Lets UtilBar.vue render the countdown
        // that broke when the access token moved to an HttpOnly cookie.
        long expAtMs = Instant.now().plusSeconds(maxAgeSeconds).toEpochMilli();
        writeReadableCookie(res, ACCESS_EXP_COOKIE, String.valueOf(expAtMs), maxAgeSeconds);
    }

    private void clearAccessCookie(HttpServletResponse res) {
        writeCookie(res, accessCookieName, "", 0);
        writeReadableCookie(res, ACCESS_EXP_COOKIE, "", 0);
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

    // Same as writeCookie but WITHOUT HttpOnly — for the access_expires_at
    // metadata cookie that the SPA reads to render the countdown. Value is
    // a unix-millis timestamp; not a secret.
    private void writeReadableCookie(HttpServletResponse res, String name, String value, int maxAgeSeconds) {
        StringBuilder sb = new StringBuilder()
                .append(name).append('=').append(value)
                .append("; Path=/")
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

        /** Cloudflare Turnstile widget token. Required. */
        @NotBlank
        private String cfTurnstileToken;
    }

    // (LoginRes and RefreshRes were removed: the access token is now delivered
    // via an HttpOnly cookie, not in the response body.)
    public record Msg(String message) {}

    public record UserRes(Long id, String email, String role, String name, boolean emailVerified) {
        public UserRes(AppUser u) { this(u.getId(), u.getEmail(), u.getRole(), u.getName(), u.isEmailVerified()); }
    }

    // Server-side strength enforcement. Frontend should also show these
    // rules live, but we never trust the client.
    private static final java.util.regex.Pattern PW_LETTER = java.util.regex.Pattern.compile("[A-Za-z]");
    private static final java.util.regex.Pattern PW_DIGIT  = java.util.regex.Pattern.compile("[0-9]");
    private static String passwordStrengthError(String pw) {
        if (pw == null || pw.length() < 8) {
            return "비밀번호는 8자 이상이어야 합니다.";
        }
        if (pw.length() > 128) {
            return "비밀번호는 128자 이하여야 합니다.";
        }
        if (!PW_LETTER.matcher(pw).find() || !PW_DIGIT.matcher(pw).find()) {
            return "영문자와 숫자를 모두 포함해야 합니다.";
        }
        // Reject all-same character / very low entropy passwords
        if (pw.matches("(.)\\1{5,}.*")) {
            return "같은 문자가 너무 반복됩니다.";
        }
        return null;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupReq req, HttpServletRequest httpReq,
                                    HttpServletResponse httpRes) {
        // 10 signups / 10 minutes / IP — enough for legitimate retries on
        // validation errors, low enough to make account-creation flooding hurt.
        String ip = clientIp(httpReq);
        if (!rateLimit.tryAcquire("signup:" + ip, 10, Duration.ofMinutes(10))) {
            return ResponseEntity.status(429)
                    .header("Retry-After", "600")
                    .body(new Msg("Too many signup attempts. Try again later."));
        }

        // Turnstile removed from signup — rate-limit (10/10min/IP above) +
        // email-verification (account inert until verified) carry the
        // bot-protection load now.

        // Strength check (length + complexity) before the more expensive
        // remote breach lookup.
        String strengthError = passwordStrengthError(req.getPassword());
        if (strengthError != null) {
            return ResponseEntity.badRequest().body(new Msg(strengthError));
        }

        // The password-breach check is the one error we surface directly: this
        // is feedback the user can act on (pick a different password), and it
        // doesn't reveal anything about existing accounts.
        if (passwordBreachChecker.isBreached(req.getPassword())) {
            return ResponseEntity.badRequest()
                    .body(new Msg("이미 유출된 적이 있는 비밀번호입니다. 다른 비밀번호를 선택해주세요. (영문/숫자/기호를 조합한 12자 이상을 권장)"));
        }

        String email = req.getEmail().trim().toLowerCase();

        // SECURITY: refuse any reserved/non-routable TLD (.local, .invalid, .test,
        // .example, .localhost). These are synthetic addresses we generate for
        // OAuth users that didn't share an email (e.g. "<kakao_id>@kakao.local").
        // Allowing them through signup would let an attacker pre-claim a future
        // OAuth user's account by guessing the provider ID. We respond with the
        // same OK body either way so attackers can't enumerate the rule.
        boolean reservedDomain = email.endsWith(".local")
                || email.endsWith(".invalid")
                || email.endsWith(".test")
                || email.endsWith(".example")
                || email.endsWith(".localhost")
                || email.endsWith(".internal");

        // Reply with the same body whether or not the email already exists, so
        // attackers can't probe which addresses are registered. We only persist
        // when the address is new and the domain is routable.
        if (!reservedDomain && users.findByEmail(email).isEmpty()) {
            AppUser u = new AppUser();
            u.setEmail(email);
            u.setName(req.getName());
            u.setRole("USER");
            u.setPasswordHash(encoder.encode(req.getPassword()));
            u.setEmailVerified(false); // inert until they prove email control
            AppUser saved = users.save(u);
            emailVerification.sendVerificationEmail(saved);
            audit.record(email, "SIGNUP_PENDING_VERIFICATION", ip, true, null);
        }

        // No cookies are minted here. Until the user enters the 6-digit code
        // they're a non-authenticated nobody. Same body whether new account,
        // existing-verified, or reserved-domain — attackers can't enumerate.
        return ResponseEntity.ok(new Msg("회원가입 요청을 받았습니다. 이메일로 보낸 6자리 인증 코드를 입력해 회원가입을 완료해주세요."));
    }

    /**
     * Public endpoint — anyone with the right email + code combo can verify
     * AND get logged in atomically. This is the single bridge from the
     * "not really a user" state created by signup into a real authenticated
     * session.
     *
     * Flow: user signed up → got 6-digit code in email → tried to log in
     * with password → server rejected with EMAIL_NOT_VERIFIED → SPA shows
     * code input → POSTs here → cookies set, user record returned.
     */
    @PostMapping("/verify")
    public ResponseEntity<?> verifyEmail(@RequestBody VerifyReq req, HttpServletRequest httpReq,
                                         HttpServletResponse httpRes) {
        if (req == null || req.email == null || req.code == null
                || req.email.isBlank() || !req.code.matches("\\d{6}")) {
            return ResponseEntity.badRequest().body(java.util.Map.of("ok", false,
                    "message", "6자리 숫자 코드를 입력해주세요."));
        }
        String ip = clientIp(httpReq);
        // Same rate-limit bucket as login — prevents brute-forcing codes for
        // arbitrary emails.
        if (!rateLimit.tryAcquire("verify:" + ip, 30, Duration.ofMinutes(1))) {
            return ResponseEntity.status(429).body(java.util.Map.of("ok", false,
                    "message", "잠시 후 다시 시도해주세요."));
        }

        AppUser u = users.findByEmail(req.email.trim().toLowerCase()).orElse(null);
        if (u == null) {
            // Same response shape as WRONG so attackers can't enumerate which
            // emails are registered.
            return ResponseEntity.status(400).body(java.util.Map.of("ok", false,
                    "message", "인증 코드가 올바르지 않습니다."));
        }

        var result = emailVerification.verify(u.getId(), req.code);

        return switch (result) {
            case OK -> {
                audit.record(u.getEmail(), "EMAIL_VERIFIED", ip, true, null);
                // Mint a real session — this is the user's first authenticated
                // moment. Same shape as /auth/login response.
                String sid = sessions.create(u.getId());
                String accessToken = jwt.createAccessToken(u.getId(), u.getRole(), sid);
                String rawRefresh = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID();
                String refreshHash = sha256Hex(rawRefresh);
                LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(refreshTtlSeconds);
                refreshTokens.save(new RefreshToken(u.getId(), refreshHash, expiresAt));
                setRefreshCookie(httpRes, rawRefresh, (int) refreshTtlSeconds);
                setAccessCookie(httpRes, accessToken, (int) accessTtlSeconds);
                yield ResponseEntity.ok(java.util.Map.of(
                        "ok", true,
                        "message", "이메일 인증 완료!",
                        "user", new UserRes(u)
                ));
            }
            case WRONG -> ResponseEntity.status(400).body(java.util.Map.of("ok", false,
                    "message", "인증 코드가 올바르지 않습니다."));
            case EXPIRED -> ResponseEntity.status(400).body(java.util.Map.of("ok", false,
                    "message", "인증 코드가 만료되었습니다. 새 코드를 요청해주세요."));
            case LOCKED -> ResponseEntity.status(429).body(java.util.Map.of("ok", false,
                    "message", "잘못된 시도가 너무 많습니다. 새 인증 코드를 요청해주세요."));
        };
    }

    @Data
    public static class VerifyReq {
        @Email @NotBlank @Size(max = 254)
        private String email;

        @NotBlank
        private String code;
    }

    /**
     * Public — anyone can request a fresh code to be sent to a given email.
     * Always returns 200 with the same body so callers can't probe which
     * emails are registered / unverified. Rate-limited per IP and per email.
     */
    @PostMapping("/verify/resend")
    public ResponseEntity<?> resendVerification(@RequestBody PwResetRequestReq req,
                                                HttpServletRequest httpReq) {
        String ip = clientIp(httpReq);
        // 5/min/IP — covers an honest user retrying, blocks scrapers.
        if (!rateLimit.tryAcquire("verify-resend-ip:" + ip, 5, Duration.ofMinutes(1))) {
            return ResponseEntity.status(429).body(new Msg("잠시 후 다시 시도해주세요."));
        }
        if (req != null && req.email != null) {
            String email = req.email.trim().toLowerCase();
            // 3/hour/email — keeps a malicious actor from flooding one mailbox.
            if (rateLimit.tryAcquire("verify-resend-email:" + email, 3, Duration.ofHours(1))) {
                users.findByEmail(email).ifPresent(u -> {
                    if (!u.isEmailVerified()) {
                        emailVerification.sendVerificationEmail(u);
                        audit.record(u.getEmail(), "VERIFY_RESEND", ip, true, null);
                    }
                });
            }
        }
        return ResponseEntity.ok(new Msg("입력하신 이메일이 등록되어 있다면 새 인증 코드를 보냈습니다."));
    }

    /**
     * Step 1 of forgot-password: anyone can hit this with an email; we ALWAYS
     * return 200 so attackers can't probe which emails are registered.
     */
    @PostMapping("/password-reset/request")
    public ResponseEntity<?> requestPasswordReset(@RequestBody PwResetRequestReq req, HttpServletRequest httpReq) {
        String ip = clientIp(httpReq);
        // 5 / hour / IP — covers honest retries, blocks scrapers.
        if (!rateLimit.tryAcquire("pwreset-ip:" + ip, 5, Duration.ofHours(1))) {
            return ResponseEntity.status(429).body(new Msg("잠시 후 다시 시도해주세요."));
        }
        // Bot check on top of rate limit — defends against an attacker who's
        // rotating IPs to slip past the 5/hour bucket. We still return 200
        // either way to avoid leaking which step failed.
        if (req == null || req.cfTurnstileToken == null
                || !turnstile.verify(req.cfTurnstileToken, ip)) {
            audit.record(req == null ? null : req.email, "PWRESET_TURNSTILE_FAILED", ip, false, null);
            return ResponseEntity.ok(new Msg("입력하신 이메일이 등록되어 있다면 재설정 링크를 보내드립니다."));
        }
        if (req.email != null) {
            String email = req.email.trim().toLowerCase();
            // 3 / hour / email so a malicious actor can't flood one mailbox.
            if (rateLimit.tryAcquire("pwreset-email:" + email, 3, Duration.ofHours(1))) {
                passwordReset.sendResetEmail(email);
                audit.record(email, "PWRESET_REQUEST", ip, true, null);
            }
        }
        return ResponseEntity.ok(new Msg("입력하신 이메일이 등록되어 있다면 재설정 링크를 보내드립니다."));
    }

    @Data
    public static class PwResetRequestReq {
        @Email @NotBlank @Size(max = 254)
        private String email;

        // Cloudflare Turnstile widget token. Required from the SPA.
        private String cfTurnstileToken;
    }

    /**
     * Step 2 of forgot-password: SPA's /reset-password posts here with the
     * token and the new password. Strength check identical to signup.
     */
    @PostMapping("/password-reset/confirm")
    public ResponseEntity<?> confirmPasswordReset(@RequestBody PwResetConfirmReq req, HttpServletRequest httpReq) {
        if (req == null || req.token == null || req.token.isBlank()
                || req.newPassword == null || req.newPassword.isBlank()) {
            return ResponseEntity.badRequest().body(new Msg("입력값이 올바르지 않습니다."));
        }
        String strengthError = passwordStrengthError(req.newPassword);
        if (strengthError != null) {
            return ResponseEntity.badRequest().body(new Msg(strengthError));
        }
        if (passwordBreachChecker.isBreached(req.newPassword)) {
            return ResponseEntity.badRequest().body(new Msg(
                    "유출된 이력이 있는 비밀번호입니다. 다른 비밀번호를 선택해주세요."));
        }
        // Snapshot the user BEFORE confirmReset wipes the token, so we can
        // notify them by email afterwards.
        Optional<AppUser> before = passwordReset.peekUser(req.token);
        String hash = passwordReset.getEncoder().encode(req.newPassword);
        Optional<Long> uid = passwordReset.confirmReset(req.token, hash);
        if (uid.isEmpty()) {
            return ResponseEntity.status(400).body(new Msg("유효하지 않거나 만료된 재설정 링크입니다."));
        }
        // 5-minute cooldown — any further reset request for this user is no-oped
        // until this expires. Keyed by user id, lives in Redis.
        passwordReset.setResetCooldown(uid.get());
        String ip = clientIp(httpReq);
        before.ifPresent(u -> passwordReset.sendPasswordChangedNotification(u, ip));
        users.findById(uid.get()).ifPresent(u -> audit.record(u.getEmail(), "PWRESET_CONFIRM", ip, true, null));
        return ResponseEntity.ok(new Msg("비밀번호가 재설정되었습니다. 새 비밀번호로 로그인해주세요."));
    }

    /** Cheap probe used by /reset-password on page load to decide whether to
     *  render the form. Doesn't consume the token. Always 200; the body
     *  tells the SPA valid:true|false. */
    @PostMapping("/password-reset/validate")
    public ResponseEntity<?> validateResetToken(@RequestBody PwResetValidateReq req) {
        boolean valid = req != null && passwordReset.isTokenValid(req.getToken());
        return ResponseEntity.ok(java.util.Map.of("valid", valid));
    }

    @Data
    public static class PwResetValidateReq {
        @NotBlank
        private String token;
    }

    @Data
    public static class PwResetConfirmReq {
        @NotBlank
        private String token;

        @NotBlank @Size(min = 8, max = 128)
        private String newPassword;
    }

    @Data
    public static class SignupReq {
        @NotBlank @Size(max = 100)
        private String name;

        @Email @NotBlank @Size(max = 255)
        private String email;

        @NotBlank @Size(min = 8, max = 100)
        private String password;

        // Turnstile field kept for backward compatibility with any in-flight
        // clients that still send it — value is ignored.
        private String cfTurnstileToken;
    }
}