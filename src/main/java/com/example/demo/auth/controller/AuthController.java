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

import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;


@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AppUserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final JwtUtil jwt;

    private final long refreshTtlSeconds;
    private final String refreshCookieName;

    private final PasswordEncoder encoder;

    public AuthController(
            AppUserRepository users,
            RefreshTokenRepository refreshTokens,
            JwtUtil jwt,
            PasswordEncoder encoder,
            @Value("${app.jwt.refreshTtlSeconds}") long refreshTtlSeconds,
            @Value("${app.jwt.refreshCookieName}") String refreshCookieName
    ) {
        this.users = users;
        this.refreshTokens = refreshTokens;
        this.jwt = jwt;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.refreshCookieName = refreshCookieName;
        this.encoder = encoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginReq req, HttpServletResponse res) {
        String email = req.getEmail().trim().toLowerCase();

        AppUser u = users.findByEmail(email).orElse(null);
        if (u == null || !encoder.matches(req.getPassword(), u.getPasswordHash())) {
            return ResponseEntity.status(401).body(new Msg("Invalid credentials"));
        }

        String accessToken = jwt.createAccessToken(u.getId(), u.getRole());

        String rawRefresh = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID();
        String refreshHash = sha256Hex(rawRefresh);

        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(refreshTtlSeconds);
        refreshTokens.save(new RefreshToken(u.getId(), refreshHash, expiresAt));

        setRefreshCookie(res, rawRefresh, (int) refreshTtlSeconds);

        return ResponseEntity.ok(new LoginRes(accessToken, new UserRes(u)));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest req, HttpServletResponse res) {
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
        return ResponseEntity.ok(new RefreshRes(newAccess));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest req, HttpServletResponse res) {
        readCookie(req, refreshCookieName).ifPresent(raw -> {
            String hash = sha256Hex(raw);
            refreshTokens.findTopByTokenHashAndRevokedAtIsNull(hash).ifPresent(token -> {
                token.revokeNow();
                refreshTokens.save(token);
            });
        });

        clearRefreshCookie(res);
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
        // For local dev (http://localhost), SameSite=Lax usually works if same-site.
        // If you deploy FE/BE on different domains, you’ll need SameSite=None; Secure (HTTPS).
        String cookie = refreshCookieName + "=" + value
                + "; Path=/"
                + "; HttpOnly"
                + "; Max-Age=" + maxAgeSeconds
                + "; SameSite=Lax";
        res.addHeader("Set-Cookie", cookie);
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

    public record LoginRes(String accessToken, UserRes user) {}
    public record RefreshRes(String accessToken) {}
    public record Msg(String message) {}

    public record UserRes(Long id, String email, String role, String name) {
        public UserRes(AppUser u) { this(u.getId(), u.getEmail(), u.getRole(), u.getName()); }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupReq req) {
        String email = req.getEmail().trim().toLowerCase();

        if (users.findByEmail(email).isPresent()) {
            return ResponseEntity.badRequest().body(new Msg("Email already exists"));
        }

        AppUser u = new AppUser();
        u.setEmail(email);
        u.setName(req.getName());
        u.setRole("USER");
        u.setPasswordHash(encoder.encode(req.getPassword()));
        users.save(u);

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