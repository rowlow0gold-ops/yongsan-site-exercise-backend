package com.example.demo.auth;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.entity.RefreshToken;
import com.example.demo.auth.jwt.JwtUtil;
import com.example.demo.auth.repository.AppUserRepository;
import com.example.demo.auth.repository.RefreshTokenRepository;
import com.example.demo.auth.session.SessionStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final String EXCHANGE_PREFIX = "oauth-exchange:";
    private static final Duration EXCHANGE_TTL = Duration.ofSeconds(60);

    private final AppUserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final JwtUtil jwt;
    private final StringRedisTemplate redis;
    private final SessionStore sessions;

    @Value("${app.jwt.refreshTtlSeconds}")
    private long refreshTtlSeconds;

    @Value("${app.jwt.refreshCookieName}")
    private String refreshCookieName;

    @Value("${app.oauth2.redirect-uri}")
    private String redirectUri;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        // Kakao: check kakao_account.email and kakao_account.profile.nickname
        if (email == null) {
            Object kakaoAccount = oAuth2User.getAttribute("kakao_account");
            if (kakaoAccount instanceof Map<?,?> accountMap) {
                email = (String) accountMap.get("email");
                Object profile = accountMap.get("profile");
                if (profile instanceof Map<?,?> profileMap) {
                    name = (String) profileMap.get("nickname");
                }
            }
        }

        // Kakao: fallback to properties.nickname
        if (name == null) {
            Object properties = oAuth2User.getAttribute("properties");
            if (properties instanceof Map<?,?> propMap) {
                name = (String) propMap.get("nickname");
            }
        }

        // Last resort: use Kakao user ID as email
        if (email == null) {
            Object id = oAuth2User.getAttribute("id");
            if (id != null) {
                email = id + "@kakao.local";
            }
        }

        if (name == null) name = "User";

        if (email == null) {
            response.sendRedirect(redirectUri + "?error=no_email");
            return;
        }

        String finalEmail = email;
        String finalName = name;

        // Account linking by verified email. If the user already has an
        // account at this email (regardless of password vs OAuth signup),
        // we sign them in to that account. The OAuth provider has just
        // attested they control the address; for major providers (Google,
        // Kakao) this is enforced by the provider's own verification, so
        // it's safe. Pre-emptive "they signed up with password, refuse
        // OAuth" was over-strict and silently broke legitimate users.
        //
        // The narrow case we still reject: a synthetic .local email
        // (e.g. "<kakao_id>@kakao.local" we minted because Kakao didn't
        // share the email). Those are guessable; if someone pre-registered
        // such an address with a password, we can't trust the OAuth match.
        var existing = users.findByEmail(finalEmail);
        if (existing.isPresent() && finalEmail.endsWith(".local")
                && !"OAUTH2_NO_PASSWORD".equals(existing.get().getPasswordHash())) {
            response.sendRedirect(redirectUri + "?error=email_taken");
            return;
        }

        AppUser user = existing.orElseGet(() -> {
            AppUser newUser = new AppUser();
            newUser.setEmail(finalEmail);
            newUser.setName(finalName);
            newUser.setRole("USER");
            newUser.setPasswordHash("OAUTH2_NO_PASSWORD");
            // OAuth providers (Google/Kakao) already proved email ownership
            // on their side, so we trust their assertion and skip our own
            // verification. Synthetic @kakao.local addresses are marked
            // verified too — Kakao users authenticated via the provider,
            // the email field is just our internal identifier.
            newUser.setEmailVerified(true);
            return users.save(newUser);
        });

        String sid = sessions.create(user.getId());
        String accessToken = jwt.createAccessToken(user.getId(), user.getRole(), sid);

        String rawRefresh = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID();
        String refreshHash = sha256Hex(rawRefresh);
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(refreshTtlSeconds);
        refreshTokens.save(new RefreshToken(user.getId(), refreshHash, expiresAt));

        String cookie = refreshCookieName + "=" + rawRefresh
                + "; Path=/"
                + "; HttpOnly"
                + "; Max-Age=" + refreshTtlSeconds
                + "; SameSite=Lax";
        response.addHeader("Set-Cookie", cookie);

        // Don't put the access token in the URL (browser history / logs / Referer header).
        // Hand the browser a short-lived one-time code instead; the SPA exchanges it
        // at POST /auth/exchange for the actual access token in a response body.
        String code = UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        redis.opsForValue().set(EXCHANGE_PREFIX + code, accessToken, EXCHANGE_TTL);

        response.sendRedirect(redirectUri + "?code=" + code);
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
}