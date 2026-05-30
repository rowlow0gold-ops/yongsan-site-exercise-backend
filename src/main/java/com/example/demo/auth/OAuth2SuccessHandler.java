package com.example.demo.auth;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.entity.OAuthIdentity;
import com.example.demo.auth.entity.RefreshToken;
import com.example.demo.auth.jwt.JwtUtil;
import com.example.demo.auth.repository.AppUserRepository;
import com.example.demo.auth.repository.OAuthIdentityRepository;
import com.example.demo.auth.repository.RefreshTokenRepository;
import com.example.demo.auth.session.SessionStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
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
@Slf4j
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final String EXCHANGE_PREFIX = "oauth-exchange:";
    private static final Duration EXCHANGE_TTL = Duration.ofSeconds(60);

    private final AppUserRepository users;
    private final OAuthIdentityRepository oauthIdentities;
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

        // Identify the provider + the provider's stable user id. Email is
        // not a reliable identifier — it can change at the provider, and two
        // different provider accounts can briefly share an email (this is
        // exactly what caused the Kakao 4827954651 incident).
        String provider = (authentication instanceof OAuth2AuthenticationToken token)
                ? token.getAuthorizedClientRegistrationId()
                : "unknown";
        String providerUserId;
        if ("google".equals(provider)) {
            providerUserId = String.valueOf(oAuth2User.getAttribute("sub"));
        } else if ("kakao".equals(provider)) {
            Object kid = oAuth2User.getAttribute("id");
            providerUserId = kid == null ? null : String.valueOf(kid);
        } else {
            providerUserId = oAuth2User.getName();
        }

        if (providerUserId == null || providerUserId.isBlank() || "null".equals(providerUserId)) {
            log.warn("OAuth provider {} did not return a stable user id", provider);
            response.sendRedirect(redirectUri + "?error=no_provider_id");
            return;
        }

        // 1) Fast path — identity already exists. (provider, providerUserId)
        //    is the only key we trust as stable, so if it matches a row we
        //    sign in that user immediately, no email lookup involved.
        var existingIdentity = oauthIdentities.findByProviderAndProviderUserId(provider, providerUserId);
        AppUser user;
        if (existingIdentity.isPresent()) {
            user = users.findById(existingIdentity.get().getUserId())
                    .orElseThrow(() -> new IllegalStateException(
                            "Identity " + provider + ":" + providerUserId + " points at missing user"));
        } else {
            // 2) Email fallback — used for first-time OAuth login on either
            //    a fresh user (no account yet) or an existing password user
            //    that's now linking this provider. Synthetic .local emails
            //    still refuse to link against a password-set account.
            var existing = users.findByEmail(finalEmail);
            if (existing.isPresent() && finalEmail.endsWith(".local")
                    && !"OAUTH2_NO_PASSWORD".equals(existing.get().getPasswordHash())) {
                response.sendRedirect(redirectUri + "?error=email_taken");
                return;
            }

            user = existing.orElseGet(() -> {
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

            // 3) Reject duplicate-provider hijack. If this AppUser already
            //    has an identity for the SAME provider but a DIFFERENT
            //    providerUserId, two distinct provider accounts are trying
            //    to converge through email — exactly the bug we're fixing.
            //    Bail out instead of silently merging.
            var sameProviderIdentities = oauthIdentities.findAllByUserIdAndProvider(user.getId(), provider);
            if (!sameProviderIdentities.isEmpty()) {
                log.warn("OAuth hijack guard: user {} already has {} identity for provider {}; refusing new providerUserId {}",
                        user.getId(), sameProviderIdentities.size(), provider, providerUserId);
                response.sendRedirect(redirectUri + "?error=email_taken");
                return;
            }

            // 4) First-time linkage — record the identity so future logins
            //    take the fast path and skip the email fallback entirely.
            oauthIdentities.save(new OAuthIdentity(user.getId(), provider, providerUserId));
        }

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