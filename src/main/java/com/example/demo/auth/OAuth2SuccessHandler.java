package com.example.demo.auth;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.entity.RefreshToken;
import com.example.demo.auth.jwt.JwtUtil;
import com.example.demo.auth.repository.AppUserRepository;
import com.example.demo.auth.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final AppUserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final JwtUtil jwt;

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

        AppUser user = users.findByEmail(finalEmail).orElseGet(() -> {
            AppUser newUser = new AppUser();
            newUser.setEmail(finalEmail);
            newUser.setName(finalName);
            newUser.setRole("USER");
            newUser.setPasswordHash("OAUTH2_NO_PASSWORD");
            return users.save(newUser);
        });

        String accessToken = jwt.createAccessToken(user.getId(), user.getRole());

        String rawRefresh = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID();
        String refreshHash = rawRefresh;
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(refreshTtlSeconds);
        refreshTokens.save(new RefreshToken(user.getId(), refreshHash, expiresAt));

        String cookie = refreshCookieName + "=" + rawRefresh
                + "; Path=/"
                + "; HttpOnly"
                + "; Max-Age=" + refreshTtlSeconds
                + "; SameSite=Lax";
        response.addHeader("Set-Cookie", cookie);

        response.sendRedirect(redirectUri + "?token=" + accessToken);
    }
}