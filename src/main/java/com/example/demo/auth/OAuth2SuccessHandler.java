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

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        // Find or create user
        AppUser user = users.findByEmail(email).orElseGet(() -> {
            AppUser newUser = new AppUser();
            newUser.setEmail(email);
            newUser.setName(name);
            newUser.setRole("USER");
            newUser.setPasswordHash("OAUTH2_NO_PASSWORD");
            return users.save(newUser);
        });

        // Generate JWT
        String accessToken = jwt.createAccessToken(user.getId(), user.getRole());

        // Generate refresh token
        String rawRefresh = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID();
        String refreshHash = rawRefresh; // simplified
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(refreshTtlSeconds);
        refreshTokens.save(new RefreshToken(user.getId(), refreshHash, expiresAt));

        // Set refresh cookie
        String cookie = refreshCookieName + "=" + rawRefresh
                + "; Path=/"
                + "; HttpOnly"
                + "; Max-Age=" + refreshTtlSeconds
                + "; SameSite=Lax";
        response.addHeader("Set-Cookie", cookie);

        // Redirect to frontend with access token
        response.sendRedirect("https://minhojan-world.site?token=" + accessToken);
    }
}