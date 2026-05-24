package com.example.demo.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Reads the access token from the HttpOnly access_token cookie (set by
 * login/exchange/refresh). The legacy Authorization: Bearer fallback was
 * removed — every supported client uses the cookie path, and accepting a
 * header-supplied JWT is just extra attack surface (e.g. for any XSS payload
 * that managed to read a non-HttpOnly storage).
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwt;
    private final TokenBlacklistService blacklist;
    private final String accessCookieName;

    public JwtAuthFilter(
            JwtUtil jwt,
            TokenBlacklistService blacklist,
            @Value("${app.jwt.accessCookieName:access_token}") String accessCookieName
    ) {
        this.jwt = jwt;
        this.blacklist = blacklist;
        this.accessCookieName = accessCookieName;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String token = readAccessCookie(request);

        if (token != null) {
            try {
                if (blacklist.isBlacklisted(token)) {
                    SecurityContextHolder.clearContext();
                    filterChain.doFilter(request, response);
                    return;
                }

                Jws<Claims> jws = jwt.parse(token);
                String userId = jws.getBody().getSubject();
                String role = String.valueOf(jws.getBody().get("role"));

                var auth = new UsernamePasswordAuthenticationToken(
                        userId,
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_" + role))
                );
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception ignored) {
                // invalid token -> treat as unauthenticated
                SecurityContextHolder.clearContext();
            }
        } else {
            // No JWT cookie or header → clear any session-based auth
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private String readAccessCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (accessCookieName.equals(c.getName())) {
                String v = c.getValue();
                return (v == null || v.isEmpty()) ? null : v;
            }
        }
        return null;
    }
}