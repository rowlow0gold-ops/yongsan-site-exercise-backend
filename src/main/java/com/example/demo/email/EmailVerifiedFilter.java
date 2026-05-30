package com.example.demo.email;

import com.example.demo.auth.repository.AppUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Runs after JwtAuthFilter. If the authenticated user has
 * email_verified=false, blocks every API call except the small allow-list
 * needed for the user to actually verify (or recover, or leave).
 *
 * That allow-list is intentionally minimal — no posting, no satisfaction,
 * no passkey enrollment, no nothing until the email is confirmed.
 */
@Component
@RequiredArgsConstructor
public class EmailVerifiedFilter extends OncePerRequestFilter {

    private final AppUserRepository users;

    /** Exact URI prefixes that work even when the user isn't email-verified.
     *  Includes /auth/signup and /auth/login because the user might want to
     *  create a different account or sign in elsewhere from an existing
     *  unverified session — blocking those would leave them stranded. */
    private static final Set<String> ALLOWLIST_PREFIXES = Set.of(
            "/auth/me",
            "/auth/logout",
            "/auth/login",           // user might want to switch accounts
            "/auth/signup",          // user might want to create a different account
            "/auth/verify",          // /verify and /verify/resend
            "/auth/exchange",
            "/auth/refresh",
            "/auth/password-reset",  // they may need to recover
            "/auth/email-exists",
            "/oauth2/",              // start of OAuth flows (Google/Kakao)
            "/login/oauth2/"         // OAuth callbacks
    );

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain)
            throws ServletException, IOException {

        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(String.valueOf(auth.getPrincipal()))) {
            chain.doFilter(req, res);
            return;
        }

        String uri = req.getRequestURI();
        // OPTIONS preflight always pass — browser CORS check
        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
            chain.doFilter(req, res);
            return;
        }
        for (String p : ALLOWLIST_PREFIXES) {
            if (uri.startsWith(p)) {
                chain.doFilter(req, res);
                return;
            }
        }
        // DELETE /auth/me (탈퇴) is on the allowlist via the /auth/me prefix above.

        Long userId;
        try { userId = Long.valueOf(String.valueOf(auth.getPrincipal())); }
        catch (NumberFormatException e) { chain.doFilter(req, res); return; }

        boolean verified = users.findById(userId).map(u -> u.isEmailVerified()).orElse(true);
        if (!verified) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
            res.setCharacterEncoding("UTF-8");
            res.getWriter().write("{\"code\":\"EMAIL_NOT_VERIFIED\",\"message\":\"이메일 인증이 필요합니다.\"}");
            return;
        }

        chain.doFilter(req, res);
    }
}
