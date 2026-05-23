package com.example.demo.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Resolve the originating client IP when the app sits behind a reverse proxy
 * or load balancer (nginx, K3s ingress, Cloudflare).
 *
 * `HttpServletRequest.getRemoteAddr()` returns the TCP peer, which is the
 * proxy's address — useless for rate limiting per-user and misleading in
 * audit logs. We honour the X-Forwarded-For chain (left-most non-trusted
 * hop) and fall back to X-Real-IP or getRemoteAddr.
 *
 * SECURITY: X-Forwarded-For is trivially spoofable if the request reaches us
 * directly. This helper is only safe when the front-most public proxy is
 * configured to strip incoming XFF and append its own value. Verify your
 * ingress/nginx config does this before relying on rate limits.
 */
@Component
public class ClientIpResolver {

    public String resolve(HttpServletRequest req) {
        // Cloudflare-specific header (if you're behind CF)
        String cf = req.getHeader("CF-Connecting-IP");
        if (isUsable(cf)) return cf.trim();

        // Generic X-Forwarded-For: take the leftmost address (the original client)
        String xff = req.getHeader("X-Forwarded-For");
        if (isUsable(xff)) {
            int comma = xff.indexOf(',');
            String first = (comma >= 0 ? xff.substring(0, comma) : xff).trim();
            if (isUsable(first)) return first;
        }

        // Nginx-style
        String real = req.getHeader("X-Real-IP");
        if (isUsable(real)) return real.trim();

        return req.getRemoteAddr();
    }

    private boolean isUsable(String s) {
        return s != null && !s.isBlank() && !"unknown".equalsIgnoreCase(s.trim());
    }
}
