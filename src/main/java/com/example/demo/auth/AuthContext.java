package com.example.demo.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuthContext {
    private AuthContext() {}

    public static Long userIdOrNull() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return null;
        Object p = auth.getPrincipal();
        if (p == null) return null;
        try { return Long.valueOf(String.valueOf(p)); }
        catch (Exception e) { return null; }
    }

    public static Long requireUserId() {
        Long id = userIdOrNull();
        if (id == null) throw new org.springframework.security.access.AccessDeniedException("Login required.");
        return id;
    }
}