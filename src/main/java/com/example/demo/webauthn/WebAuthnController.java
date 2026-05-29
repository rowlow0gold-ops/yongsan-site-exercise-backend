package com.example.demo.webauthn;

import com.example.demo.auth.AuthContext;
import com.example.demo.auth.jwt.JwtUtil;
import com.example.demo.auth.repository.AppUserRepository;
import com.example.demo.auth.entity.AppUser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/webauthn")
@RequiredArgsConstructor
public class WebAuthnController {

    private final WebAuthnService svc;
    private final JwtUtil jwt;
    private final AppUserRepository users;

    @Value("${app.jwt.accessTtlSeconds:60}")
    private long accessTtlSeconds;

    @PostMapping("/register/start")
    public ResponseEntity<?> regStart() {
        Long uid = AuthContext.userIdOrNull();
        if (uid == null) return ResponseEntity.status(401).body(Map.of("message", "Login required"));
        return ResponseEntity.ok(svc.registrationStart(uid));
    }

    public record RegisterFinishReq(String credentialId, String publicKey, String name) {}

    @PostMapping("/register/finish")
    public ResponseEntity<?> regFinish(@RequestBody RegisterFinishReq req) {
        Long uid = AuthContext.userIdOrNull();
        if (uid == null) return ResponseEntity.status(401).body(Map.of("message", "Login required"));
        svc.registrationFinish(uid, req.credentialId(), req.publicKey(), req.name());
        return ResponseEntity.ok(Map.of("ok", true));
    }

    @PostMapping("/login/start")
    public ResponseEntity<?> loginStart() {
        return ResponseEntity.ok(svc.loginStart());
    }

    public record LoginFinishReq(String credentialId, String challenge) {}

    @PostMapping("/login/finish")
    public ResponseEntity<?> loginFinish(@RequestBody LoginFinishReq req, HttpServletResponse res) {
        Long uid = svc.loginFinish(req.credentialId(), req.challenge());
        AppUser u = users.findById(uid).orElseThrow();
        String token = jwt.createAccessToken(u.getId(), u.getRole());
        // Same cookie format as password login
        Cookie c = new Cookie("access_token", token);
        c.setHttpOnly(true);
        c.setSecure(true);
        c.setPath("/");
        c.setMaxAge((int) accessTtlSeconds);
        res.addCookie(c);
        Cookie exp = new Cookie("access_expires_at", String.valueOf(System.currentTimeMillis() + accessTtlSeconds * 1000));
        exp.setSecure(true); exp.setPath("/"); exp.setMaxAge((int) accessTtlSeconds);
        res.addCookie(exp);
        return ResponseEntity.ok(Map.of("id", u.getId(), "email", u.getEmail(), "role", u.getRole(), "name", u.getName()));
    }

    @GetMapping("/credentials")
    public ResponseEntity<?> myCredentials() {
        Long uid = AuthContext.userIdOrNull();
        if (uid == null) return ResponseEntity.status(401).body(Map.of("message", "Login required"));
        List<WebAuthnCredential> list = svc.list(uid);
        // Use LinkedHashMap (not Map.of) — Map.of throws NPE on null values,
        // and lastUsedAt is null for a credential that hasn't been used to
        // sign in yet. Order preserved for stable JSON output.
        return ResponseEntity.ok(list.stream().map(c -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", c.getId());
            m.put("name", c.getName());
            m.put("createdAt", c.getCreatedAt());
            m.put("lastUsedAt", c.getLastUsedAt());
            return m;
        }).toList());
    }

    @DeleteMapping("/credentials/{id}")
    public ResponseEntity<?> revoke(@PathVariable Long id) {
        Long uid = AuthContext.userIdOrNull();
        if (uid == null) return ResponseEntity.status(401).body(Map.of("message", "Login required"));
        svc.revoke(uid, id);
        return ResponseEntity.noContent().build();
    }
}
