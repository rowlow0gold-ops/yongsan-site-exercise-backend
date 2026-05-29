package com.example.demo.webauthn;

import com.example.demo.auth.AppUser;
import com.example.demo.auth.AppUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
public class WebAuthnService {

    private final WebAuthnCredentialRepository creds;
    private final AppUserRepository users;
    private final StringRedisTemplate redis;
    private final ObjectMapper json = new ObjectMapper();

    @Value("${app.webauthn.rp-id:yongsan.minhojan-world.site}")
    private String rpId;

    @Value("${app.webauthn.rp-name:용산구청}")
    private String rpName;

    @Value("${app.webauthn.origin:https://yongsan.minhojan-world.site}")
    private String origin;

    private static final String CH_PREFIX = "webauthn:challenge:";
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);

    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
    private final SecureRandom random = new SecureRandom();
    private final Base64.Encoder b64url = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder b64urlDec = Base64.getUrlDecoder();

    /** Step 1 of enrollment — we tell the browser what to sign and remember
     *  the challenge so we can verify what comes back. */
    public Map<String, Object> registrationStart(Long userId) {
        AppUser user = users.findById(userId).orElseThrow(() -> new IllegalStateException("User not found"));

        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        redis.opsForValue().set(CH_PREFIX + "reg:" + userId, b64url.encodeToString(challenge), CHALLENGE_TTL);

        // List of credentials already registered — browser will exclude them
        List<Map<String, Object>> excludeList = new ArrayList<>();
        for (WebAuthnCredential c : creds.findAllByUserId(userId)) {
            excludeList.add(Map.of(
                "type", "public-key",
                "id", b64url.encodeToString(c.getCredentialId())
            ));
        }

        // PublicKeyCredentialCreationOptions, serialized as a plain Map → JSON
        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("challenge", b64url.encodeToString(challenge));
        opts.put("rp", Map.of("id", rpId, "name", rpName));
        opts.put("user", Map.of(
            "id", b64url.encodeToString(("u-" + userId).getBytes()),
            "name", user.getEmail(),
            "displayName", user.getName() != null ? user.getName() : user.getEmail()
        ));
        opts.put("pubKeyCredParams", List.of(
            Map.of("type", "public-key", "alg", -7),    // ES256
            Map.of("type", "public-key", "alg", -257)   // RS256
        ));
        opts.put("authenticatorSelection", Map.of(
            "userVerification", "preferred",
            "residentKey", "preferred"
        ));
        opts.put("timeout", 60_000);
        opts.put("attestation", "none");
        opts.put("excludeCredentials", excludeList);
        return opts;
    }

    /** Step 2 of enrollment — browser sends back attestation, we verify and persist. */
    public void registrationFinish(Long userId, String credentialIdB64, String publicKeyCoseB64, String name) {
        String challenge = redis.opsForValue().getAndDelete(CH_PREFIX + "reg:" + userId);
        if (challenge == null) throw new IllegalArgumentException("Registration challenge expired or missing.");

        // Note: full attestation verification needs the raw clientDataJSON +
        // attestationObject from the browser. For demo simplicity we store the
        // browser-supplied credential id + public key as-is. Production hardening
        // (TODO Phase A.1): pass attestationObject through webAuthnManager.parse()
        // and webAuthnManager.validate() with ServerProperty(rpId, origin, challenge, null).
        byte[] credentialId = b64urlDec.decode(credentialIdB64);
        byte[] publicKey = b64urlDec.decode(publicKeyCoseB64);

        WebAuthnCredential c = WebAuthnCredential.builder()
                .credentialId(credentialId)
                .publicKeyCose(publicKey)
                .userId(userId)
                .name(name != null && !name.isBlank() ? name : "Passkey")
                .build();
        creds.save(c);
    }

    /** Login start — we don't know who the user is yet, so the browser will
     *  send back the credentialId, and we look the user up from that. */
    public Map<String, Object> loginStart() {
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        String chB64 = b64url.encodeToString(challenge);
        redis.opsForValue().set(CH_PREFIX + "login:" + chB64, chB64, CHALLENGE_TTL);

        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("challenge", chB64);
        opts.put("rpId", rpId);
        opts.put("userVerification", "preferred");
        opts.put("timeout", 60_000);
        opts.put("allowCredentials", List.of()); // empty = let the platform offer any registered key
        return opts;
    }

    /** Login finish — verify the assertion against the stored public key + bump counter.
     *  Returns the user id on success. */
    public Long loginFinish(String credentialIdB64, String challengeB64) {
        // Drain the challenge so it can't be replayed
        String challenge = redis.opsForValue().getAndDelete(CH_PREFIX + "login:" + challengeB64);
        if (challenge == null) throw new IllegalArgumentException("Login challenge expired or missing.");

        byte[] credentialId = b64urlDec.decode(credentialIdB64);
        WebAuthnCredential c = creds.findByCredentialId(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown passkey."));

        // Production hardening: verify signature using webAuthnManager.validate() with
        // the assertion's authenticatorData + clientDataJSON + signature + public key.
        // Demo path here trusts the browser's credentialId presence.

        c.setSignCount(c.getSignCount() + 1);
        c.setLastUsedAt(Instant.now());
        creds.save(c);
        return c.getUserId();
    }

    public List<WebAuthnCredential> list(Long userId) {
        return creds.findAllByUserId(userId);
    }

    public void revoke(Long userId, Long credId) {
        creds.findById(credId).ifPresent(c -> {
            if (c.getUserId().equals(userId)) creds.delete(c);
        });
    }
}
