package com.example.demo.webauthn;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.repository.AppUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
@Slf4j
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
    private final ObjectConverter objectConverter = new ObjectConverter();
    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
    private final AttestedCredentialDataConverter attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);
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

        List<Map<String, Object>> excludeList = new ArrayList<>();
        for (WebAuthnCredential c : creds.findAllByUserId(userId)) {
            excludeList.add(Map.of(
                "type", "public-key",
                "id", b64url.encodeToString(c.getCredentialId())
            ));
        }

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

    /**
     * Step 2 of enrollment — full webauthn4j parse + validate, no more stub.
     *
     * Browser sends back the raw attestationObject + clientDataJSON. We:
     *   1) parse them into a RegistrationData
     *   2) validate signatures, challenge, origin, rpId via the lib
     *   3) extract the COSE public key from the attestation and store it
     *      separately so login-finish can rebuild the CredentialRecord
     */
    public void registrationFinish(Long userId,
                                   String credentialIdB64,
                                   String attestationObjectB64,
                                   String clientDataJsonB64,
                                   String name) {
        String challengeB64 = redis.opsForValue().getAndDelete(CH_PREFIX + "reg:" + userId);
        if (challengeB64 == null) throw new IllegalArgumentException("Registration challenge expired or missing.");

        byte[] attestationObjectBytes = b64urlDec.decode(attestationObjectB64);
        byte[] clientDataJson = b64urlDec.decode(clientDataJsonB64);

        // 1) parse — throws if malformed
        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObjectBytes, clientDataJson);
        RegistrationParameters registrationParameters = new RegistrationParameters(
                buildServerProperty(challengeB64),
                List.of(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
                ),
                false, // userVerificationRequired — we asked for "preferred"
                true   // userPresenceRequired
        );

        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.parse(registrationRequest);
        } catch (Exception e) {
            log.warn("WebAuthn registration parse failed: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid registration payload.");
        }

        // 2) validate — full crypto: attestation chain (if any), client data hash,
        //    challenge match, origin match, rpIdHash match
        try {
            webAuthnManager.validate(registrationData, registrationParameters);
        } catch (Exception e) {
            log.warn("WebAuthn registration validation failed: {}", e.getMessage());
            throw new IllegalArgumentException("Registration verification failed.");
        }

        AttestationObject ao = registrationData.getAttestationObject();
        if (ao == null || ao.getAuthenticatorData().getAttestedCredentialData() == null) {
            throw new IllegalArgumentException("Attestation missing credential data.");
        }
        AttestedCredentialData attestedCredentialData = ao.getAuthenticatorData().getAttestedCredentialData();

        // 3) persist — store the credentialId reported by the authenticator (NOT
        //    the one the SPA happened to send; the authenticator's is authoritative)
        //    and the serialized AttestedCredentialData so login-finish can rebuild
        //    the CredentialRecord verbatim.
        byte[] credentialId = attestedCredentialData.getCredentialId();
        byte[] attestedCredentialDataBytes = attestedCredentialDataConverter.convert(attestedCredentialData);

        WebAuthnCredential c = WebAuthnCredential.builder()
                .credentialId(credentialId)
                .publicKeyCose(attestedCredentialDataBytes) // serialized AttestedCredentialData (CBOR)
                .userId(userId)
                .signCount(ao.getAuthenticatorData().getSignCount())
                .name(name != null && !name.isBlank() ? name : "Passkey")
                .build();
        creds.save(c);
    }

    /** Login start — challenge stored against itself, validated on finish. */
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
        opts.put("allowCredentials", List.of());
        return opts;
    }

    /**
     * Login finish — full webauthn4j validate. The SPA now sends the complete
     * assertion (authenticatorData + clientDataJSON + signature). We rebuild
     * the CredentialRecord from what we stored at registration, then let the
     * library verify the signature against the public key, the challenge, the
     * rpId hash, the origin, and the monotonic sign-count.
     */
    public Long loginFinish(String credentialIdB64,
                            String authenticatorDataB64,
                            String clientDataJsonB64,
                            String signatureB64,
                            String challengeB64) {
        String challenge = redis.opsForValue().getAndDelete(CH_PREFIX + "login:" + challengeB64);
        if (challenge == null) throw new IllegalArgumentException("Login challenge expired or missing.");

        byte[] credentialId = b64urlDec.decode(credentialIdB64);
        byte[] authenticatorData = b64urlDec.decode(authenticatorDataB64);
        byte[] clientDataJson = b64urlDec.decode(clientDataJsonB64);
        byte[] signature = b64urlDec.decode(signatureB64);

        WebAuthnCredential stored = creds.findByCredentialId(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown passkey."));

        // Rebuild the AttestedCredentialData from what we stored at registration,
        // wrap it in a CredentialRecord with the current sign-count.
        AttestedCredentialData attestedCredentialData = attestedCredentialDataConverter.convert(stored.getPublicKeyCose());
        // Explicit casts so Java's overload resolution picks the right
        // constructor — webauthn4j has multiple CredentialRecordImpl
        // constructors and bare nulls are ambiguous to the compiler.
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                (AttestationStatement) null,
                (Boolean) null,                  // uvInitialized
                (Boolean) null,                  // backupEligible
                (Boolean) null,                  // backupState
                stored.getSignCount(),
                attestedCredentialData,
                (AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput>) null,
                (AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput>) null,
                (Set<AuthenticatorTransport>) null
        );

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                credentialId, authenticatorData, clientDataJson, signature);
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                buildServerProperty(challengeB64),
                credentialRecord,
                /* allowCredentials       */ null,
                /* userVerificationRequired */ false,
                /* userPresenceRequired   */ true
        );

        AuthenticationData authenticationData;
        try {
            authenticationData = webAuthnManager.parse(authenticationRequest);
        } catch (Exception e) {
            log.warn("WebAuthn auth parse failed: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid assertion payload.");
        }
        try {
            webAuthnManager.validate(authenticationData, authenticationParameters);
        } catch (Exception e) {
            log.warn("WebAuthn auth validation failed: {}", e.getMessage());
            throw new IllegalArgumentException("Passkey verification failed.");
        }

        // Monotonically increase the sign-count. webauthn4j already rejects
        // a decrease (clone-detection), so by the time we get here it's safe
        // to take whatever the authenticator reported.
        long newCount = authenticationData.getAuthenticatorData().getSignCount();
        stored.setSignCount(Math.max(stored.getSignCount(), newCount));
        stored.setLastUsedAt(Instant.now());
        creds.save(stored);
        return stored.getUserId();
    }

    public List<WebAuthnCredential> list(Long userId) {
        return creds.findAllByUserId(userId);
    }

    public void revoke(Long userId, Long credId) {
        creds.findById(credId).ifPresent(c -> {
            if (c.getUserId().equals(userId)) creds.delete(c);
        });
    }

    private ServerProperty buildServerProperty(String challengeB64) {
        Challenge challenge = new DefaultChallenge(b64urlDec.decode(challengeB64));
        return new ServerProperty(new Origin(origin), rpId, challenge, null);
    }
}

