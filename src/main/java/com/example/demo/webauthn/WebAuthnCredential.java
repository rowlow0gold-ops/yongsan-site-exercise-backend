package com.example.demo.webauthn;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "webauthn_credentials", indexes = {
    @Index(name = "ix_webauthn_user_id", columnList = "user_id"),
    @Index(name = "ix_webauthn_cred_id", columnList = "credential_id", unique = true)
})
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class WebAuthnCredential {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** WebAuthn credentialId (raw bytes, base64url-encoded when sent to/from browser) */
    @Column(name = "credential_id", nullable = false, length = 512)
    private byte[] credentialId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    /** COSE-encoded public key bytes */
    @Column(name = "public_key_cose", nullable = false, length = 1024)
    private byte[] publicKeyCose;

    /** Monotonic sign counter — bumped on every successful authentication */
    @Column(name = "sign_count", nullable = false)
    @Builder.Default
    private long signCount = 0;

    /** Authenticator AAGUID (16 bytes, hex string for readability) */
    @Column(name = "aaguid", length = 64)
    private String aaguid;

    /** User-friendly nickname ("MacBook Touch ID", "YubiKey 5C", etc.) */
    @Column(length = 100)
    private String name;

    @Column(name = "created_at", nullable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "last_used_at")
    private Instant lastUsedAt;
}
