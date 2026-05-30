package com.example.demo.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Stable (provider, provider_user_id) -> AppUser mapping. Replaces the
 * email-based OAuth lookup that broke when two provider accounts ended up
 * sharing an email (the Kakao 4827954651 incident).
 */
@Entity
@Table(name = "oauth_identities", uniqueConstraints = {
        @UniqueConstraint(name = "uq_oauth_identities_provider_uid",
                          columnNames = {"provider", "provider_user_id"})
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OAuthIdentity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false, length = 20)
    private String provider;          // "google" | "kakao"

    @Column(name = "provider_user_id", nullable = false, length = 64)
    private String providerUserId;    // Google sub, Kakao id

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    public void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }

    public OAuthIdentity(Long userId, String provider, String providerUserId) {
        this.userId = userId;
        this.provider = provider;
        this.providerUserId = providerUserId;
    }
}
