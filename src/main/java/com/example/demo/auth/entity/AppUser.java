package com.example.demo.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "app_users")
@Getter
@Setter
@NoArgsConstructor
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(nullable = false, length = 30)
    private String role; // USER / ADMIN

    @Column(length = 100)
    private String name;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    /**
     * False until the user clicks the verification link emailed at signup.
     * OAuth sign-ups (Google/Kakao) are auto-verified — the provider has
     * already proven ownership of the email. Password sign-ups start at
     * false and the API enforces that nothing but a tiny allow-list of
     * endpoints works until this flips to true.
     */
    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified = false;

    // ✅ ADD THIS
    @PrePersist
    public void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = this.createdAt;
    }

    // ✅ ADD THIS
    @PreUpdate
    public void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}