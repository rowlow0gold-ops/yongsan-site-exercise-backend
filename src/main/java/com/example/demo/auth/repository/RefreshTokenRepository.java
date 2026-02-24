package com.example.demo.auth.repository;

import com.example.demo.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findTopByTokenHashAndRevokedAtIsNull(String tokenHash);
    long deleteByExpiresAtBefore(LocalDateTime t);
}