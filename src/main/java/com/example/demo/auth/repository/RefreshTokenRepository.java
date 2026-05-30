package com.example.demo.auth.repository;

import com.example.demo.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findTopByTokenHashAndRevokedAtIsNull(String tokenHash);
    // Includes revoked rows — used to detect replay of an already-rotated token.
    Optional<RefreshToken> findTopByTokenHash(String tokenHash);
    // All currently-active refresh tokens for a user — used to revoke the whole
    // chain when a reuse is detected.
    List<RefreshToken> findAllByUserIdAndRevokedAtIsNull(Long userId);
    long deleteByExpiresAtBefore(LocalDateTime t);
    long deleteAllByUserId(Long userId);
}