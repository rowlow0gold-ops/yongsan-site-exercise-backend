package com.example.demo.webauthn;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredential, Long> {
    List<WebAuthnCredential> findAllByUserId(Long userId);
    Optional<WebAuthnCredential> findByCredentialId(byte[] credentialId);
    long countByUserId(Long userId);
    void deleteAllByUserId(Long userId);
}
