package com.example.demo.auth.repository;

import com.example.demo.auth.entity.OAuthIdentity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OAuthIdentityRepository extends JpaRepository<OAuthIdentity, Long> {
    Optional<OAuthIdentity> findByProviderAndProviderUserId(String provider, String providerUserId);
    List<OAuthIdentity> findAllByUserIdAndProvider(Long userId, String provider);
}
