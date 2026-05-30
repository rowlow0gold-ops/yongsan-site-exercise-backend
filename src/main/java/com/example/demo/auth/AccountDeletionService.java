package com.example.demo.auth;

import com.example.demo.auth.repository.AppUserRepository;
import com.example.demo.auth.repository.RefreshTokenRepository;
import com.example.demo.audit.AuditLog;
import com.example.demo.board.repository.BoardPostRepository;
import com.example.demo.satisfaction.PageSatisfactionRepository;
import com.example.demo.webauthn.WebAuthnCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Handles 탈퇴 (account deletion).
 *
 * Korean privacy norms (and GDPR right-to-erasure) call for a hard delete
 * of personally-identifying records, but we want to keep the community-
 * value of the user's public board posts. The compromise: posts stay,
 * attribution is stripped (author_user_id = null, author label = "탈퇴한 회원").
 * Everything else tied to the user (passkeys, refresh tokens, satisfaction
 * survey rows, the user row itself) is removed.
 *
 * All steps run in a single transaction — partial deletion would leave
 * orphan rows pointing at a missing user_id and break joins.
 */
@Service
@RequiredArgsConstructor
public class AccountDeletionService {

    private final AppUserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final WebAuthnCredentialRepository passkeys;
    private final BoardPostRepository posts;
    private final PageSatisfactionRepository satisfactions;
    private final AuditLog audit;

    @Transactional
    public void deleteAccount(Long userId, String email, String ip) {
        // 1. Anonymize public posts — keep content, drop personal link.
        int anonymized = posts.anonymizePostsByUser(userId);

        // 2. Wipe everything that's strictly personal.
        long refresh = refreshTokens.deleteAllByUserId(userId);
        passkeys.deleteAllByUserId(userId);
        long surveys = satisfactions.deleteAllByUserId(userId);

        // 3. Finally, the user row.
        users.deleteById(userId);

        // 4. Audit trail. Email is kept here because audit log is the
        //    legal record of "the user 탈퇴'd at this time" — independent
        //    of whether the user row still exists.
        audit.record(userId, "ACCOUNT_DELETED", ip, true,
                "anonymized_posts=" + anonymized
                        + " refresh_tokens=" + refresh
                        + " surveys=" + surveys
                        + " email=" + email);
    }
}
