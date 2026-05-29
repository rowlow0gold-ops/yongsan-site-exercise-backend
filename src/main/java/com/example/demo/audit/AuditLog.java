package com.example.demo.audit;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuditLog {

    private final AuditEventRepository repo;

    /** Always commits in its own transaction so failure-path audit rows don't
     *  get rolled back when the caller throws. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(String email, String action, String ip, boolean success, String details) {
        repo.save(AuditEvent.builder()
                .email(email)
                .action(action)
                .ip(ip)
                .success(success)
                .details(details != null && details.length() > 500 ? details.substring(0, 500) : details)
                .build());
    }
}
