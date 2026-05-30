package com.example.demo.satisfaction;

import org.springframework.data.jpa.repository.JpaRepository;

public interface PageSatisfactionRepository extends JpaRepository<PageSatisfaction, Long> {
    long deleteAllByUserId(Long userId);
}
