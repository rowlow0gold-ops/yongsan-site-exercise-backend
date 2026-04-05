package com.example.demo.satisfaction;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "page_satisfaction")
@Getter
@Setter
@NoArgsConstructor
public class PageSatisfaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "page_path", nullable = false, length = 500)
    private String pagePath;

    @Column(nullable = false, length = 20)
    private String rating;

    @Column(length = 200)
    private String feedback;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}
