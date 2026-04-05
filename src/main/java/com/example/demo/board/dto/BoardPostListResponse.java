package com.example.demo.board.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class BoardPostListResponse implements Serializable {
    private List<Item> items;
    private long total;

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Item implements Serializable {
        private Long id;
        private String title;
        private String author;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
        private Long views;
        private String visibility;   // "PUBLIC" or "PRIVATE"
        private Long authorUserId;   // null for guest posts
        private boolean guestPost;   // true if no authorUserId (guest-written)
    }
}
