package com.example.demo.board.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@AllArgsConstructor
public class BoardPostListResponse {
    private List<Item> items;
    private long total;

    @Getter
    @AllArgsConstructor
    public static class Item {
        private Long id;
        private String title;
        private String author;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
        private Long views;
    }
}
